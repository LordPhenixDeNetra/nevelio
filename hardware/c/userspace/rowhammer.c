/*
 * Nevelio Hardware Security — Rowhammer Test (Userspace)
 *
 * Test de vulnérabilité Rowhammer sur la DRAM physique.
 * Double-sided hammering : deux rows agresseurs encadrent la row cible.
 *
 * Compilation :
 *   gcc -O2 -march=native -o rowhammer_test rowhammer.c
 * Utilisation autonome :
 *   sudo ./rowhammer_test --size 256 --iters 2000000 --time 30
 * Via nevelio-hw :
 *   nevelio-hw scan --active  (intégré dans hw-memory via cc crate)
 *
 * AVERTISSEMENT :
 *   - Ne jamais exécuter sur une machine de production.
 *   - Faire un snapshot VM avant le test.
 *   - Arrêter immédiatement si des bit flips sont détectés sur des données critiques.
 *   - Root requis pour mlock() sur grandes zones mémoire.
 *
 * Références :
 *   [1] Kim et al., ISCA 2014 — Découverte originale Rowhammer
 *   [2] Google Project Zero, "Exploiting the DRAM Rowhammer Bug" (2015)
 *   [3] Frigo et al., "TRRespass" (IEEE S&P 2020)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#endif

/* ── Constantes configurables ────────────────────────────────────────────── */

#define DEFAULT_MEM_SIZE_MB   256UL
#define DEFAULT_HAMMER_ITERS  2000000UL
#define DEFAULT_TEST_SECS     30
#define DEFAULT_PATTERN       0x00

/* Stride entre deux rows dans la même bank (typiquement 8KB sur DDR4) */
#define DRAM_ROW_SIZE         (8 * 1024UL)
/* Stride de bank : une bank toutes les 64KB sur la plupart des DDR4 */
#define DRAM_BANK_STRIDE      (64 * 1024UL)

/* ── Structure de résultat (exportée vers Rust via FFI) ──────────────────── */

typedef struct {
    uint64_t bit_flips;         /* Nombre total de bit flips détectés */
    uint64_t bytes_flipped;     /* Nombre d'octets ayant subi au moins un flip */
    uint64_t iterations;        /* Itérations de hammering effectuées */
    uint64_t duration_ms;       /* Durée totale en ms */
    uint64_t rows_tested;       /* Nombre de paires de rows testées */
    uint32_t memory_mb;         /* Taille de la zone testée en MB */
    int      ecc_detected;      /* 1 si des corrections ECC semblent actives */
    int      vulnerable;        /* 1 si des bit flips ont été détectés */
} NevelioRowhammerResult;

/* ── Primitives bas-niveau ───────────────────────────────────────────────── */

/*
 * Flush une ligne de cache et attend que l'opération soit terminée.
 * Utilise CLFLUSH (invalide la cache line) + MFENCE (barrière mémoire).
 */
static inline void flush_line(volatile void *addr)
{
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile(
        "clflush (%0)\n\t"
        "mfence\n\t"
        :
        : "r" (addr)
        : "memory"
    );
#elif defined(__aarch64__)
    /* ARM64 : DC CIVAC (Data Cache Clean and Invalidate to PoC) */
    __asm__ volatile(
        "dc civac, %0\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        :
        : "r" (addr)
        : "memory"
    );
#else
    /* Fallback : lecture volatile pour forcer l'accès */
    (void)(*(volatile uint8_t *)addr);
#endif
}

/*
 * Lit un octet en forçant l'accès DRAM (bypass cache).
 * CLFLUSH avant lecture garantit que l'accès va en DRAM.
 */
static inline uint8_t read_no_cache(volatile uint8_t *addr)
{
    flush_line(addr);
    return *addr;
}

/* ── Hammering ────────────────────────────────────────────────────────────── */

/*
 * hammer_pair : hammer deux adresses à haute fréquence.
 * Row A et Row B doivent être dans la même bank DRAM pour que l'effet
 * de perturbation affecte la row intercalée (row C = cible).
 */
static void hammer_pair(volatile uint8_t *row_a, volatile uint8_t *row_b,
                         uint64_t iterations)
{
    volatile uint8_t x, y;
    (void)x; (void)y;

    for (uint64_t i = 0; i < iterations; i++) {
        x = *row_a;
        flush_line(row_a);

        y = *row_b;
        flush_line(row_b);
    }

    /*
     * Note de timing :
     *   Sur DDR4 3200 MHz, une activation DRAM prend ~40ns.
     *   Un CLFLUSH prend ~10ns en cache miss.
     *   Temps total par itération : ~100ns → 10M iter/seconde max.
     *   Pour 2M itérations : ~200ms → bien dans la fenêtre de refresh (64ms = ~3 fenêtres).
     */
}

/* ── Comptage des bit flips ──────────────────────────────────────────────── */

static uint64_t count_bit_flips(const uint8_t *region, size_t size,
                                  uint8_t expected_pattern,
                                  uint64_t *bytes_flipped)
{
    uint64_t total_flips = 0;
    *bytes_flipped = 0;

    for (size_t i = 0; i < size; i++) {
        uint8_t actual   = region[i];
        uint8_t expected = expected_pattern;
        uint8_t diff     = actual ^ expected;

        if (diff) {
            (*bytes_flipped)++;
            /* Compter les bits qui ont changé (popcount) */
#if defined(__GNUC__) && defined(__x86_64__)
            total_flips += (uint64_t)__builtin_popcount(diff);
#else
            for (int b = 0; b < 8; b++) {
                if (diff & (1 << b)) total_flips++;
            }
#endif
        }
    }

    return total_flips;
}

/* ── Trouver des rows dans la même bank DRAM ─────────────────────────────── */

/*
 * find_same_bank_rows :
 *   Trouve des paires de rows agresseurs qui partagent la même bank DRAM
 *   avec une row cible intercalée.
 *
 *   Sans accès aux adresses physiques (nécessite root + /proc/self/pagemap),
 *   on utilise le stride de bank. Approximation valide sur la majorité des
 *   configurations DDR4 single-channel/dual-channel.
 *
 *   row_a = base + 0
 *   row_c = base + DRAM_ROW_SIZE           (cible)
 *   row_b = base + 2 * DRAM_ROW_SIZE       (agressor 2)
 */
static void test_region(uint8_t *base, size_t region_size,
                         uint64_t hammer_iters,
                         uint8_t pattern,
                         NevelioRowhammerResult *result)
{
    /* Initialiser la région avec le pattern connu */
    memset(base, pattern, region_size);

    /* Synchroniser vers la DRAM (éviter les pages encore en cache) */
#ifdef __linux__
    msync(base, region_size, MS_SYNC);
#endif

    /* Tester par blocs de 3 rows */
    size_t rows_per_test = 3;
    size_t row_stride    = DRAM_ROW_SIZE;

    for (size_t offset = 0;
         offset + rows_per_test * row_stride <= region_size;
         offset += DRAM_BANK_STRIDE)
    {
        volatile uint8_t *row_a = (volatile uint8_t *)(base + offset);
        volatile uint8_t *row_b = (volatile uint8_t *)(base + offset + 2 * row_stride);
        /* row_c (cible) = base + offset + row_stride — pas hammée, juste surveillée */
        uint8_t          *row_c = base + offset + row_stride;

        /* Sauvegarder l'état de la row cible avant hammering */
        uint8_t target_backup[8];
        size_t  check_size = (row_stride < 8) ? row_stride : 8;
        memcpy(target_backup, row_c, check_size);

        /* Hammer ! */
        hammer_pair(row_a, row_b, hammer_iters);

        /* Vérifier les bit flips sur la row cible */
        uint64_t bytes_flipped = 0;
        uint64_t flips = count_bit_flips(row_c, row_stride, pattern, &bytes_flipped);

        if (flips > 0) {
            result->bit_flips     += flips;
            result->bytes_flipped += bytes_flipped;
            result->vulnerable     = 1;

            /*
             * Si les flips sont corrigés automatiquement (ECC),
             * la mémoire lue redevient correcte après un court délai.
             * Heuristique : si les flips disparaissent à la deuxième lecture,
             * ECC est probablement actif.
             */
            uint64_t recheck_flips = count_bit_flips(row_c, row_stride,
                                                      pattern, &bytes_flipped);
            if (recheck_flips < flips) {
                result->ecc_detected = 1;
            }

            /* Restaurer le pattern pour les tests suivants */
            memset((void *)row_a, pattern, row_stride);
            memset((void *)row_b, pattern, row_stride);
            memset(row_c,         pattern, row_stride);
        }

        result->rows_tested++;
    }
}

/* ── Point d'entrée FFI (appelé depuis Rust via hw-memory) ──────────────── */

/*
 * nevelio_rowhammer_test :
 *   Fonction principale exportée — interface entre Rust et C.
 *
 * Paramètres :
 *   mem_size_mb   : taille de la zone de test en MB (256MB recommandé)
 *   hammer_count  : itérations de hammering par paire de rows
 *   max_seconds   : durée maximale du test en secondes (0 = illimité)
 *   result        : pointeur vers la structure de résultat
 *
 * Retour :
 *    0 : succès
 *   -1 : erreur d'allocation mémoire
 *   -2 : mlock() échoué (root requis)
 *   -3 : plateforme non supportée
 */
int nevelio_rowhammer_test(
    uint32_t             mem_size_mb,
    uint64_t             hammer_count,
    uint32_t             max_seconds,
    NevelioRowhammerResult *result)
{
    if (!result) return -1;

    memset(result, 0, sizeof(*result));
    result->memory_mb = mem_size_mb ? mem_size_mb : (uint32_t)DEFAULT_MEM_SIZE_MB;
    result->iterations = hammer_count ? hammer_count : DEFAULT_HAMMER_ITERS;

#ifndef __linux__
    /* Rowhammer n'est opérationnel qu'avec accès direct à la DRAM */
    result->bit_flips = 0;
    result->vulnerable = 0;
    return -3;
#else
    size_t mem_size = (size_t)result->memory_mb * 1024 * 1024;
    uint8_t *mem;
    struct timespec start, now;

    /* Allocation mémoire anonyme (non swappable si mlock réussit) */
    mem = (uint8_t *)mmap(NULL, mem_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                           -1, 0);
    if (mem == MAP_FAILED) {
        return -1;
    }

    /* mlock : empêcher le swap — essentiel pour tester la vraie DRAM */
    if (mlock(mem, mem_size) != 0) {
        /*
         * mlock échoue sans root ou si RLIMIT_MEMLOCK est trop bas.
         * Le test continue mais peut être moins précis (pages swappées).
         */
        result->ecc_detected = -1; /* Signal que mlock a échoué */
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    /*
     * Tester avec 3 patterns différents pour une couverture maximale :
     *   0x00 : bits à 0, chercher les flips à 1
     *   0xFF : bits à 1, chercher les flips à 0
     *   0x55 : pattern alterné (détecte les couplages capacitifs)
     */
    uint8_t patterns[] = { 0x00, 0xFF, 0x55 };
    size_t  region_per_pattern = mem_size / 3;

    for (int p = 0; p < 3; p++) {
        /* Vérifier le timeout */
        if (max_seconds > 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed = (long)(now.tv_sec - start.tv_sec);
            if (elapsed >= (long)max_seconds) break;
        }

        test_region(mem + p * region_per_pattern,
                    region_per_pattern,
                    result->iterations,
                    patterns[p],
                    result);
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    result->duration_ms = (uint64_t)(
        (now.tv_sec  - start.tv_sec)  * 1000 +
        (now.tv_nsec - start.tv_nsec) / 1000000
    );

    munlock(mem, mem_size);
    munmap(mem, mem_size);

    return 0;
#endif /* __linux__ */
}

/* ── Programme autonome (test sans nevelio-hw) ───────────────────────────── */

#ifdef ROWHAMMER_STANDALONE
int main(int argc, char *argv[])
{
    uint32_t mem_mb      = DEFAULT_MEM_SIZE_MB;
    uint64_t iters       = DEFAULT_HAMMER_ITERS;
    uint32_t max_secs    = DEFAULT_TEST_SECS;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--size")  == 0 && i+1 < argc) mem_mb   = (uint32_t)atoi(argv[++i]);
        if (strcmp(argv[i], "--iters") == 0 && i+1 < argc) iters    = (uint64_t)atoll(argv[++i]);
        if (strcmp(argv[i], "--time")  == 0 && i+1 < argc) max_secs = (uint32_t)atoi(argv[++i]);
    }

    fprintf(stderr,
            "[nevelio] Rowhammer test — %uMB, %llu iter/paire, max %us\n"
            "[nevelio] ATTENTION : ne jamais lancer sur une machine de prod !\n\n",
            mem_mb, (unsigned long long)iters, max_secs);

    NevelioRowhammerResult result = {0};
    int rc = nevelio_rowhammer_test(mem_mb, iters, max_secs, &result);

    if (rc == -3) {
        fprintf(stderr, "[!] Test disponible uniquement sur Linux x86_64.\n");
        return 1;
    }
    if (rc < 0) {
        fprintf(stderr, "[!] Erreur d'initialisation : %d (errno=%d)\n", rc, errno);
        return 1;
    }

    printf("\n=== Résultats Rowhammer ===\n");
    printf("  Durée          : %llu ms\n",  (unsigned long long)result.duration_ms);
    printf("  Rows testées   : %llu\n",     (unsigned long long)result.rows_tested);
    printf("  Itérations     : %llu\n",     (unsigned long long)result.iterations);
    printf("  Bit flips      : %llu\n",     (unsigned long long)result.bit_flips);
    printf("  Octets affectés: %llu\n",     (unsigned long long)result.bytes_flipped);
    printf("  ECC détecté    : %s\n",       result.ecc_detected ? "oui" : "non");
    printf("  VULNERABLE     : %s\n",       result.vulnerable ? "OUI !!!" : "non");

    if (result.vulnerable) {
        printf("\n[CRITICAL] La DRAM est vulnérable à Rowhammer !\n");
        printf("           CWE-1278 — CVSS 8.8 (AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)\n");
        printf("           Recommandations :\n");
        printf("           - Activer l'ECC si disponible sur la carte mère\n");
        printf("           - Vérifier les mises à jour firmware DRAM/BIOS\n");
        printf("           - Envisager un remplacement des modules DRAM\n");
    } else {
        printf("\n[OK] Aucun bit flip détecté avec les paramètres testés.\n");
        printf("     Note : un résultat négatif ne garantit pas l'absence de vulnérabilité.\n");
        printf("     Augmenter --iters et --time pour un test plus exhaustif.\n");
    }

    return result.vulnerable ? 1 : 0;
}
#endif /* ROWHAMMER_STANDALONE */
