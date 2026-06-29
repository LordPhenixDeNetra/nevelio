// ============================================================================
// Nevelio Hardware Security — ARM64 Timing primitives
// Syntaxe : GAS (as -o timing.o timing.asm)
// Cible   : AArch64 (ARMv8-A et ultérieur)
//
// Ces fonctions sont documentées ici comme référence.
// L'implémentation en production utilise l'inline assembly Rust via
// std::arch::asm! dans hw-sidechannel/src/cache.rs.
// ============================================================================

.section .text
.global flush_reload_measure    // u64 flush_reload_measure(const uint8_t *addr)
.global read_virtual_timer      // u64 read_virtual_timer(void)
.global cache_flush_addr        // void cache_flush_addr(const uint8_t *addr)

// ----------------------------------------------------------------------------
// flush_reload_measure(addr: *const u8) -> u64
//
// ARM64 utilise le compteur virtuel CNTVCT_EL0 (timer système, ~100MHz à ~1GHz)
// plutôt que RDTSC. La granularité est inférieure à x86_64 RDTSC mais
// suffisante pour distinguer cache hit (~5ns) de cache miss (~50ns).
//
// Paramètre : X0 = adresse
// Retour    : X0 = delta timer
// ----------------------------------------------------------------------------
flush_reload_measure:
    // Phase 1 : vider la ligne de cache (DC CIVAC = Clean+Invalidate by VA)
    dc civac, x0               // Clean + Invalidate cache line
    dsb sy                     // Data Synchronization Barrier (attendre complétion)
    isb                        // Instruction Synchronization Barrier

    // Phase 2 : lire le timer virtuel avant accès
    mrs x1, cntvct_el0         // X1 = Virtual Timer Count (monotone croissant)
    isb                        // Sérialisation

    // Phase 3 : accès mémoire
    ldr x2, [x0]               // Charge depuis DRAM après invalidation
    dsb ld                     // Barrière : attend la fin du load

    // Phase 4 : lire le timer après accès
    isb
    mrs x3, cntvct_el0         // X3 = timestamp fin

    // Phase 5 : delta
    sub x0, x3, x1             // X0 = fin - début
    ret

// ----------------------------------------------------------------------------
// read_virtual_timer() -> u64
//
// Lecture directe du compteur timer virtuel.
// Fréquence lisible via CNTFRQ_EL0 (ex : 24MHz sur Apple M1/M2).
// Retour : X0 = CNTVCT_EL0
// ----------------------------------------------------------------------------
read_virtual_timer:
    isb
    mrs x0, cntvct_el0
    ret

// ----------------------------------------------------------------------------
// cache_flush_addr(addr: *const u8)
//
// Vide et invalide la ligne de cache 64 octets contenant addr.
// Paramètre : X0 = adresse
// ----------------------------------------------------------------------------
cache_flush_addr:
    dc civac, x0               // Clean + Invalidate cache line
    dsb sy                     // Attendre la propagation
    isb
    ret

// ============================================================================
// Notes sur ARM64 vs x86_64 :
//
// 1. CNTVCT_EL0 vs RDTSC :
//    - RDTSC : fréquence fixe (TSC invariant), 1 tick ≈ 0.3ns à 3GHz
//    - CNTVCT : fréquence variable (24MHz sur Apple M1 → 1 tick ≈ 42ns)
//      Pour cache timing, cette granularité peut être insuffisante.
//      Solution : répéter l'accès N fois et diviser par N.
//
// 2. DC CIVAC vs CLFLUSH :
//    - Sur ARM, DC CIVAC nécessite le privilege EL1 sur certaines
//      configurations système (accès contrôlé par CTR_EL0.DIC).
//    - Sur Apple Silicon, l'accès user-space à DC CIVAC est restreint.
//    - Les attaques Flush+Reload sont donc moins triviales sur ARM.
//
// 3. Mitigations ARM-spécifiques :
//    - Stage-2 translation (hyperviseur) pour isoler les caches
//    - Cache Coloring dans le noyau (allocation cache sets dédiés)
//    - FEAT_CSV2 (ARMv8.5) : limitation de la spéculation cross-domain
// ============================================================================
