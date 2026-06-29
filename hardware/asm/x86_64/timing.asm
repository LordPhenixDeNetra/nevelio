; ============================================================================
; Nevelio Hardware Security — x86_64 Timing primitives
; Syntaxe : NASM (nasm -f elf64 timing.asm -o timing.o)
;
; Ces fonctions sont documentées ici comme référence.
; L'implémentation en production utilise les intrinsics Rust dans
; hw-sidechannel/src/cache.rs via core::arch::x86_64.
; ============================================================================

section .text
global flush_reload_measure    ; u64 flush_reload_measure(const uint8_t *addr)
global rdtsc_serialized        ; u64 rdtsc_serialized(void)
global clflush_addr            ; void clflush_addr(const uint8_t *addr)

; ----------------------------------------------------------------------------
; flush_reload_measure(addr: *const u8) -> u64
;
; Vide la ligne de cache contenant addr, force une barrière mémoire,
; lit le timestamp, accède à la mémoire, lit à nouveau le timestamp.
; Retourne le delta en cycles CPU.
;
; Paramètre : RDI = adresse (ABI System V AMD64)
; Retour    : RAX = cycles d'accès
; ----------------------------------------------------------------------------
flush_reload_measure:
    ; Phase 1 : vider le cache
    clflush byte [rdi]          ; invalide la ligne de cache (64 octets)
    mfence                      ; barrière mémoire complète (store + load)

    ; Phase 2 : lire le timestamp avant accès
    rdtsc                       ; EDX:EAX = TSC (Time Stamp Counter)
    shl rdx, 32
    or  rax, rdx                ; RAX = timestamp 64-bit
    mov r8, rax                 ; sauvegarder start

    ; Phase 3 : accès mémoire à mesurer
    mov rax, [rdi]              ; charge la donnée depuis DRAM (cache miss)
    lfence                      ; sérialise : attend la fin du load

    ; Phase 4 : lire le timestamp après accès
    rdtsc
    shl rdx, 32
    or  rax, rdx                ; RAX = timestamp fin

    ; Phase 5 : calculer le delta
    sub rax, r8                 ; RAX = end - start = cycles d'accès
    ret

; ----------------------------------------------------------------------------
; rdtsc_serialized() -> u64
;
; Lecture sérialisée du TSC via RDTSCP ou CPUID+RDTSC.
; RDTSCP (if available) est plus précis : attend la fin des instructions
; précédentes avant de lire le compteur.
;
; Retour : RAX = TSC 64-bit
; ----------------------------------------------------------------------------
rdtsc_serialized:
    rdtscp                      ; EDX:EAX = TSC, ECX = IA32_TSC_AUX
    shl rdx, 32
    or  rax, rdx
    ret

; ----------------------------------------------------------------------------
; clflush_addr(addr: *const u8)
;
; Vide la ligne de cache de 64 octets contenant addr.
; Paramètre : RDI = adresse
; ----------------------------------------------------------------------------
clflush_addr:
    clflush byte [rdi]
    mfence
    ret

; ============================================================================
; Notes de sécurité :
;
; CLFLUSH est une instruction non-privilégiée disponible depuis Intel P4.
; Elle peut être utilisée par les processus user-space pour vider le cache
; de lignes correspondant à leurs propres pages — ou à des pages partagées
; (shared libraries, vDSO, etc.) — rendant possibles les attaques :
;   - Flush+Reload  : vider + attendre + mesurer (processus victimes)
;   - Prime+Probe   : remplir des ensembles de cache + mesurer éviction
;   - Rowhammer     : cibler des lignes DRAM adjacentes (aggro = CLFLUSH + charge)
;
; Mitigations disponibles :
;   - Désactiver CLFLUSH user : nécessite patch noyau ou hyperviseur
;   - KPTI (Kernel Page-Table Isolation) : réduit la surface mémoire partagée
;   - nosmt : désactive hyperthreading, supprime le vecteur de fuite intra-core
;   - Constant-time algorithms : libsodium, BoringSSL, HACL*
; ============================================================================
