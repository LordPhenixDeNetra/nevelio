# =============================================================================
# Nevelio Hardware Security — JTAG Audit Script
# Moteur : OpenOCD (≥ 0.11)
# Usage   : openocd -f interface/ftdi/ft2232h.cfg -f target/stm32f4x.cfg
#                   -f /path/to/jtag_audit.tcl
#           openocd -f jtag_audit.tcl --target stm32l4x --dry-run
#
# Sortie  : lignes préfixées NEVELIO_FINDING: parsées par hw-jtag/src/openocd.rs
#           Format : NEVELIO_FINDING:<ID>:<SEVERITY>:<TITRE>:<DETAIL>
# =============================================================================

set NEVELIO_VERSION "0.1.0"
set DRY_RUN         0

# ── Helpers de sortie ────────────────────────────────────────────────────────

proc nevelio_log {msg} {
    puts "NEVELIO_LOG: $msg"
}

proc nevelio_finding {id severity title detail} {
    puts "NEVELIO_FINDING:${id}:${severity}:${title}:${detail}"
}

proc nevelio_info {id title detail} {
    nevelio_finding $id "INFORMATIVE" $title $detail
}

proc nevelio_medium {id title detail} {
    nevelio_finding $id "MEDIUM" $title $detail
}

proc nevelio_high {id title detail} {
    nevelio_finding $id "HIGH" $title $detail
}

proc nevelio_critical {id title detail} {
    nevelio_finding $id "CRITICAL" $title $detail
}

# ── Détection sécurisée de mémoire ──────────────────────────────────────────

proc safe_mrb {addr} {
    if {[catch {set val [mrb $addr]} err]} {
        nevelio_log "Lecture mémoire 0x[format %x $addr] échouée : $err"
        return -1
    }
    return $val
}

proc safe_mrw {addr} {
    if {[catch {set val [mrw $addr]} err]} {
        nevelio_log "Lecture mot 0x[format %x $addr] échouée : $err"
        return -1
    }
    return $val
}

# ── Audit STM32F0/F1/F2/F3/F4 ───────────────────────────────────────────────

proc audit_stm32_rdp {} {
    global DRY_RUN

    nevelio_log "Audit Read Protection STM32F4 (Option Bytes @ 0x1FFFC000)"

    # Option Bytes Register : RDP Level dans l'octet [7:0]
    set rdp [safe_mrb 0x1FFFC000]

    if {$rdp == -1} {
        nevelio_medium "STM32_RDP_UNREADABLE" \
            "Impossible de lire les Option Bytes STM32" \
            "L'accès mémoire à 0x1FFFC000 a échoué. Le target est peut-être en RDP Level 2 \
             (accès debug totalement bloqué) ou déconnecté."
        return
    }

    nevelio_log "RDP byte = 0x[format %02x $rdp]"

    switch $rdp {
        0xAA {
            nevelio_critical "STM32_RDP_LEVEL0" \
                "STM32 RDP Level 0 — Aucune protection flash active — CWE-1240" \
                "La protection lecture (RDP) est désactivée (0xAA = Level 0). \
                 Un attaquant avec accès physique peut lire l'intégralité de la flash, \
                 extraire le firmware, les clés cryptographiques et les secrets embarqués. \
                 CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 6.8"

            if {!$DRY_RUN} {
                nevelio_log "Tentative de dump flash (--active mode)..."
                audit_stm32_flash_dump
            } else {
                nevelio_log "Mode dry-run : dump flash ignoré."
            }
        }
        0xBB -
        default {
            # Tout autre octet = Level 1
            nevelio_medium "STM32_RDP_LEVEL1" \
                "STM32 RDP Level 1 — Protection partielle" \
                "Level 1 (0x[format %02x $rdp]) : la lecture via JTAG est bloquée mais \
                 un downgrade vers Level 0 efface la flash (protection partielle). \
                 Envisager Level 2 pour une protection permanente."
        }
        0xCC {
            nevelio_info "STM32_RDP_LEVEL2" \
                "STM32 RDP Level 2 — Protection maximale active" \
                "Level 2 (0xCC) : JTAG désactivé de façon permanente, \
                 flash illisible. Configuration de sécurité optimale."
        }
    }

    # Vérifier PCROP (Proprietary Code Readout Protection) sur les zones Flash
    audit_stm32_pcrop
}

proc audit_stm32_pcrop {} {
    nevelio_log "Vérification PCROP (STM32F4)..."
    # PCROP dans le registre FLASH_OPTCR à 0x40023C14, bit SPRMOD (bit 31)
    set optcr [safe_mrw 0x40023C14]
    if {$optcr == -1} { return }

    set sprmod [expr {($optcr >> 31) & 1}]
    if {$sprmod == 0} {
        nevelio_medium "STM32_PCROP_DISABLED" \
            "PCROP non actif sur STM32F4" \
            "Le bit SPRMOD (FLASH_OPTCR[31]) est à 0. PCROP permet de protéger \
             des régions spécifiques de flash contre la lecture en Level 1."
    } else {
        nevelio_info "STM32_PCROP_ENABLED" \
            "PCROP actif (FLASH_OPTCR bit 31)" \
            "Des régions flash sont protégées par PCROP en complément du RDP Level 1."
    }
}

proc audit_stm32_flash_dump {} {
    nevelio_log "Début dump flash STM32F4 (512KB @ 0x08000000)..."
    if {[catch {
        dump_image /tmp/nevelio_stm32_dump.bin 0x08000000 0x80000
        nevelio_log "Dump réussi : /tmp/nevelio_stm32_dump.bin"
        nevelio_finding "STM32_FLASH_DUMP" "INFORMATIVE" \
            "Dump flash STM32 réussi" \
            "512KB dumpés depuis 0x08000000 → /tmp/nevelio_stm32_dump.bin. \
             Analyser avec : binwalk, strings, radare2."
    } err]} {
        nevelio_log "Dump flash échoué : $err"
    }
}

# ── Audit STM32L4 (série L) ──────────────────────────────────────────────────

proc audit_stm32l4_rdp {} {
    nevelio_log "Audit Read Protection STM32L4 (Option Bytes @ 0x1FFF7800)"

    # STM32L4 : Flash Option Register à 0x40022020
    set flash_optr [safe_mrw 0x40022020]
    if {$flash_optr == -1} {
        nevelio_medium "STM32L4_OPTR_UNREADABLE" \
            "Impossible de lire FLASH_OPTR STM32L4" \
            "Accès à FLASH_OPTR (0x40022020) refusé."
        return
    }

    set rdp [expr {$flash_optr & 0xFF}]
    nevelio_log "FLASH_OPTR[7:0] (RDP) = 0x[format %02x $rdp]"

    if {$rdp == 0xAA} {
        nevelio_critical "STM32L4_RDP_LEVEL0" \
            "STM32L4 RDP Level 0 — Aucune protection" \
            "0xAA = RDP Level 0. Flash entièrement lisible via JTAG/SWD."
    } elseif {$rdp == 0xCC} {
        nevelio_info "STM32L4_RDP_LEVEL2" \
            "STM32L4 RDP Level 2 — Protection permanente" \
            "JTAG/SWD désactivé de façon irréversible."
    } else {
        nevelio_medium "STM32L4_RDP_LEVEL1" \
            "STM32L4 RDP Level 1 (0x[format %02x $rdp])" \
            "Protection partielle. Downgrade possible vers Level 0 (efface la flash)."
    }
}

# ── Audit générique DAP ───────────────────────────────────────────────────────

proc audit_generic_dap {} {
    nevelio_log "Audit DAP (Debug Access Port) générique..."

    if {[catch {dap info} out]} {
        nevelio_medium "DAP_INFO_FAILED" \
            "Impossible d'accéder au DAP" \
            "La commande `dap info` a échoué. Vérifier le câblage JTAG/SWD \
             et la configuration OpenOCD (interface + target)."
        return
    }

    nevelio_log "DAP accessible : debug en lecture possible"
    nevelio_info "DAP_ACCESSIBLE" \
        "Debug Access Port accessible via JTAG/SWD" \
        "Le DAP répond normalement. L'accès debug est ouvert. \
         Vérifier le niveau de protection (RDP/LDP selon le MCU cible)."

    # Vérifier CoreSight components
    if {[catch {set idcode [dap get IDCODE]} err]} {
        nevelio_log "IDCODE non disponible : $err"
    } else {
        nevelio_log "IDCODE : 0x[format %08x $idcode]"
    }
}

# ── Audit UART ────────────────────────────────────────────────────────────────

proc audit_bootloader_uart {} {
    nevelio_log "Vérification mode bootloader UART STM32..."

    # Sur STM32, le bootloader UART system memory est à 0x1FFF0000
    set sysmem_sig [safe_mrw 0x1FFF0000]
    if {$sysmem_sig == -1} { return }

    # Vérifier la signature du bootloader STM32 system (0xXXXXXXXX selon la famille)
    nevelio_info "STM32_SYSMEM" \
        "System Memory (bootloader UART) sondée" \
        "0x1FFF0000 = 0x[format %08x $sysmem_sig]. \
         Si le BOOT0 pin est à 1, l'UART bootloader démarre en lieu du firmware."
}

# ── Routage selon la cible ────────────────────────────────────────────────────

proc run_audit {target} {
    nevelio_log "Nevelio JTAG Audit v$::NEVELIO_VERSION — cible : $target"
    nevelio_log "Mode dry-run : $::DRY_RUN"

    switch -glob $target {
        "stm32f*" - "stm32F*" {
            audit_stm32_rdp
            audit_bootloader_uart
        }
        "stm32l*" - "stm32L*" {
            audit_stm32l4_rdp
        }
        "generic" - "*" {
            audit_generic_dap
        }
    }

    nevelio_log "Audit terminé."
}

# ── Point d'entrée ────────────────────────────────────────────────────────────

# Variables configurables par OpenOCD -c "set TARGET stm32f4x; set DRY_RUN 1"
if {![info exists TARGET]}  { set TARGET "generic" }
if {![info exists DRY_RUN]} { set DRY_RUN 0        }

# Initialiser et halter la cible
if {[catch {
    init
    halt
} err]} {
    nevelio_log "Erreur d'initialisation : $err"
    nevelio_medium "JTAG_INIT_FAILED" \
        "Initialisation JTAG/SWD échouée" \
        "OpenOCD n'a pas pu se connecter à la cible. \
         Vérifier le câblage, la tension (3.3V/1.8V), la configuration OpenOCD \
         et que la cible est bien alimentée."
    exit 1
}

run_audit $TARGET
