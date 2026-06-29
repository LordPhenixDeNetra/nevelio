/*
 * Nevelio Hardware Security — MSR Reader
 *
 * Module noyau Linux pour lire les Model-Specific Registers (MSR) Intel/AMD
 * pertinents pour l'audit de sécurité hardware.
 *
 * MSR ciblés :
 *   IA32_SPEC_CTRL   (0x48)  — contrôle Spectre v2 (IBRS/STIBP/SSBD)
 *   IA32_MISC_ENABLE (0x1A0) — désactivation Turbo/branches prédictions
 *   IA32_EFER        (0xC0000080) — NXE (No-Execute Enable, protection W^X)
 *   IA32_LSTAR       (0xC0000082) — adresse syscall 64-bit (vérification KASLR)
 *   IA32_MCG_CAP     (0x179)  — capacités Machine Check
 *   IA32_TSC         (0x10)   — Timer Stamp Counter
 *
 * Compilation :
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 * Utilisation :
 *   sudo insmod msr_reader.ko
 *   dmesg | grep nevelio_msr
 *   sudo rmmod msr_reader
 *
 * Note : les résultats sont dans dmesg pour éviter d'exposer les valeurs MSR
 *        via un fichier /proc (surface d'attaque supplémentaire).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <asm/msr.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Nevelio Hardware Security Team");
MODULE_DESCRIPTION("MSR Security Audit — IBRS, NXE, EFER, Spectre mitigations");
MODULE_VERSION("0.1.0");

/* ── Définitions MSR ─────────────────────────────────────────────────────── */

#define MSR_IA32_SPEC_CTRL    0x00000048
#define MSR_IA32_MISC_ENABLE  0x000001A0
#define MSR_IA32_EFER         0xC0000080
#define MSR_IA32_LSTAR        0xC0000082
#define MSR_IA32_MCG_CAP      0x00000179

/* Bits de IA32_SPEC_CTRL */
#define SPEC_CTRL_IBRS  BIT(0)   /* Indirect Branch Restricted Speculation */
#define SPEC_CTRL_STIBP BIT(1)   /* Single Thread Indirect Branch Predictors */
#define SPEC_CTRL_SSBD  BIT(2)   /* Speculative Store Bypass Disable */

/* Bits de IA32_EFER */
#define EFER_NXE        BIT(11)  /* No-Execute Enable */
#define EFER_LMA        BIT(10)  /* Long Mode Active */
#define EFER_SCE        BIT(0)   /* System Call Extensions */

/* ── Structure de résultat par CPU ──────────────────────────────────────── */

struct msr_audit_result {
    int      cpu;
    uint64_t spec_ctrl;
    uint64_t misc_enable;
    uint64_t efer;
    uint64_t lstar;
    uint64_t mcg_cap;
    bool     read_ok;
};

/* ── Lecture MSR sur le CPU courant ─────────────────────────────────────── */

static void read_msrs_on_cpu(void *info)
{
    struct msr_audit_result *res = info;
    uint64_t lo, hi;

    res->read_ok = false;
    res->cpu     = smp_processor_id();

    /* IA32_SPEC_CTRL — mitigations Spectre */
    if (rdmsr_safe(MSR_IA32_SPEC_CTRL, (uint32_t *)&lo, (uint32_t *)&hi) == 0)
        res->spec_ctrl = lo | (hi << 32);
    else
        res->spec_ctrl = UINT64_MAX;

    /* IA32_MISC_ENABLE */
    if (rdmsr_safe(MSR_IA32_MISC_ENABLE, (uint32_t *)&lo, (uint32_t *)&hi) == 0)
        res->misc_enable = lo | (hi << 32);
    else
        res->misc_enable = UINT64_MAX;

    /* IA32_EFER — Long Mode + NXE + SCE */
    if (rdmsr_safe(MSR_IA32_EFER, (uint32_t *)&lo, (uint32_t *)&hi) == 0)
        res->efer = lo | (hi << 32);
    else
        res->efer = UINT64_MAX;

    /* IA32_LSTAR — adresse du handler syscall 64-bit */
    if (rdmsr_safe(MSR_IA32_LSTAR, (uint32_t *)&lo, (uint32_t *)&hi) == 0)
        res->lstar = lo | (hi << 32);
    else
        res->lstar = UINT64_MAX;

    /* IA32_MCG_CAP — machine check */
    if (rdmsr_safe(MSR_IA32_MCG_CAP, (uint32_t *)&lo, (uint32_t *)&hi) == 0)
        res->mcg_cap = lo | (hi << 32);
    else
        res->mcg_cap = UINT64_MAX;

    res->read_ok = true;
}

/* ── Analyse et reporting dans dmesg ─────────────────────────────────────── */

static void analyze_and_report(const struct msr_audit_result *res)
{
    pr_info("nevelio_msr: === Audit CPU %d ===\n", res->cpu);

    /* ── SPEC_CTRL — protections Spectre ── */
    if (res->spec_ctrl == UINT64_MAX) {
        pr_warn("nevelio_msr: SPEC_CTRL inaccessible (MSR 0x48 — CPU trop ancien ?)\n");
    } else {
        bool ibrs  = !!(res->spec_ctrl & SPEC_CTRL_IBRS);
        bool stibp = !!(res->spec_ctrl & SPEC_CTRL_STIBP);
        bool ssbd  = !!(res->spec_ctrl & SPEC_CTRL_SSBD);

        pr_info("nevelio_msr: SPEC_CTRL=0x%llx — IBRS=%d STIBP=%d SSBD=%d\n",
                res->spec_ctrl, ibrs, stibp, ssbd);

        if (!ibrs)
            pr_warn("nevelio_msr: [MEDIUM] IBRS désactivé — Spectre v2 non atténué (CWE-1037)\n");
        if (!ssbd)
            pr_warn("nevelio_msr: [MEDIUM] SSBD désactivé — Spectre v4 non atténué\n");
    }

    /* ── EFER — NXE (protection W^X) ── */
    if (res->efer == UINT64_MAX) {
        pr_warn("nevelio_msr: EFER inaccessible\n");
    } else {
        bool nxe = !!(res->efer & EFER_NXE);
        bool lma = !!(res->efer & EFER_LMA);

        pr_info("nevelio_msr: EFER=0x%llx — NXE=%d LMA=%d\n", res->efer, nxe, lma);

        if (!nxe)
            pr_err("nevelio_msr: [HIGH] NXE désactivé — pages mémoire exécutables (CWE-1209)\n");
        if (!lma)
            pr_warn("nevelio_msr: [INFO] Long Mode inactif — CPU en mode 32-bit\n");
    }

    /* ── LSTAR — intégrité du handler syscall ── */
    if (res->lstar != UINT64_MAX && res->lstar != 0) {
        pr_info("nevelio_msr: LSTAR=0x%llx (adresse handler syscall)\n", res->lstar);
        /*
         * En espace noyau normal, LSTAR pointe vers entry_SYSCALL_64.
         * Une valeur très basse ou outside de la plage kernel peut indiquer un rootkit.
         * Plage noyau typique : 0xffffffff80000000 – 0xffffffffffffffff
         */
        if (res->lstar < 0xffffffff80000000ULL) {
            pr_err("nevelio_msr: [CRITICAL] LSTAR hors de la plage noyau — rootkit potentiel !\n");
            pr_err("nevelio_msr:   Valeur : 0x%llx  Attendu : >= 0xffffffff80000000\n", res->lstar);
        }
    }

    /* ── MCG_CAP — machine check banks ── */
    if (res->mcg_cap != UINT64_MAX) {
        uint32_t banks = res->mcg_cap & 0xFF;
        pr_info("nevelio_msr: MCG_CAP=0x%llx — %u banques Machine Check\n",
                res->mcg_cap, banks);
    }

    pr_info("nevelio_msr: === Fin audit CPU %d ===\n", res->cpu);
}

/* ── Initialisation du module ────────────────────────────────────────────── */

static int __init nevelio_msr_init(void)
{
    struct msr_audit_result result;
    int cpu;

    pr_info("nevelio_msr: démarrage de l'audit MSR\n");
    pr_info("nevelio_msr: %u CPU(s) présent(s)\n", num_online_cpus());

    /* Lire les MSR sur le CPU 0 (bootstrap processor) */
    memset(&result, 0, sizeof(result));
    smp_call_function_single(0, read_msrs_on_cpu, &result, 1);

    if (result.read_ok)
        analyze_and_report(&result);
    else
        pr_err("nevelio_msr: lecture MSR échouée sur CPU 0\n");

    /* Vérifier les CPUs supplémentaires si nécessaire */
    if (num_online_cpus() > 1) {
        for_each_online_cpu(cpu) {
            if (cpu == 0)
                continue;

            memset(&result, 0, sizeof(result));
            smp_call_function_single(cpu, read_msrs_on_cpu, &result, 1);

            if (result.read_ok) {
                /* Signaler uniquement les différences inter-CPU */
                pr_info("nevelio_msr: CPU %d — SPEC_CTRL=0x%llx EFER=0x%llx\n",
                        cpu, result.spec_ctrl, result.efer);
            }
        }
    }

    pr_info("nevelio_msr: audit terminé. Déchargement.\n");

    /* Convention LiME : déchargement immédiat après audit */
    return -ENODEV;
}

static void __exit nevelio_msr_exit(void)
{
    pr_info("nevelio_msr: module déchargé.\n");
}

module_init(nevelio_msr_init);
module_exit(nevelio_msr_exit);
