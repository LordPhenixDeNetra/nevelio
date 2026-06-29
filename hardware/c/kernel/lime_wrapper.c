/*
 * Nevelio Hardware Security — LiME-compatible Memory Acquisition Wrapper
 *
 * Ce module noyau Linux exporte la RAM physique via un fichier ou un socket TCP.
 * Il est basé sur les principes de LiME (Linux Memory Extractor) mais simplifié
 * pour l'intégration dans le pipeline nevelio-hw.
 *
 * Compilation :
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 * Chargement :
 *   sudo insmod lime_wrapper.ko path=/tmp/nevelio_mem.lime format=lime
 * Déchargement :
 *   sudo rmmod lime_wrapper
 *
 * Paramètres :
 *   path    = chemin de sortie (fichier ou tcp:port pour extraction réseau)
 *   format  = lime | raw | padded
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/io.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Nevelio Hardware Security Team");
MODULE_DESCRIPTION("Forensic Memory Acquisition — LiME-compatible format");
MODULE_VERSION("0.1.0");

/* ── Paramètres du module ────────────────────────────────────────────────── */

static char *path   = "";
static char *format = "lime";

module_param(path,   charp, S_IRUGO);
module_param(format, charp, S_IRUGO);
MODULE_PARM_DESC(path,   "Chemin de sortie (fichier) ou tcp:port");
MODULE_PARM_DESC(format, "Format : lime | raw | padded");

/* ── En-tête LiME ────────────────────────────────────────────────────────── */

/*
 * Spécification LiME :
 * Chaque région mémoire physique est précédée d'un en-tête de 32 octets :
 *
 *   [0..3]   magic     = 0x4C694D45 ('LiME')
 *   [4..7]   version   = 1
 *   [8..15]  start     = adresse physique de début
 *   [16..23] end       = adresse physique de fin (incluse)
 *   [24..31] reserved  = 0
 */

#define LIME_MAGIC   0x4C694D45U
#define LIME_VERSION 1

struct __attribute__((packed)) lime_header {
    uint32_t magic;
    uint32_t version;
    uint64_t start;
    uint64_t end;
    uint64_t reserved;
};

/* ── Contexte d'écriture ─────────────────────────────────────────────────── */

struct nevelio_writer {
    struct file *fp;
    loff_t       pos;
    bool         use_lime_format;
    uint64_t     bytes_written;
    uint64_t     regions_written;
};

/* ── Écriture noyau vers fichier ─────────────────────────────────────────── */

static int write_buf(struct nevelio_writer *w, const void *buf, size_t len)
{
    ssize_t ret;

    ret = kernel_write(w->fp, buf, len, &w->pos);
    if (ret < 0) {
        pr_err("nevelio_lime: kernel_write failed: %zd\n", ret);
        return (int)ret;
    }
    w->bytes_written += ret;
    return 0;
}

/* ── Écriture d'une région mémoire ────────────────────────────────────────── */

static int write_memory_region(struct nevelio_writer *w,
                               struct resource       *res)
{
    struct lime_header hdr;
    uint64_t start = res->start;
    uint64_t end   = res->end;
    uint64_t pfn, pfn_end;
    struct page *page;
    void *vaddr;
    int ret = 0;

    pr_info("nevelio_lime: region 0x%llx - 0x%llx (%llu MB)\n",
            start, end, (end - start + 1) / (1024 * 1024));

    /* En-tête LiME */
    if (w->use_lime_format) {
        hdr.magic    = LIME_MAGIC;
        hdr.version  = LIME_VERSION;
        hdr.start    = start;
        hdr.end      = end;
        hdr.reserved = 0;
        ret = write_buf(w, &hdr, sizeof(hdr));
        if (ret < 0)
            return ret;
    }

    /* Itération page par page (4KB chacune) */
    pfn     = start >> PAGE_SHIFT;
    pfn_end = end   >> PAGE_SHIFT;

    for (; pfn <= pfn_end; pfn++) {
        if (!pfn_valid(pfn)) {
            /* Écrire des zéros pour les PFN invalides en mode padded */
            if (strncmp(format, "padded", 6) == 0) {
                char zero[PAGE_SIZE] = {0};
                ret = write_buf(w, zero, PAGE_SIZE);
                if (ret < 0)
                    return ret;
            }
            continue;
        }

        page  = pfn_to_page(pfn);
        vaddr = kmap(page);
        if (!vaddr)
            continue;

        ret = write_buf(w, vaddr, PAGE_SIZE);
        kunmap(page);

        if (ret < 0)
            return ret;

        /* Céder le processeur périodiquement (ne pas bloquer le système) */
        if ((pfn & 0x3FF) == 0)
            cond_resched();
    }

    w->regions_written++;
    return 0;
}

/* ── Parcours des régions physiques RAM ──────────────────────────────────── */

static int dump_memory(struct nevelio_writer *w)
{
    struct resource *ram;
    struct resource *child;
    int ret = 0;

    /*
     * iomem_resource est la racine de l'arbre des ressources I/O.
     * On cherche les régions "System RAM" pour récupérer uniquement la RAM physique.
     */
    ram = &iomem_resource;

    read_lock(&resource_lock);
    for (child = ram->child; child; child = child->sibling) {
        if (strcmp(child->name, "System RAM") == 0) {
            read_unlock(&resource_lock);
            ret = write_memory_region(w, child);
            read_lock(&resource_lock);
            if (ret < 0)
                break;
        }
    }
    read_unlock(&resource_lock);

    return ret;
}

/* ── Initialisation du module ────────────────────────────────────────────── */

static int __init nevelio_lime_init(void)
{
    struct nevelio_writer w = {0};
    int ret;

    pr_info("nevelio_lime: démarrage — format=%s, path=%s\n", format, path);

    if (!path || path[0] == '\0') {
        pr_err("nevelio_lime: paramètre 'path' requis. "
               "Exemple : insmod lime_wrapper.ko path=/tmp/mem.lime format=lime\n");
        return -EINVAL;
    }

    /* Ouvrir le fichier de sortie */
    w.fp = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(w.fp)) {
        pr_err("nevelio_lime: impossible d'ouvrir %s: %ld\n", path, PTR_ERR(w.fp));
        return PTR_ERR(w.fp);
    }

    w.pos            = 0;
    w.use_lime_format = (strncmp(format, "lime", 4) == 0);
    w.bytes_written  = 0;
    w.regions_written = 0;

    /* Dump mémoire */
    ret = dump_memory(&w);

    filp_close(w.fp, NULL);

    if (ret < 0) {
        pr_err("nevelio_lime: dump échoué: %d\n", ret);
        return ret;
    }

    pr_info("nevelio_lime: dump terminé — %llu régions, %llu MB\n",
            w.regions_written,
            w.bytes_written / (1024 * 1024));

    /*
     * Retourner -ENODEV pour déclencher le déchargement automatique du module.
     * LiME utilise cette convention : init échoue intentionnellement après dump
     * pour que insmod décharge le module immédiatement.
     */
    return -ENODEV;
}

static void __exit nevelio_lime_exit(void)
{
    pr_info("nevelio_lime: module déchargé.\n");
}

module_init(nevelio_lime_init);
module_exit(nevelio_lime_exit);
