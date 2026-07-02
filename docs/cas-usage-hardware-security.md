# Nevelio Hardware Security — Cas d'usage et capacités actuelles

> Ce document décrit ce que `nevelio-hw` peut faire **aujourd'hui** (v0.6.0),
> sans matériel spécial, juste avec une machine Linux de développement ou de pentest.

---

## Ce qui tourne en passif (sans root, sans hardware)

### `hw-cpu` — Sécurité processeur

Utile pour **auditer n'importe quelle machine Linux** avant de la mettre en prod ou en pentest :

- Détecte les mitigations manquantes (Spectre, Meltdown, Retbleed, MDS…) → indique si le CPU est à risque d'exfiltration cross-process
- Vérifie que le microcode CPU est à jour
- Confirme que NX/SMEP/SMAP sont actifs (protection contre shellcode)

**Cas d'usage concret :** audit d'un serveur avant déploiement, vérification d'une VM cloud, check post-pentest pour confirmer que la machine cible est vulnérable aux side-channels.

---

### `hw-firmware` — UEFI/BIOS

- Détecte si Secure Boot est désactivé → porte d'entrée pour bootkits
- Vérifie la version du BIOS + si des mises à jour sont disponibles (via fwupdmgr)
- Détecte les entrées boot UEFI Shell (vecteur d'attaque physique)
- Tente de lire la flash SPI (non-destructif via flashrom)

**Cas d'usage concret :** audit pré-livraison d'un parc de machines, vérification qu'une machine confisquée n'a pas de bootkit.

---

### `hw-dma` — Attaques DMA

- Vérifie si IOMMU/VT-d est actif et bien configuré (off / passthrough / strict)
- Lit le niveau de sécurité Thunderbolt (none → DMA libre, user → partiel, secure → OK)
- Liste les devices PCIe avec capacité BusMaster DMA (FireWire, ExpressCard)
- Vérifie le kernel lockdown (none / integrity / confidentiality)

**Cas d'usage concret :** vérifier qu'un laptop branché en conférence ne peut pas être dumped via un dock Thunderbolt malveillant. Audit de postes de travail sensibles.

---

### `hw-sidechannel` — Canaux auxiliaires

- Mesure si Flush+Reload est faisable en user-space (sans root) → confirme la vulnérabilité aux attaques cache
- Vérifie perf_event_paranoid, ptrace_scope, protections stack (ASLR entropy, mmap_rnd_bits)
- Timing oracle HTTP sur une cible : 100 requêtes, détecte une variance anormale (indicateur de timing SQLi ou auth timing leak)

**Cas d'usage concret :** inclure dans un pentest API pour détecter les timing leaks auth (ex : comparaison de tokens en temps constant vs non). Vérifier qu'un serveur ne laisse pas fuir des infos via timing.

---

### `hw-jtag` — Audit embarqué

- Détecte les sondes JTAG connectées (FTDI, J-Link, ST-Link…) par VID/PID USB
- Détecte les ports série UART ouverts (/dev/ttyUSB*, /dev/ttyACM*)
- Si une sonde est présente + mode actif : lance OpenOCD → lit le niveau RDP STM32 (Read Protection) → signale si la flash est dumpable
- Analyse un firmware binaire (binwalk + strings + r2pipe + angr) via `--target /chemin/firmware.bin`

**Cas d'usage concret :** audit d'un objet connecté (IoT) — brancher la sonde, lancer nevelio-hw, savoir en 30 secondes si le debug est ouvert.

---

### `hw-memory` — Mémoire physique et forensics

- Vérifie le chiffrement du swap (dm-crypt) et KASLR
- Vérifie la configuration des core dumps (risque de leak de mémoire en clair)
- Détecte si l'ECC est disponible via le sous-système EDAC
- Analyse DDR4/DDR5 (vulnérabilité TRRespass)
- Dump RAM via avml (passif, sans module kernel) si disponible
- Lance Volatility 3 sur un dump : détecte processus cachés (DKOM), injections mémoire (malfind), hashes NTLM, hooks rootkit syscall

**Cas d'usage concret :** forensics post-incident — dumper la RAM d'une machine compromise et lancer l'analyse Volatility sans quitter nevelio-hw.

---

### `hw-dma-fpga` — Audit DMA approfondi

En passif (sans FPGA) :

- Re-vérifie IOMMU en mode strict (`iommu=force`)
- Lit chaque device Thunderbolt et son niveau de sécurité détaillé

**Cas d'usage concret :** double confirmation des findings hw-dma sur les postes à haute sensibilité.

---

## Résumé par scénario

| Scénario | Modules utiles |
|---|---|
| Audit pré-prod d'un serveur Linux | hw-cpu + hw-firmware + hw-dma |
| Pentest physique d'un laptop | hw-dma + hw-dma-fpga + hw-firmware |
| Audit IoT / embarqué (avec sonde JTAG) | hw-jtag |
| Forensics post-incident (dump RAM) | hw-memory + Volatility |
| Détection timing leak API | hw-sidechannel |
| Check complet sans hardware spécifique | tous les modules en passif |

---

## Commandes de lancement

```bash
# Audit complet passif — rapport terminal
./target/release/nevelio-hw scan --accept-legal

# Rapport HTML livrable
./target/release/nevelio-hw scan --accept-legal --output html --out-file audit.html

# Rapport JSON intégrable dans nevelio principal
./target/release/nevelio-hw scan --accept-legal --output nevelio-json

# En anglais
./target/release/nevelio-hw scan --accept-legal --lang en

# Audit d'un firmware embarqué
./target/release/nevelio-hw scan --accept-legal --target /chemin/vers/firmware.bin

# Forensics sur un dump RAM existant
python3 hardware/python/volatility_runner.py --dump /tmp/memory.lime --os linux
```

---

## Ce qui nécessite du matériel physique (tâches restantes)

| Tâche | Matériel requis |
|---|---|
| Test Rowhammer réel | Machine dédiée (jamais sur machine de travail) |
| Validation Volatility sur dump VM | VM Linux publiée (projet Volatility) |
| JTAG sur STM32 avec RDP | STM32 Nucleo + sonde J-Link ou ST-Link |
| Acquisition traces CPA | ChipWhisperer Nano/Lite |
| PCIe DMA via FPGA | Nexys A7-35T + Vivado |
| Test DMA Thunderbolt réel | Câble TB3 + machine cible |

Ces 8 tâches ne bloquent pas l'usage quotidien de l'outil — tout le reste fonctionne sans matériel spécifique.
