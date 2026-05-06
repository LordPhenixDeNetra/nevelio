# Extensions possibles : Sécurité Hardware

> Pistes d'extension de Nevelio vers les vulnérabilités hardware et bas niveau.
> Ces fonctionnalités sont hors scope de la v0.1 (scanner API couche 7).

---

## Vulnérabilités hardware à couvrir

### Attaques CPU
- **Spectre / Meltdown** — Exécution spéculative des processeurs (Intel, AMD, ARM).
  Permettent de lire la mémoire d'autres processus, y compris le noyau OS.
- **Rowhammer** — Accès répétés à des lignes DRAM adjacentes pour faire basculer
  des bits voisins. Élévation de privilèges démontrée.

### Canaux auxiliaires (Side-channel)
- **Timing attacks** — Mesurer le temps d'exécution d'une opération cryptographique
  pour retrouver des informations sur la clé secrète.
- **Power analysis** — Mesurer la consommation électrique pendant un chiffrement
  (courant sur cartes à puce).
- **Electromagnetic analysis** — Même principe via les émissions EM.

### Attaques physiques
- **Cold boot attack** — La RAM conserve ses données quelques secondes après
  coupure courant. Permet d'extraire des clés BitLocker/FileVault.
- **DMA attacks** — Via Thunderbolt/FireWire, un périphérique accède directement
  à la RAM sans passer par le CPU.
- **JTAG/debug ports** — Interfaces de débogage laissées ouvertes sur embarqué.

### Supply chain
- **Implants hardware** — Composants modifiés en usine ou en transit.
- **Firmware malveillant** — BIOS/UEFI ou firmware disque/réseau infecté,
  persistant après réinstallation OS.

---

## Rôles des langages

### Shell — Extraction brute et automation système

```bash
# Inspecter le firmware d'un appareil
binwalk -e firmware.bin

# Dump de la mémoire RAM (cold boot)
dd if=/dev/mem of=ram.dump bs=1M count=512

# Inspecter le BIOS/UEFI
dmidecode -t bios

# Lire les interfaces PCI (détection DMA)
lspci -vvv

# Extraire des chaînes lisibles d'un binaire
strings firmware.bin | grep -i "password\|key\|secret"

# Lire le flash SPI d'une carte mère
flashrom -p internal -r bios_backup.bin
```

**Intégration Nevelio envisagée :** module `nevelio-hardware` qui exécute
ces commandes via `std::process::Command` et parse les sorties.

---

### Python — Analyse de dumps et timing

```python
# ── Timing attack sur un endpoint HTTP ──────────────────────────────────────
import requests, time, statistics

def timing_oracle(payload, n=100):
    """Mesure le temps médian de réponse pour détecter un side-channel."""
    temps = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        requests.post("https://api.example.com/login", json=payload)
        temps.append(time.perf_counter_ns() - t0)
    return statistics.median(temps)

# Comparer deux payloads — une différence > 1ms peut indiquer une fuite
t_valide   = timing_oracle({"user": "admin", "pass": "correct"})
t_invalide = timing_oracle({"user": "admin", "pass": "wrong"})
print(f"Δ = {abs(t_valide - t_invalide) / 1e6:.3f} ms")


# ── Analyse mémoire avec Volatility ─────────────────────────────────────────
# pip install volatility3

# volatility -f ram.dump windows.pslist   → liste des processus
# volatility -f ram.dump windows.hashdump → extraire les hashs NTLM
# volatility -f ram.dump windows.netscan  → connexions réseau actives


# ── Manipulation réseau bas niveau avec Scapy ────────────────────────────────
# pip install scapy
from scapy.all import *

# Sniffer le trafic réseau
sniff(iface="eth0", prn=lambda p: p.summary(), count=100)

# Forger un paquet ARP (man-in-the-middle)
arp = ARP(op=2, pdst="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff",
          psrc="192.168.1.100")
send(arp, verbose=False)
```

**Intégration Nevelio envisagée :** module `nevelio-timing` qui effectue
des mesures statistiques précises sur les réponses HTTP (détection de
timing oracles liés à des vulnérabilités hardware côté serveur).

---

### Rust — Exploitation bas niveau

```rust
// ── Mesure de timing haute précision (Spectre-style) ────────────────────────
use std::time::Instant;
use std::hint::black_box;

fn mesure_acces_cache(ptr: *const u8) -> u64 {
    let debut = Instant::now();
    unsafe { black_box(ptr.read_volatile()); }
    debut.elapsed().as_nanos() as u64
}

// Seuil : < 100ns → en cache (ligne lue récemment)
//         > 300ns → pas en cache (accès DRAM)


// ── Pattern Rowhammer (accès répétés DRAM) ───────────────────────────────────
unsafe fn hammer_row(addr_a: *mut u64, addr_b: *mut u64, iterations: usize) {
    for _ in 0..iterations {
        addr_a.read_volatile();
        addr_b.read_volatile();
        // Flush le cache pour forcer un accès DRAM
        core::arch::x86_64::_mm_clflush(addr_a as *const u8);
        core::arch::x86_64::_mm_clflush(addr_b as *const u8);
    }
}
```

**Note :** Ces techniques nécessitent `unsafe` Rust et des droits élevés.
Réservé à la recherche en environnement contrôlé.

---

## Bilan — Ce que Nevelio couvre déjà vs ce qui reste

| Capacité | Nevelio v0.1 | Extension envisagée |
|---|---|---|
| Timing HTTP (SQLi, CMDi time-based) | ✅ | — |
| Automation d'attaques applicatives | ✅ | — |
| Timing oracle statistique (side-channel réseau) | ❌ | Module `timing` (Rust) |
| Analyse firmware / BIOS | ❌ | Module `hardware` (Shell via Command) |
| Analyse dumps mémoire | ❌ | Intégration Volatility (Python subprocess) |
| Exploitation Spectre/Rowhammer | ❌ | Rust `unsafe` — recherche uniquement |
| Manipulation réseau bas niveau | ❌ | Intégration Scapy ou crate `pnet` |

---

## Priorités si extension souhaitée

1. **Module timing oracle** — Extension naturelle de Nevelio, 100% Rust,
   mesures statistiques (médiane, percentile 95) sur les réponses HTTP.
   Détecte les side-channels applicatifs liés au hardware serveur.

2. **Module hardware audit** — Exécute `dmidecode`, `lspci`, `flashrom`
   via `std::process::Command` et parse les sorties pour détecter
   configurations dangereuses (debug ports ouverts, firmware non signé).

3. **Intégration Volatility** — Via subprocess Python, analyse des dumps
   RAM fournis par l'utilisateur dans le cadre d'un incident response.
