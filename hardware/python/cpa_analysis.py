#!/usr/bin/env python3
"""
Nevelio Hardware Security — Correlation Power Analysis (CPA) + TVLA
Implémentation CPA sur AES-128 (attaque au premier AddRoundKey + SubBytes).
Visualisation matplotlib + TVLA via SCALib ou scipy.

Usage :
    python3 cpa_analysis.py --traces traces.npz --output-key recovered_key.hex
    python3 cpa_analysis.py --traces traces.npz --tvla --plot
    python3 cpa_analysis.py --simulate --n 500 --plot   # démo sans hardware

Prérequis :
    pip install numpy scipy matplotlib
    pip install chipwhisperer   # optionnel, pour generate_simulated_traces
    pip install scalib          # optionnel, pour TVLA précis
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"

# ── Imports optionnels ────────────────────────────────────────────────────────

try:
    import numpy as np
    NP_AVAILABLE = True
except ImportError:
    NP_AVAILABLE = False

try:
    from scipy import stats as scipy_stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use("Agg")  # backend sans affichage (CI/serveur)
    import matplotlib.pyplot as plt
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False

try:
    import scalib
    SCALIB_AVAILABLE = True
except ImportError:
    SCALIB_AVAILABLE = False

# ── AES S-Box ────────────────────────────────────────────────────────────────

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]


def aes_sbox(b: int) -> int:
    """Retourne S-Box[b]."""
    return _SBOX[b & 0xFF]


def hamming_weight(v: int) -> int:
    """Nombre de bits à 1 (popcount)."""
    return bin(v).count('1')


# ── Modèle de fuite ──────────────────────────────────────────────────────────

def leakage_model(plaintext_byte: int, key_hypothesis: int) -> int:
    """HW(SBox(pt[i] XOR k)) — modèle Hamming Weight au premier AddRoundKey."""
    return hamming_weight(aes_sbox(plaintext_byte ^ key_hypothesis))


# ── CPA ──────────────────────────────────────────────────────────────────────

def cpa_attack_one_byte(
    traces:    "np.ndarray",  # shape (n_traces, n_samples)
    plaintexts:"np.ndarray",  # shape (n_traces, 16) uint8
    byte_idx:  int,
) -> tuple[int, "np.ndarray"]:
    """
    Attaque CPA sur un seul byte de la clé.
    Retourne (meilleur_candidat, corrélations_max_par_hypothèse).
    """
    n_traces = traces.shape[0]
    hyp_matrix = np.zeros((256, n_traces), dtype=np.float32)

    for k in range(256):
        for t in range(n_traces):
            hyp_matrix[k, t] = leakage_model(plaintexts[t, byte_idx], k)

    # Pearson correlation entre chaque hypothèse et chaque instant
    max_corr = np.zeros(256, dtype=np.float32)
    for k in range(256):
        h = hyp_matrix[k]
        h_std = h.std()
        if h_std < 1e-10:
            continue

        # Vectorisé : correlation de h avec toutes les colonnes de traces
        t_mean  = traces.mean(axis=0)
        h_mean  = h.mean()
        num     = ((traces - t_mean) * (h - h_mean)[:, None]).mean(axis=0)
        denom   = traces.std(axis=0) * h_std
        # Éviter division par zéro
        with np.errstate(invalid='ignore', divide='ignore'):
            corr = np.where(denom > 1e-10, num / denom, 0.0)

        max_corr[k] = np.abs(corr).max()

    best_key = int(np.argmax(max_corr))
    return best_key, max_corr


def cpa_full_key(
    traces:    "np.ndarray",
    plaintexts:"np.ndarray",
) -> tuple[bytes, list]:
    """
    Attaque CPA complète sur les 16 bytes de la clé.
    Retourne (clé_recouvrée_bytes, liste_de_max_corr_par_byte).
    """
    key   = bytearray(16)
    corrs = []

    for byte_idx in range(16):
        best, max_corr = cpa_attack_one_byte(traces, plaintexts, byte_idx)
        key[byte_idx]  = best
        corrs.append(max_corr)
        confidence = max_corr[best]
        print(f"  Byte {byte_idx:2d} → 0x{best:02X}  (corrélation max : {confidence:.4f})")

    return bytes(key), corrs


# ── TVLA ─────────────────────────────────────────────────────────────────────

def tvla_welch(
    fixed_traces:  "np.ndarray",  # traces avec plaintext fixe
    random_traces: "np.ndarray",  # traces avec plaintext aléatoire
    threshold:     float = 4.5,   # seuil standard du papier TVLA (Goodwill 2011)
) -> tuple["np.ndarray", bool]:
    """
    TVLA (Test Vector Leakage Assessment) — Welch t-test.
    Retourne (t_values, leakage_detected).
    Seuil standard : |t| > 4.5 → fuite statistiquement significative (p < 6e-6).
    """
    if SCALIB_AVAILABLE:
        return _tvla_scalib(fixed_traces, random_traces, threshold)
    elif SCIPY_AVAILABLE:
        return _tvla_scipy(fixed_traces, random_traces, threshold)
    else:
        raise RuntimeError(
            "scipy ou scalib requis pour TVLA : pip install scipy"
        )


def _tvla_scipy(fixed_traces, random_traces, threshold):
    """TVLA via scipy.stats.ttest_ind (Welch)."""
    t_values, _ = scipy_stats.ttest_ind(
        fixed_traces, random_traces,
        axis=0, equal_var=False
    )
    leakage = bool(np.abs(t_values).max() > threshold)
    return t_values, leakage


def _tvla_scalib(fixed_traces, random_traces, threshold):
    """TVLA via SCALib (plus précis sur grandes quantités de traces)."""
    from scalib.postprocessing import SNR
    # SCALib Ttest
    t = scalib.postprocessing.Ttest(len(fixed_traces[0]))
    t.fit_u(fixed_traces.astype(np.int16), np.zeros(len(fixed_traces), dtype=np.uint16))
    t.fit_u(random_traces.astype(np.int16), np.ones(len(random_traces), dtype=np.uint16))
    t_values = t.get_ttest()
    leakage = bool(np.abs(t_values).max() > threshold)
    return t_values, leakage


# ── Visualisation ─────────────────────────────────────────────────────────────

def plot_traces(
    traces:   "np.ndarray",
    n_show:   int = 10,
    save_to:  str | None = None,
    title:    str = "Power Traces",
) -> None:
    """Trace les n_show premières traces de consommation."""
    if not MPL_AVAILABLE:
        print("  [!] matplotlib non disponible — visualisation ignorée.", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(14, 5))
    for i in range(min(n_show, len(traces))):
        ax.plot(traces[i], alpha=0.4, linewidth=0.5)
    ax.set_title(title)
    ax.set_xlabel("Échantillon")
    ax.set_ylabel("Amplitude")
    ax.grid(True, alpha=0.3)

    if save_to:
        plt.tight_layout()
        plt.savefig(save_to, dpi=150)
        print(f"  [✓] Traces sauvegardées : {save_to}")
    else:
        plt.tight_layout()
        plt.savefig("traces.png", dpi=150)
        print("  [✓] Traces sauvegardées : traces.png")
    plt.close()


def plot_cpa_results(
    max_corrs:   list,
    recovered_key: bytes,
    save_to:     str | None = None,
) -> None:
    """Affiche les corrélations CPA pour chaque byte de clé."""
    if not MPL_AVAILABLE:
        return

    fig, axes = plt.subplots(4, 4, figsize=(16, 10))
    axes = axes.flatten()

    for byte_idx, corr in enumerate(max_corrs):
        ax = axes[byte_idx]
        ax.bar(range(256), corr, width=1, color='steelblue', alpha=0.7)
        best = recovered_key[byte_idx]
        ax.bar(best, corr[best], width=2, color='red', label=f'0x{best:02X}')
        ax.set_title(f"Byte {byte_idx} → 0x{best:02X}")
        ax.set_xlim(0, 256)
        ax.tick_params(labelsize=7)

    plt.suptitle("CPA — Corrélation max par hypothèse de clé", fontsize=13)
    plt.tight_layout()

    out = save_to or "cpa_results.png"
    plt.savefig(out, dpi=150)
    print(f"  [✓] Résultats CPA sauvegardés : {out}")
    plt.close()


def plot_tvla(
    t_values: "np.ndarray",
    threshold: float = 4.5,
    save_to:  str | None = None,
) -> None:
    """Visualise les résultats TVLA avec seuil."""
    if not MPL_AVAILABLE:
        return

    fig, ax = plt.subplots(figsize=(14, 4))
    ax.plot(t_values, linewidth=0.8, color='navy')
    ax.axhline( threshold, color='red', linestyle='--', linewidth=1, label=f'+{threshold}')
    ax.axhline(-threshold, color='red', linestyle='--', linewidth=1, label=f'-{threshold}')
    ax.fill_between(range(len(t_values)), t_values,
                    where=np.abs(t_values) > threshold,
                    color='red', alpha=0.3, label='Fuite détectée')
    ax.set_title("TVLA — t de Welch (|t| > 4.5 = fuite significative)")
    ax.set_xlabel("Échantillon")
    ax.set_ylabel("t-statistique")
    ax.legend()
    ax.grid(True, alpha=0.3)

    out = save_to or "tvla.png"
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    print(f"  [✓] TVLA sauvegardé : {out}")
    plt.close()


# ── Pipeline complet ─────────────────────────────────────────────────────────

def generate_simulated_traces_cpa(n_traces: int, n_samples: int = 5000):
    """Génère des traces simulées avec fuite AES réaliste."""
    import secrets

    SECRET_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    traces     = np.zeros((n_traces, n_samples), dtype=np.float32)
    plaintexts = np.zeros((n_traces, 16),        dtype=np.uint8)

    for i in range(n_traces):
        pt = list(secrets.token_bytes(16))
        plaintexts[i] = pt
        for byte_idx in range(16):
            leak = hamming_weight(aes_sbox(pt[byte_idx] ^ SECRET_KEY[byte_idx]))
            center = byte_idx * (n_samples // 16) + (n_samples // 32)
            traces[i, center] += leak * 0.3
        traces[i] += np.random.normal(0, 0.05, n_samples).astype(np.float32)

    return traces, plaintexts, SECRET_KEY


def run_analysis(args: argparse.Namespace) -> int:
    if not NP_AVAILABLE:
        print("[✗] numpy requis : pip install numpy", file=sys.stderr)
        return 1

    print(f"\n  Nevelio CPA Analysis v{VERSION}\n")

    # Chargement ou simulation des traces
    if args.simulate:
        print(f"  [i] Mode simulation — génération de {args.n} traces AES-128...")
        traces, plaintexts, secret_key = generate_simulated_traces_cpa(args.n)
        print(f"  Clé secrète simulée : {secret_key.hex()}\n")
    else:
        if not args.traces:
            print("[✗] --traces requis (ou --simulate)", file=sys.stderr)
            return 1
        print(f"  Chargement des traces : {args.traces}")
        data   = np.load(args.traces)
        traces = data["traces"]
        plaintexts = data["plaintexts"]
        secret_key = None
        print(f"  {traces.shape[0]} traces × {traces.shape[1]} échantillons\n")

    # Visualisation des traces brutes
    if args.plot:
        plot_traces(traces, n_show=20,
                    save_to=args.plot_dir + "/traces_raw.png" if args.plot_dir else None)

    results = {"tool": "nevelio-hw CPA", "version": VERSION,
               "timestamp": datetime.now(timezone.utc).isoformat()}

    # CPA
    print("  [*] Attaque CPA en cours...")
    recovered_key, corrs = cpa_full_key(traces, plaintexts)
    print(f"\n  Clé recouvrée : {recovered_key.hex()}")

    if secret_key:
        if recovered_key == secret_key:
            print("  [✓] Clé correctement recouvrée !")
        else:
            wrong = sum(1 for a, b in zip(recovered_key, secret_key) if a != b)
            print(f"  [!] {wrong}/16 bytes incorrects")

    results["recovered_key"] = recovered_key.hex()

    if args.plot:
        plot_cpa_results(corrs, recovered_key,
            save_to=args.plot_dir + "/cpa_results.png" if args.plot_dir else None)

    # TVLA
    if args.tvla:
        print("\n  [*] TVLA en cours...")
        mid = len(traces) // 2
        try:
            t_values, leakage = tvla_welch(traces[:mid], traces[mid:])
            status = "FUITE DÉTECTÉE" if leakage else "Pas de fuite détectée"
            t_max  = float(np.abs(t_values).max())
            print(f"  TVLA → |t|_max = {t_max:.2f}  ({status})")
            results["tvla"] = {"t_max": t_max, "leakage_detected": leakage}

            if args.plot:
                plot_tvla(t_values,
                    save_to=args.plot_dir + "/tvla.png" if args.plot_dir else None)
        except RuntimeError as e:
            print(f"  [!] TVLA non disponible : {e}", file=sys.stderr)

    # Sauvegarde
    if args.output_key:
        Path(args.output_key).write_text(recovered_key.hex() + "\n")
        print(f"\n  [✓] Clé sauvegardée : {args.output_key}")

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(results, indent=2))
        print(f"  [✓] Rapport JSON : {args.output_json}")

    return 0


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Nevelio — Correlation Power Analysis (CPA) + TVLA"
    )
    parser.add_argument("--traces",      help="Fichier .npz de traces (chipwhisperer_acq.py)")
    parser.add_argument("--simulate",    action="store_true",
                        help="Générer des traces simulées (démo sans hardware)")
    parser.add_argument("--n",           type=int, default=500,
                        help="Nombre de traces simulées (avec --simulate)")
    parser.add_argument("--tvla",        action="store_true",
                        help="Lancer le TVLA (Test Vector Leakage Assessment)")
    parser.add_argument("--plot",        action="store_true",
                        help="Générer des graphiques matplotlib")
    parser.add_argument("--plot-dir",    default=".",
                        help="Répertoire pour les graphiques (défaut: .)")
    parser.add_argument("--output-key",  help="Fichier de sortie pour la clé recouvrée (.hex)")
    parser.add_argument("--output-json", help="Rapport JSON complet")
    args = parser.parse_args()
    sys.exit(run_analysis(args))


if __name__ == "__main__":
    main()
