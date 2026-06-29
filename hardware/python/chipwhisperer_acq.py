#!/usr/bin/env python3
"""
Nevelio Hardware Security — ChipWhisperer Acquisition
Acquisition de traces de consommation électrique via ChipWhisperer Nano/Lite/Pro.
Compatible : SimpleSerial v1/v2, cible AES-128 par défaut.

Usage :
    python3 chipwhisperer_acq.py --n 500 --output traces.npz
    python3 chipwhisperer_acq.py --n 1000 --scope CW-Nano --output traces.npz --target-type simpleserial

Prérequis :
    pip install chipwhisperer numpy
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
MODULE  = "hw-sidechannel-ext"

# ── Paramètres par défaut ─────────────────────────────────────────────────────

DEFAULT_GAIN    = 25     # dB (ChipWhisperer AFE)
DEFAULT_SAMPLES = 5000   # échantillons par trace
DEFAULT_OFFSET  = 0      # décalage dans le segment d'acquisition
DEFAULT_CLOCK   = 7.37e6 # Hz (7.37 MHz — fréquence STM32 par défaut)
AES_BLOCK_SIZE  = 16     # octets

# ── Tentative d'import ChipWhisperer ─────────────────────────────────────────

try:
    import chipwhisperer as cw
    import numpy as np
    CW_AVAILABLE = True
except ImportError:
    CW_AVAILABLE = False

try:
    import numpy as np
    NP_AVAILABLE = True
except ImportError:
    NP_AVAILABLE = False


# ── Connexion scope ──────────────────────────────────────────────────────────

def connect_scope(scope_type: str = "auto") -> object:
    """Connecte le scope ChipWhisperer. Lève RuntimeError si absent."""
    if not CW_AVAILABLE:
        raise RuntimeError(
            "chipwhisperer non installé. Installer avec : pip install chipwhisperer"
        )

    type_map = {
        "auto":    cw.scopes.OpenADC,
        "CW-Nano": cw.scopes.CWNano,
        "CW-Lite": cw.scopes.OpenADC,
        "CW-Pro":  cw.scopes.OpenADC,
        "CW-Husky":cw.scopes.CWHuskyScope,
    }
    scope_cls = type_map.get(scope_type, cw.scopes.OpenADC)

    scope = cw.scope(scope_cls)
    scope.default_setup()
    return scope


def configure_scope(scope, gain: int = DEFAULT_GAIN,
                    samples: int = DEFAULT_SAMPLES,
                    offset:  int = DEFAULT_OFFSET,
                    clock:   float = DEFAULT_CLOCK) -> None:
    """Configure les paramètres d'acquisition."""
    scope.gain.db          = gain
    scope.adc.samples      = samples
    scope.adc.offset       = offset
    scope.adc.basic_mode   = "rising_edge"
    scope.clock.clkgen_freq  = clock
    scope.clock.adc_src      = "clkgen_x4"
    scope.trigger.triggers   = "tio4"


def connect_target(scope, target_type: str = "simpleserial") -> object:
    """Connecte la cible via SimpleSerial."""
    if not CW_AVAILABLE:
        raise RuntimeError("chipwhisperer requis pour la connexion cible")

    if target_type == "simpleserial":
        target = cw.target(scope, cw.targets.SimpleSerial)
    elif target_type == "simpleserial2":
        target = cw.target(scope, cw.targets.SimpleSerial2)
    else:
        raise ValueError(f"Type de cible inconnu : {target_type}")

    target.baud = 38400
    return target


# ── Acquisition de traces ────────────────────────────────────────────────────

def capture_trace(scope, target, plaintext: bytes) -> "np.ndarray | None":
    """Capture une trace pour un plaintext donné. Retourne None si timeout."""
    ktp     = cw.ktp.Basic()
    key, _  = ktp.next()

    target.simpleserial_write('k', key)
    target.simpleserial_write('p', plaintext)

    ret = scope.capture()
    if ret:
        return None  # Timeout

    trace     = scope.get_last_trace()
    response  = target.simpleserial_read('r', AES_BLOCK_SIZE)
    return trace


def capture_n_traces(
    scope, target,
    n_traces:  int,
    key:       bytes | None = None,
) -> tuple[list, list, list]:
    """
    Capture n_traces traces avec des plaintexts aléatoires.
    Retourne (traces, plaintexts, ciphertexts).
    """
    import secrets

    traces      = []
    plaintexts  = []
    ciphertexts = []

    if key is None:
        ktp  = cw.ktp.Basic()
        key, _ = ktp.next()
        target.simpleserial_write('k', key)

    for i in range(n_traces):
        pt = secrets.token_bytes(AES_BLOCK_SIZE)
        target.simpleserial_write('p', pt)

        ret = scope.capture()
        if ret:
            print(f"  [!] Timeout à la trace {i+1}/{n_traces}", file=sys.stderr)
            continue

        trace = scope.get_last_trace()
        ct    = target.simpleserial_read('r', AES_BLOCK_SIZE)

        traces.append(trace)
        plaintexts.append(pt)
        ciphertexts.append(ct)

        if (i + 1) % 100 == 0:
            print(f"  [*] {i+1}/{n_traces} traces acquises", file=sys.stderr)

    return traces, plaintexts, ciphertexts


# ── Mode simulation (sans hardware) ─────────────────────────────────────────

def generate_simulated_traces(
    n_traces:  int,
    n_samples: int = DEFAULT_SAMPLES,
    noise_std: float = 0.05,
) -> tuple[list, list, list]:
    """
    Génère des traces simulées pour le développement et les tests.
    Modèle : consommation = HW(AES_SBox(plaintext[0] XOR key[0])) + bruit gaussien.
    """
    if not NP_AVAILABLE:
        raise RuntimeError("numpy requis pour la simulation : pip install numpy")

    import secrets
    from .cpa_analysis import aes_sbox, hamming_weight  # import local

    SECRET_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    traces      = []
    plaintexts  = []
    ciphertexts = []

    for _ in range(n_traces):
        pt    = list(secrets.token_bytes(AES_BLOCK_SIZE))
        trace = np.random.normal(0, noise_std, n_samples)

        # Fuite au premier AddRoundKey + SubBytes pour chaque byte
        for byte_idx in range(AES_BLOCK_SIZE):
            leak = hamming_weight(aes_sbox(pt[byte_idx] ^ SECRET_KEY[byte_idx]))
            sample_idx = byte_idx * (n_samples // AES_BLOCK_SIZE)
            trace[sample_idx] += leak * 0.1

        traces.append(trace)
        plaintexts.append(bytes(pt))
        ciphertexts.append(b'\x00' * AES_BLOCK_SIZE)  # non calculé en simulation

    return traces, plaintexts, ciphertexts


# ── Sauvegarde ───────────────────────────────────────────────────────────────

def save_traces(
    output_path: str,
    traces:      list,
    plaintexts:  list,
    ciphertexts: list,
    metadata:    dict | None = None,
) -> None:
    """Sauvegarde les traces au format .npz (numpy) ou .json."""
    if not NP_AVAILABLE:
        raise RuntimeError("numpy requis pour la sauvegarde : pip install numpy")

    t_arr  = np.array(traces,      dtype=np.float32)
    pt_arr = np.array([list(p) for p in plaintexts],  dtype=np.uint8)
    ct_arr = np.array([list(c) for c in ciphertexts], dtype=np.uint8)

    meta = {
        "tool":        "nevelio-hw ChipWhisperer Acquisition",
        "version":     VERSION,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "n_traces":    len(traces),
        "n_samples":   t_arr.shape[1] if t_arr.ndim > 1 else 0,
        **(metadata or {}),
    }

    if output_path.endswith(".npz"):
        np.savez_compressed(
            output_path,
            traces      = t_arr,
            plaintexts  = pt_arr,
            ciphertexts = ct_arr,
        )
        # Métadonnées dans un fichier json adjacent
        meta_path = output_path.replace(".npz", "_meta.json")
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
        print(f"[✓] Traces sauvegardées : {output_path}")
        print(f"[✓] Métadonnées         : {meta_path}")
    else:
        raise ValueError("Format supporté : .npz uniquement")


def load_traces(path: str) -> tuple[object, object, object, dict]:
    """Charge un fichier .npz de traces."""
    if not NP_AVAILABLE:
        raise RuntimeError("numpy requis : pip install numpy")

    data = np.load(path)
    meta_path = path.replace(".npz", "_meta.json")
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)

    return data["traces"], data["plaintexts"], data["ciphertexts"], meta


# ── Pipeline d'acquisition ───────────────────────────────────────────────────

def run_acquisition(args: argparse.Namespace) -> int:
    """Pipeline complet d'acquisition. Retourne 0 si succès."""
    print(f"\n  Nevelio ChipWhisperer Acquisition v{VERSION}")
    print(f"  Scope : {args.scope}  |  Cible : {args.target_type}")
    print(f"  Traces demandées : {args.n}\n")

    if not CW_AVAILABLE or args.simulate:
        if args.simulate:
            print("  [i] Mode simulation activé (--simulate).")
        else:
            print("  [!] ChipWhisperer non détecté — mode simulation.")
        print(f"  Génération de {args.n} traces simulées...")
        traces, pts, cts = generate_simulated_traces(args.n)
    else:
        try:
            scope  = connect_scope(args.scope)
            configure_scope(scope, gain=args.gain, samples=args.samples)
            target = connect_target(scope, args.target_type)
            print(f"  [✓] Scope connecté : {scope}")
            print(f"  [✓] Cible connectée : {target}\n")
            traces, pts, cts = capture_n_traces(scope, target, n_traces=args.n)
            scope.dis()
            target.dis()
        except Exception as e:
            print(f"  [✗] Erreur acquisition : {e}", file=sys.stderr)
            print("  Basculement vers le mode simulation...", file=sys.stderr)
            traces, pts, cts = generate_simulated_traces(args.n)

    meta = {
        "scope":       args.scope,
        "target_type": args.target_type,
        "gain_db":     args.gain,
        "n_samples":   args.samples,
        "simulated":   not CW_AVAILABLE or args.simulate,
    }

    save_traces(args.output, traces, pts, cts, metadata=meta)
    print(f"\n  [✓] {len(traces)} traces acquises et sauvegardées.")
    return 0


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Nevelio — ChipWhisperer acquisition de traces power"
    )
    parser.add_argument("--n",           type=int,   default=500,
                        help="Nombre de traces à acquérir (défaut: 500)")
    parser.add_argument("--scope",       default="auto",
                        choices=["auto", "CW-Nano", "CW-Lite", "CW-Pro", "CW-Husky"],
                        help="Type de scope ChipWhisperer")
    parser.add_argument("--target-type", default="simpleserial",
                        choices=["simpleserial", "simpleserial2"],
                        help="Protocole cible")
    parser.add_argument("--gain",    type=int,   default=DEFAULT_GAIN,
                        help=f"Gain AFE en dB (défaut: {DEFAULT_GAIN})")
    parser.add_argument("--samples", type=int,   default=DEFAULT_SAMPLES,
                        help=f"Échantillons par trace (défaut: {DEFAULT_SAMPLES})")
    parser.add_argument("--output",  default="traces.npz",
                        help="Fichier de sortie .npz (défaut: traces.npz)")
    parser.add_argument("--simulate", action="store_true",
                        help="Mode simulation — ne nécessite pas de hardware")
    args = parser.parse_args()

    sys.exit(run_acquisition(args))


if __name__ == "__main__":
    main()
