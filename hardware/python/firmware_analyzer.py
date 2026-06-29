#!/usr/bin/env python3
"""
Nevelio Hardware Security — Firmware Analyzer
Pipeline : binwalk (extraction) → strings (secrets) → radare2/r2pipe (ELF)
Sortie   : JSON findings compatibles avec HardwareFinding (Rust)

Usage :
    python3 firmware_analyzer.py --firmware firmware.bin
    python3 firmware_analyzer.py --firmware firmware.bin --output findings.json
    python3 firmware_analyzer.py --firmware firmware.bin --no-r2  # sans radare2
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
MODULE  = "hw-firmware-ext"

# ── Patterns de détection de secrets ─────────────────────────────────────────

SENSITIVE_PATTERNS = [
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY', re.I),
     "Clé privée embarquée dans le firmware", "CRITICAL", 321, 9.1),
    (re.compile(r'AKIA[0-9A-Z]{16}'),
     "Clé AWS IAM Access Key détectée", "CRITICAL", 798, 9.1),
    (re.compile(r'(?:password|passwd|secret|pwd)\s*[=:]\s*["\']?(\S{4,})["\']?', re.I),
     "Credential en clair détecté", "HIGH", 798, 7.5),
    (re.compile(r'(?:admin|root):[^:]{0,60}:\d+:\d+:', re.I),
     "Entrée /etc/passwd (compte root/admin)", "HIGH", 798, 7.5),
    (re.compile(r'backdoor|BACKDOOR|debug_shell|factory_mode', re.I),
     "Référence à une backdoor ou mode usine", "CRITICAL", 912, 9.8),
    (re.compile(r'telnetd|dropbear|sshd\b', re.I),
     "Service réseau distant détecté dans le firmware", "MEDIUM", 912, 5.3),
    (re.compile(r'(?:authtoken|api[_\-]?key|bearer\s+)[=: ]["\']?\S{8,}', re.I),
     "Token ou clé API en clair", "HIGH", 312, 7.5),
    (re.compile(r'https?://(?!example\.com|localhost)\S{8,}', re.I),
     "URL distante en dur (C2 potentiel ou endpoint de confiance)", "LOW", 200, 3.1),
]

# ── Signatures de systèmes de fichiers (magic bytes) ─────────────────────────

FS_SIGNATURES = [
    (b'sqsh',           0,  "SquashFS (little-endian)"),
    (b'hsqs',           0,  "SquashFS (big-endian)"),
    (b'\x73\x71\x73\x68', 0, "SquashFS"),
    (b'UBI#',           0,  "UBI (NAND Flash)"),
    (b'\x19\x85',       0,  "JFFS2"),
    (b'\x85\x19',       0,  "JFFS2 (big-endian)"),
    (b'\x28\xcd\x3d\x45', 0, "CramFS"),
    (b'070701',         0,  "CPIO newc (initramfs)"),
    (b'\x1f\x8b',       0,  "gzip"),
    (b'BZh',            0,  "bzip2"),
    (b'\xfd7zXZ',       0,  "xz"),
    (b'\x02\x21\x4c\x18', 0, "LZ4"),
    (b'LZMA',           0,  "LZMA"),
    (b'\x00\x00\x00\x01', 0, "U-Boot Image (potentiel)"),
    (b'MZ',             0,  "PE/COFF (Windows ou UEFI)"),
    (b'\x7fELF',        0,  "ELF binaire"),
]

# ── Vendor IDs de sondes JTAG ─────────────────────────────────────────────────

JTAG_VENDORS = {
    '0403': 'FTDI (FT2232H/FT232H)',
    '1366': 'Segger J-Link',
    '0483': 'STMicroelectronics ST-Link',
    '04b4': 'Cypress FX2LP',
    '0d28': 'DAPLink / CMSIS-DAP',
    '1fc9': 'NXP LPC-Link2',
}

# ── Utilitaires ───────────────────────────────────────────────────────────────

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list, timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, '', f"Commande introuvable : {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, '', f"Timeout ({timeout}s) : {' '.join(cmd)}"
    except Exception as e:
        return -3, '', str(e)


def tool_available(name: str) -> bool:
    rc, _, _ = run(['which', name], timeout=5)
    return rc == 0


def finding(title, description, severity, cwe=None, cvss=None, evidence='', remediation=''):
    return {
        'title':       title,
        'description': description,
        'severity':    severity,
        'module':      MODULE,
        'cwe':         cwe,
        'cvss':        cvss,
        'evidence':    evidence,
        'remediation': remediation,
    }


# ── Analyse binwalk ───────────────────────────────────────────────────────────

def run_binwalk(firmware_path: str, extract_dir: str, findings: list) -> list:
    """Extraction et signatures binwalk."""
    if not tool_available('binwalk'):
        findings.append(finding(
            "binwalk non installé — analyse firmware incomplète",
            "L'outil binwalk est requis pour l'extraction et la détection de signatures. "
            "Installer : pip install binwalk  ou  apt-get install binwalk",
            "INFORMATIVE", evidence="binwalk absent du PATH",
            remediation="pip install binwalk"
        ))
        return []

    # Scan des signatures (sans extraction)
    rc, out, err = run(['binwalk', '--no-extract', firmware_path], timeout=120)
    detected_fs = []

    if rc == 0 and out:
        for line in out.splitlines():
            for fs_name in ['SquashFS', 'JFFS2', 'CramFS', 'UBI', 'CPIO', 'Zlib', 'LZMA', 'xz']:
                if fs_name.lower() in line.lower():
                    detected_fs.append(fs_name)
                    break
        if detected_fs:
            findings.append(finding(
                f"Système(s) de fichiers détecté(s) : {', '.join(set(detected_fs))}",
                f"binwalk a détecté {len(set(detected_fs))} type(s) de conteneur(s) dans "
                f"l'image firmware. L'extraction peut révéler des binaires analysables, "
                f"des scripts de démarrage et des fichiers de configuration.",
                "INFORMATIVE",
                evidence=f"binwalk scan : {', '.join(set(detected_fs))}",
                remediation="Extraire et analyser chaque système de fichiers individuellement."
            ))

    # Extraction dans extract_dir
    rc, out, err = run(
        ['binwalk', '--extract', '--matryoshka',
         '--directory', extract_dir, firmware_path],
        timeout=300
    )
    if rc != 0 and rc not in (-1, -2):
        findings.append(finding(
            "Extraction binwalk partielle ou échouée",
            f"Code de retour : {rc}. L'extraction a peut-être partiellement réussi.",
            "INFORMATIVE", evidence=err[:500] if err else '',
            remediation="Vérifier les droits d'écriture sur le répertoire d'extraction."
        ))

    return list(set(detected_fs))


# ── Détection de secrets via strings ─────────────────────────────────────────

def run_strings_analysis(firmware_path: str, findings: list):
    """Analyse des chaînes ASCII/Unicode pour secrets et backdoors."""
    rc, out, err = run(['strings', '-n', '8', firmware_path], timeout=60)
    if rc != 0:
        # Fallback Python si `strings` absent
        try:
            with open(firmware_path, 'rb') as f:
                data = f.read()
            # Extraire les séquences ASCII imprimables de longueur ≥ 8
            out = '\n'.join(re.findall(rb'[ -~]{8,}', data).decode('ascii', errors='replace')
                            for _ in [None])  # simplification
            out = '\n'.join(
                m.decode('ascii', errors='replace')
                for m in re.findall(rb'[ -~]{8,}', data)
            )
        except Exception:
            return

    hits: dict[str, list[str]] = {}

    for pattern, title, severity, cwe, cvss in SENSITIVE_PATTERNS:
        matches = pattern.findall(out)
        if matches:
            # Dédupliquer et tronquer
            samples = list(dict.fromkeys(str(m) for m in matches))[:3]
            key = f"{title}|{severity}"
            hits[key] = (title, severity, cwe, cvss, samples)

    for key, (title, severity, cwe, cvss, samples) in hits.items():
        evidence_lines = [f"  • {s[:120]}" for s in samples]
        findings.append(finding(
            title,
            f"Détecté par analyse `strings` sur l'image firmware brute. "
            f"{len(samples)} occurrence(s) (tronquées à 3 pour l'affichage).",
            severity, cwe, cvss,
            evidence='\n'.join(evidence_lines),
            remediation="Ne pas embarquer de secrets en clair dans le firmware. "
                        "Utiliser un stockage sécurisé (eFuse, secure enclave, TPM). "
                        "Implémenter un mécanisme de provisioning post-production."
        ))


# ── Détection magic bytes dans le fichier brut ───────────────────────────────

def detect_filesystems_raw(firmware_path: str, findings: list) -> list:
    """Scan les magic bytes dans l'image brute (complète binwalk)."""
    detected = []
    try:
        with open(firmware_path, 'rb') as f:
            data = f.read(min(os.path.getsize(firmware_path), 16 * 1024 * 1024))
    except (IOError, MemoryError):
        return detected

    for magic, offset, fs_name in FS_SIGNATURES:
        idx = data.find(magic)
        if idx != -1:
            detected.append((fs_name, idx))

    if detected:
        detail = ', '.join(f"{n} @ 0x{o:x}" for n, o in detected[:6])
        findings.append(finding(
            f"Magic bytes détectés : {len(detected)} conteneur(s)",
            "Des signatures de systèmes de fichiers ou de formats compressés ont été "
            "trouvées dans l'image brute. Utiliser binwalk pour l'extraction complète.",
            "INFORMATIVE",
            evidence=detail,
            remediation="binwalk --extract --matryoshka firmware.bin"
        ))

    return [n for n, _ in detected]


# ── Analyse ELF via r2pipe / radare2 ─────────────────────────────────────────

def analyze_elf_binaries(extract_dir: str, findings: list):
    """Cherche les ELF extraits et vérifie NX, PIE, Canary, RELRO."""
    if not tool_available('r2') and not tool_available('radare2'):
        findings.append(finding(
            "radare2 non installé — analyse ELF ignorée",
            "L'analyse des protections binaires (NX, PIE, Canary, RELRO) "
            "nécessite radare2. Installer : apt-get install radare2",
            "INFORMATIVE",
            remediation="apt-get install radare2  # ou pip install r2pipe"
        ))
        return

    r2_bin = 'r2' if tool_available('r2') else 'radare2'

    elf_files = []
    for root, _, files in os.walk(extract_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'rb') as f:
                    magic = f.read(4)
                if magic == b'\x7fELF':
                    elf_files.append(fpath)
            except (IOError, PermissionError):
                pass
        if len(elf_files) >= 50:  # limiter l'analyse à 50 binaires
            break

    if not elf_files:
        return

    unprotected = []

    for elf_path in elf_files[:20]:  # analyser max 20 ELF
        rc, out, _ = run(
            [r2_bin, '-A', '-q', '-c', 'iI~nx,canary,pic,relro', elf_path],
            timeout=30
        )
        if rc != 0 or not out:
            continue

        nx     = 'true'  in out.lower() and 'nx' in out.lower()
        canary = 'true'  in out.lower() and 'canary' in out.lower()
        pic    = 'true'  in out.lower() and 'pic' in out.lower()
        relro  = 'full'  in out.lower() and 'relro' in out.lower()

        missing = []
        if not nx:     missing.append('NX')
        if not canary: missing.append('Canary')
        if not pic:    missing.append('PIE')
        if not relro:  missing.append('RELRO')

        if missing:
            unprotected.append((os.path.basename(elf_path), missing))

    if unprotected:
        detail = '; '.join(f"{n}: manque {', '.join(m)}" for n, m in unprotected[:5])
        severity = "HIGH" if len(unprotected) > 3 else "MEDIUM"
        findings.append(finding(
            f"Binaires ELF sans protections : {len(unprotected)} trouvé(s) — CWE-1209",
            f"{len(unprotected)} binaire(s) extrait(s) du firmware manquent de protections "
            f"mémoire critiques. Un attaquant ayant accès au shell du dispositif peut "
            f"plus facilement exploiter des vulnérabilités buffer overflow.",
            severity, 1209, 6.8,
            evidence=detail,
            remediation="Recompiler avec : -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now\n"
                        "Vérifier les options du toolchain (Buildroot, Yocto) pour activer "
                        "ces protections par défaut."
        ))
    else:
        findings.append(finding(
            f"Binaires ELF correctement protégés ({len(elf_files)} analysés)",
            "Tous les binaires ELF analysés disposent des protections mémoire standard.",
            "INFORMATIVE",
            evidence=f"{len(elf_files)} ELF analysés via radare2"
        ))


# ── Informations générales sur le firmware ────────────────────────────────────

def firmware_info(firmware_path: str, findings: list) -> dict:
    size  = os.path.getsize(firmware_path)
    sha   = sha256_file(firmware_path)
    ftype = ''

    rc, out, _ = run(['file', firmware_path], timeout=10)
    if rc == 0:
        ftype = out.strip()

    # Avertir si le firmware n'est pas chiffré (entropie élevée ≠ chiffré mais faible = non chiffré)
    rc, out, _ = run(['binwalk', '--entropy', '--no-extract', firmware_path], timeout=30)
    low_entropy_detected = False
    if rc == 0 and out:
        # L'entropie < 0.5 sur une grande section indique du texte/données non compressées
        values = re.findall(r'[\d.]+', out)
        if values:
            avg_entropy = sum(float(v) for v in values if float(v) <= 1.0) / max(len(values), 1)
            if avg_entropy < 0.5:
                low_entropy_detected = True
                findings.append(finding(
                    "Entropie faible détectée — firmware potentiellement non chiffré",
                    f"L'entropie moyenne du firmware est {avg_entropy:.2f} (< 0.5). "
                    "Un firmware non chiffré expose son contenu à l'analyse statique complète, "
                    "facilitant l'extraction de secrets, de clés et de code propriétaire.",
                    "HIGH", 311, 7.5,
                    evidence=f"Entropie moyenne : {avg_entropy:.2f}",
                    remediation="Chiffrer le firmware avec AES-256 (boot ROM decrypt). "
                                "Activer Secure Boot pour vérifier l'authenticité."
                ))

    return {
        'path':   firmware_path,
        'size':   size,
        'sha256': sha,
        'type':   ftype,
        'low_entropy': low_entropy_detected,
    }


# ── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Nevelio Firmware Analyzer v' + VERSION
    )
    parser.add_argument('--firmware',     required=True,  help='Chemin vers l'image firmware')
    parser.add_argument('--output',       default='-',    help='Fichier JSON de sortie (défaut : stdout)')
    parser.add_argument('--no-r2',        action='store_true', help='Désactiver l'analyse radare2')
    parser.add_argument('--no-extract',   action='store_true', help='Ne pas extraire avec binwalk')
    parser.add_argument('--extract-dir',  default=None,   help='Répertoire d'extraction (défaut : tempdir)')
    args = parser.parse_args()

    if not os.path.exists(args.firmware):
        print(json.dumps({'error': f"Firmware introuvable : {args.firmware}"}))
        sys.exit(1)

    findings  = []
    use_tempdir = args.extract_dir is None

    if use_tempdir:
        tmp = tempfile.mkdtemp(prefix='nevelio_fw_')
        extract_dir = tmp
    else:
        extract_dir = args.extract_dir
        os.makedirs(extract_dir, exist_ok=True)

    try:
        # 1. Informations générales
        info = firmware_info(args.firmware, findings)

        # 2. Détection magic bytes
        raw_fs = detect_filesystems_raw(args.firmware, findings)

        # 3. Analyse strings (secrets)
        run_strings_analysis(args.firmware, findings)

        # 4. Extraction binwalk
        if not args.no_extract:
            bw_fs = run_binwalk(args.firmware, extract_dir, findings)
        else:
            bw_fs = []

        # 5. Analyse ELF via r2pipe
        if not args.no_r2 and not args.no_extract:
            analyze_elf_binaries(extract_dir, findings)

        # Résultat final
        result = {
            'tool':      'nevelio-firmware-analyzer',
            'version':   VERSION,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'firmware': {
                'path':   info['path'],
                'size':   info['size'],
                'sha256': info['sha256'],
                'type':   info['type'],
            },
            'filesystems': list(set(raw_fs + bw_fs)),
            'findings':   findings,
        }

        output = json.dumps(result, indent=2, ensure_ascii=False)

        if args.output == '-':
            print(output)
        else:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"[✓] Rapport écrit dans {args.output} ({len(findings)} finding(s))",
                  file=sys.stderr)

    finally:
        if use_tempdir:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
