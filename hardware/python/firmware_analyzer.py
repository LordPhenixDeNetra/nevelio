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

try:
    from i18n import t
except ImportError:
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    try:
        from i18n import t
    except ImportError:
        def t(key, **kwargs): return key

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
            t("fw.binwalk.missing.title"),
            t("fw.binwalk.missing.desc"),
            "INFORMATIVE", evidence="binwalk absent du PATH",
            remediation=t("fw.binwalk.missing.rem")
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
            _fs_set = set(detected_fs)
            findings.append(finding(
                t("fw.binwalk.filesystems.title", fs=', '.join(_fs_set)),
                t("fw.binwalk.filesystems.desc", n=len(_fs_set)),
                "INFORMATIVE",
                evidence=f"binwalk scan : {', '.join(_fs_set)}",
                remediation=t("fw.binwalk.filesystems.rem")
            ))

    # Extraction dans extract_dir
    rc, out, err = run(
        ['binwalk', '--extract', '--matryoshka',
         '--directory', extract_dir, firmware_path],
        timeout=300
    )
    if rc != 0 and rc not in (-1, -2):
        findings.append(finding(
            t("fw.binwalk.partial.title"),
            t("fw.binwalk.partial.desc", rc=rc),
            "INFORMATIVE", evidence=err[:500] if err else '',
            remediation=t("fw.binwalk.partial.rem")
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
            t("fw.strings.desc", n=len(samples)),
            severity, cwe, cvss,
            evidence='\n'.join(evidence_lines),
            remediation=t("fw.strings.rem")
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
            t("fw.magic.title", n=len(detected)),
            t("fw.magic.desc"),
            "INFORMATIVE",
            evidence=detail,
            remediation=t("fw.magic.rem")
        ))

    return [n for n, _ in detected]


# ── Analyse ELF via r2pipe / radare2 ─────────────────────────────────────────

def analyze_elf_binaries(extract_dir: str, findings: list):
    """Cherche les ELF extraits et vérifie NX, PIE, Canary, RELRO."""
    if not tool_available('r2') and not tool_available('radare2'):
        findings.append(finding(
            t("fw.r2.missing.title"),
            t("fw.r2.missing.desc"),
            "INFORMATIVE",
            remediation=t("fw.r2.missing.rem")
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
            t("fw.elf.unprotected.title", n=len(unprotected)),
            t("fw.elf.unprotected.desc", n=len(unprotected)),
            severity, 1209, 6.8,
            evidence=detail,
            remediation=t("fw.elf.unprotected.rem")
        ))
    else:
        findings.append(finding(
            t("fw.elf.ok.title", n=len(elf_files)),
            t("fw.elf.ok.desc"),
            "INFORMATIVE",
            evidence=f"{len(elf_files)} ELF analysés via radare2"
        ))


# ── Analyse symbolique angr ───────────────────────────────────────────────────

ANGR_DANGEROUS_FUNCS = [
    ('strcpy',   'Buffer overflow potentiel via strcpy()',  'HIGH',    121, 7.8),
    ('gets',     'Buffer overflow via gets() — CWE-120',   'CRITICAL', 120, 9.8),
    ('sprintf',  'Format string ou overflow via sprintf()', 'HIGH',    134, 7.5),
    ('strcat',   'Buffer overflow potentiel via strcat()',  'HIGH',    121, 7.2),
    ('scanf',    'Entrée non bornée via scanf()',           'HIGH',    120, 7.2),
    ('system',   'Exécution commande arbitraire via system()', 'HIGH', 78, 8.1),
    ('popen',    'Exécution commande via popen()',          'HIGH',    78, 7.5),
    ('printf',   'Format string potentiel via printf()',    'MEDIUM',  134, 5.5),
    ('memcpy',   'Possible overflow mémoire non borné',    'LOW',     120, 4.3),
]

def analyze_with_angr(extract_dir: str, findings: list, max_binaries: int = 5):
    """Analyse symbolique via angr : détection buffer overflows + fonctions dangereuses."""
    try:
        import angr
    except ImportError:
        findings.append(finding(
            t("fw.angr.missing.title"),
            t("fw.angr.missing.desc"),
            "INFORMATIVE",
            remediation="pip install angr"
        ))
        return

    # Collecter les ELF
    elf_files = []
    for root, _, files in os.walk(extract_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'rb') as f:
                    if f.read(4) == b'\x7fELF':
                        elf_files.append(fpath)
            except (IOError, PermissionError):
                pass
        if len(elf_files) >= max_binaries * 3:
            break

    if not elf_files:
        return

    analyzed    = 0
    all_vulns   = []

    for elf_path in elf_files[:max_binaries]:
        try:
            proj = angr.Project(
                elf_path,
                auto_load_libs=False,
                load_options={'except_missing_libs': True}
            )
        except Exception:
            continue

        # 1. Détection par CFG des fonctions dangereuses importées
        try:
            cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=False)
        except Exception:
            continue

        # Chercher les symboles PLT importés
        dangereux_trouves = []
        for sym_name, label, sev, cwe, cvss in ANGR_DANGEROUS_FUNCS:
            sym = proj.loader.find_symbol(sym_name)
            if sym is not None:
                dangereux_trouves.append((sym_name, label, sev, cwe, cvss))

        if dangereux_trouves:
            # Choisir la sévérité la plus haute
            sev_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFORMATIVE': 0}
            top = max(dangereux_trouves, key=lambda x: sev_order.get(x[2], 0))
            names = ', '.join(f[0] for f in dangereux_trouves)
            all_vulns.append((os.path.basename(elf_path), dangereux_trouves, top))

        # 2. Vérification protection PIE (pour binaires critiques)
        is_pie = proj.loader.main_object.pic
        nx_stack = getattr(proj.loader.main_object, 'execstack', None)
        if nx_stack:  # pile exécutable
            findings.append(finding(
                t("fw.angr.execstack.title", bin=os.path.basename(elf_path)),
                t("fw.angr.execstack.desc"),
                "CRITICAL", 119, 9.3,
                evidence=f"{elf_path}: execstack=RWX",
                remediation=t("fw.angr.execstack.rem")
            ))

        analyzed += 1

    # Rapport consolidé des fonctions dangereuses
    if all_vulns:
        for bin_name, vulns, top in all_vulns:
            names = ', '.join(v[0] for v in vulns)
            findings.append(finding(
                t("fw.angr.dangerous.title", bin=bin_name, funcs=names),
                t("fw.angr.dangerous.desc", n=len(vulns), bin=bin_name),
                top[2], top[3], top[4],
                evidence=', '.join(v[0] for v in vulns),
                remediation=t("fw.angr.dangerous.rem")
            ))

    if analyzed > 0:
        findings.append(finding(
            t("fw.angr.done.title", n=analyzed),
            t("fw.angr.done.desc", analyzed=analyzed, vulns=len(all_vulns)),
            "INFORMATIVE",
            evidence=f"{analyzed} binaires analysés via angr CFGFast"
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
                    t("fw.entropy.low.title"),
                    t("fw.entropy.low.desc", entropy=avg_entropy),
                    "HIGH", 311, 7.5,
                    evidence=f"Entropie moyenne : {avg_entropy:.2f}",
                    remediation=t("fw.entropy.low.rem")
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
    parser.add_argument('--firmware',     required=True,  help="Chemin vers l'image firmware")
    parser.add_argument('--output',       default='-',    help="Fichier JSON de sortie (défaut : stdout)")
    parser.add_argument('--no-r2',        action='store_true', help="Désactiver l'analyse radare2")
    parser.add_argument('--no-extract',   action='store_true', help="Ne pas extraire avec binwalk")
    parser.add_argument('--extract-dir',  default=None,   help="Répertoire d'extraction (défaut : tempdir)")
    parser.add_argument('--no-angr',      action='store_true', help="Désactiver l'analyse symbolique angr")
    args = parser.parse_args()

    if not os.path.exists(args.firmware):
        print(json.dumps({'error': t("fw.error.not_found", path=args.firmware)}))
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

        # 6. Analyse symbolique angr
        if not args.no_angr and not args.no_extract:
            analyze_with_angr(extract_dir, findings)

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
            print(t("fw.report_written", path=args.output, n=len(findings)),
                  file=sys.stderr)

    finally:
        if use_tempdir:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
