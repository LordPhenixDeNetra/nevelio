#!/usr/bin/env python3
"""
Nevelio Hardware Security — Volatility 3 Wrapper
Analyse forensique d'un dump mémoire physique (avml, LiME ou raw).

Usage :
    python3 volatility_runner.py --dump /tmp/memory.lime
    python3 volatility_runner.py --dump /tmp/memory.lime --os linux
    python3 volatility_runner.py --dump /tmp/memory.lime --os windows --output findings.json
    python3 volatility_runner.py --dump /tmp/memory.lime --plugins pslist,netscan,malfind

Sortie : JSON compatible avec HardwareFinding (Rust hw-memory)
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

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
MODULE  = "hw-memory-forensics"


# ── Commandes Volatility ──────────────────────────────────────────────────────

LINUX_PLUGINS = [
    "linux.pslist",       # liste des processus
    "linux.psscan",       # scan des structures task_struct (détecte DKOM)
    "linux.netstat",      # connexions réseau
    "linux.bash",         # historique bash des processus
    "linux.malfind",      # régions mémoire suspectes (exécutables + écrites)
    "linux.check_syscall",# vérifie l'intégrité des tables de syscalls
    "linux.lsmod",        # modules noyau chargés
    "linux.check_modules",# détecte les modules cachés (DKOM)
]

WINDOWS_PLUGINS = [
    "windows.pslist",
    "windows.psscan",
    "windows.netscan",
    "windows.malfind",
    "windows.hashdump",   # extraire les hashes NTLM
    "windows.dlllist",
    "windows.cmdline",
    "windows.svcscan",    # services Windows
    "windows.driverirp",  # hooks IRP des drivers (rootkit)
]


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def run_vol(vol_bin: str, dump_path: str, plugin: str, timeout: int = 120) -> tuple[int, str, str]:
    """Lance une commande Volatility et retourne (rc, stdout, stderr)."""
    cmd = [vol_bin, '-f', dump_path, plugin]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, '', f'{vol_bin} introuvable'
    except subprocess.TimeoutExpired:
        return -2, '', f'Timeout ({timeout}s) pour {plugin}'


def find_volatility() -> str | None:
    """Cherche vol3, volatility, volatility3 dans le PATH."""
    for name in ['vol', 'vol3', 'volatility', 'volatility3']:
        rc, out, _ = run_vol(name, '/dev/null', '--help', timeout=5)
        if rc not in (-1, -2) or 'vol' in out.lower():
            return name
    return None


# ── Détection OS ──────────────────────────────────────────────────────────────

def detect_os_from_dump(dump_path: str) -> str:
    """Heuristique : détecte Windows vs Linux depuis les premiers bytes du dump."""
    try:
        with open(dump_path, 'rb') as f:
            header = f.read(512)

        # LiME format : magic 0x4C694D45
        if header[:4] == b'\x45\x4D\x69\x4C':
            return 'linux'  # LiME est toujours Linux

        # Chercher des signatures Windows (KDBG, MZ headers de ntoskrnl)
        # Vérification grossière : chercher des strings Windows dans les premiers 64KB
        sample = header
        with open(dump_path, 'rb') as f:
            sample = f.read(65536)

        if b'NTOSKRNL' in sample or b'ntoskrnl' in sample or b'Windows NT' in sample:
            return 'windows'
        if b'Linux' in sample or b'linux' in sample.lower()[:len(sample)]:
            return 'linux'
    except (IOError, Exception):
        pass

    return 'linux'  # défaut Linux si inconnu


# ── Analyse pslist + psscan (détection DKOM) ─────────────────────────────────

def analyze_pslist_psscan(vol_bin: str, dump_path: str, os_name: str, findings: list):
    """
    Compare pslist (liste walked) et psscan (scan de structures en mémoire).
    Les processus dans psscan mais pas dans pslist sont probablement cachés (DKOM).
    """
    pslist_plugin = f'{os_name}.pslist'
    psscan_plugin = f'{os_name}.psscan'

    # Récupérer les PIDs de pslist
    _, pslist_out, _ = run_vol(vol_bin, dump_path, pslist_plugin, timeout=60)
    pslist_pids = set()
    pslist_names = {}

    for line in pslist_out.splitlines()[2:]:  # skip headers
        parts = line.split()
        if len(parts) >= 2:
            try:
                pid = int(parts[-1] if parts[-1].isdigit() else parts[1])
                name = parts[0]
                pslist_pids.add(pid)
                pslist_names[pid] = name
            except (ValueError, IndexError):
                pass

    # Récupérer les PIDs de psscan
    _, psscan_out, _ = run_vol(vol_bin, dump_path, psscan_plugin, timeout=90)
    psscan_pids = set()

    for line in psscan_out.splitlines()[2:]:
        parts = line.split()
        if len(parts) >= 2:
            try:
                pid = int(parts[1]) if parts[1].isdigit() else int(parts[-2])
                psscan_pids.add(pid)
            except (ValueError, IndexError):
                pass

    # Processus dans psscan mais pas dans pslist → potentiellement cachés (DKOM)
    hidden_pids = psscan_pids - pslist_pids
    # PIDs légitimement absents (processus terminés pendant le dump)
    hidden_pids = {p for p in hidden_pids if p > 4}  # exclure PID 0 et 4 (System)

    if hidden_pids:
        _pids_str = ', '.join(str(p) for p in sorted(hidden_pids)[:10])
        findings.append(finding(
            t("vol.dkom.title", n=len(hidden_pids)),
            t("vol.dkom.desc", n=len(hidden_pids), pids=_pids_str),
            "CRITICAL",
            693, 8.1,
            f"PIDs dans psscan∖pslist : {sorted(hidden_pids)[:10]}",
            t("vol.dkom.rem"),
        ))
    elif pslist_pids:
        findings.append(finding(
            t("vol.dkom.ok.title", n=len(pslist_pids)),
            t("vol.dkom.ok.desc"),
            "INFORMATIVE",
            evidence=f"{len(pslist_pids)} processus dans pslist",
        ))


# ── Analyse malfind (injection de code) ──────────────────────────────────────

def analyze_malfind(vol_bin: str, dump_path: str, os_name: str, findings: list):
    """
    malfind détecte les régions mémoire avec permissions RWX (Write + Execute)
    et des patterns d'injection (MZ header, shellcode patterns).
    """
    plugin = f'{os_name}.malfind'
    _, out, _ = run_vol(vol_bin, dump_path, plugin, timeout=120)

    if not out or 'Error' in out[:200]:
        return

    # Compter les entrées suspectes
    injections = []
    current = {}

    for line in out.splitlines():
        if line.startswith('Process:') or line.startswith('PID:'):
            if current:
                injections.append(current)
            current = {'line': line.strip()}
        elif '4d 5a' in line.lower() or 'MZ' in line:  # PE header
            current['pe_header'] = True
        elif 'PAGE_EXECUTE_READWRITE' in line.upper():
            current['rwx'] = True

    if current:
        injections.append(current)

    # Filtrer : garder ceux avec PE header ou RWX + signature shellcode
    suspicious = [i for i in injections if i.get('pe_header') or i.get('rwx')]

    if suspicious:
        findings.append(finding(
            t("vol.malfind.title", n=len(suspicious)),
            t("vol.malfind.desc", n=len(suspicious)),
            "HIGH",
            94, 7.8,
            '\n'.join(i.get('line', '') for i in suspicious[:3]),
            t("vol.malfind.rem"),
        ))
    else:
        findings.append(finding(
            t("vol.malfind.ok.title"),
            t("vol.malfind.ok.desc"),
            "INFORMATIVE",
        ))


# ── Analyse hashdump (Windows) ────────────────────────────────────────────────

def analyze_hashdump(vol_bin: str, dump_path: str, findings: list):
    """Extrait les hashes NTLM depuis la mémoire Windows (SAM hive)."""
    _, out, err = run_vol(vol_bin, dump_path, 'windows.hashdump', timeout=60)

    if not out or 'Error' in out[:200]:
        if 'hashdump' in err.lower() or 'SAM' in err:
            return
        return

    hashes = []
    for line in out.splitlines():
        # Format : Administrator:500:aad3b435...:8846f7ea...:::
        if ':' in line and len(line) > 20:
            parts = line.split(':')
            if len(parts) >= 4:
                username = parts[0]
                ntlm     = parts[3] if len(parts) > 3 else ''
                if len(ntlm) == 32 and all(c in '0123456789abcdefABCDEF' for c in ntlm):
                    hashes.append((username, ntlm))

    if hashes:
        findings.append(finding(
            t("vol.hashdump.title", n=len(hashes)),
            t("vol.hashdump.desc", n=len(hashes)),
            "HIGH",
            312, 7.5,
            f"Comptes : {', '.join(u for u, _ in hashes[:5])} ...",
            t("vol.hashdump.rem"),
        ))


# ── Analyse des syscall tables (Linux) ───────────────────────────────────────

def analyze_syscall_hooks(vol_bin: str, dump_path: str, findings: list):
    """
    Vérifie l'intégrité des tables de syscalls Linux.
    Des modifications indiquent la présence d'un rootkit kernel.
    """
    _, out, _ = run_vol(vol_bin, dump_path, 'linux.check_syscall', timeout=60)

    if not out:
        return

    hooked = []
    for line in out.splitlines():
        if 'HOOKED' in line.upper() or 'hooked' in line.lower():
            hooked.append(line.strip())

    if hooked:
        findings.append(finding(
            t("vol.syscall.title", n=len(hooked)),
            t("vol.syscall.desc", n=len(hooked)),
            "CRITICAL",
            693, 9.1,
            '\n'.join(hooked[:5]),
            t("vol.syscall.rem"),
        ))


# ── Analyse des connexions réseau ─────────────────────────────────────────────

def analyze_network(vol_bin: str, dump_path: str, os_name: str, findings: list):
    """Détecte les connexions réseau suspectes (C2, ports non standards)."""
    plugin = f'{os_name}.netstat' if os_name == 'linux' else 'windows.netscan'
    _, out, _ = run_vol(vol_bin, dump_path, plugin, timeout=60)

    if not out:
        return

    suspicious_ports = {4444, 8888, 31337, 1337, 12345, 54321, 6660, 6667, 6668, 6669}
    suspicious_connections = []

    for line in out.splitlines()[2:]:
        parts = line.split()
        for part in parts:
            # Chercher les ports dans les adresses
            if ':' in part:
                try:
                    port = int(part.split(':')[-1])
                    if port in suspicious_ports:
                        suspicious_connections.append(line.strip())
                        break
                except ValueError:
                    pass

    if suspicious_connections:
        findings.append(finding(
            t("vol.network.title", n=len(suspicious_connections)),
            t("vol.network.desc"),
            "HIGH",
            200, 7.5,
            '\n'.join(suspicious_connections[:3]),
            t("vol.network.rem"),
        ))


# ── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f'Nevelio Volatility 3 Runner v{VERSION}'
    )
    parser.add_argument('--dump',    required=True, help='Chemin vers le dump mémoire')
    parser.add_argument('--os',      default='auto', choices=['linux', 'windows', 'auto'],
                        help='OS du dump (défaut: auto-détection)')
    parser.add_argument('--output',  default='-',   help='Fichier JSON de sortie (- = stdout)')
    parser.add_argument('--plugins', default='all',
                        help='Plugins à exécuter (défaut: all)')
    args = parser.parse_args()

    if not os.path.exists(args.dump):
        print(json.dumps({'error': t("vol.error.not_found", path=args.dump)}))
        sys.exit(1)

    findings = []
    dump_size = os.path.getsize(args.dump)

    # Détecter l'OS
    os_name = args.os
    if os_name == 'auto':
        os_name = detect_os_from_dump(args.dump)

    # Chercher Volatility
    vol_bin = find_volatility()
    if not vol_bin:
        findings.append(finding(
            t("vol.missing.title"),
            t("vol.missing.desc"),
            "INFORMATIVE",
            evidence="vol3 absent du PATH",
            remediation=t("vol.missing.rem"),
        ))
    else:
        # Lancer les analyses
        analyze_pslist_psscan(vol_bin, args.dump, os_name, findings)
        analyze_malfind(vol_bin, args.dump, os_name, findings)
        analyze_network(vol_bin, args.dump, os_name, findings)

        if os_name == 'linux':
            analyze_syscall_hooks(vol_bin, args.dump, findings)
        elif os_name == 'windows':
            analyze_hashdump(vol_bin, args.dump, findings)

    result = {
        'tool':      'nevelio-volatility-runner',
        'version':   VERSION,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'dump': {
            'path':    args.dump,
            'size':    dump_size,
            'os':      os_name,
            'sha256':  _sha256(args.dump),
        },
        'volatility': vol_bin or 'absent',
        'findings':  findings,
    }

    output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output == '-':
        print(output)
    else:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(t("vol.report_written", path=args.output, n=len(findings)),
              file=sys.stderr)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
    except IOError:
        return ''
    return h.hexdigest()


if __name__ == '__main__':
    main()
