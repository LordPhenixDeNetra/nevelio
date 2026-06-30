#!/usr/bin/env python3
"""
Nevelio Hardware Security — Python i18n module.
Simple dictionary-based translation with NEVELIO_LANG / $LANG auto-detection.
Usage:
    from i18n import t
    print(t("key"))
    print(t("key.with.var", name="value"))
"""

import os
import re

# ── Language detection ────────────────────────────────────────────────────────

def _detect_lang() -> str:
    for env in ("NEVELIO_LANG", "LANG", "LANGUAGE"):
        val = os.environ.get(env, "")
        if val.startswith("en"):
            return "en"
        if val.startswith("es"):
            return "es"
        if val.startswith("fr"):
            return "fr"
    return "fr"

_LANG = _detect_lang()

def set_lang(lang: str):
    """Override the detected language at runtime."""
    global _LANG
    if lang in ("fr", "en", "es"):
        _LANG = lang

# ── Translations ──────────────────────────────────────────────────────────────

_T: dict[str, dict[str, str]] = {

    # ── firmware_analyzer.py ─────────────────────────────────────────────────

    "fw.banner": {
        "fr": "Nevelio Firmware Analyzer v{version}",
        "en": "Nevelio Firmware Analyzer v{version}",
        "es": "Nevelio Firmware Analyzer v{version}",
    },
    "fw.report_written": {
        "fr": "[✓] Rapport écrit dans {path} ({n} finding(s))",
        "en": "[✓] Report written to {path} ({n} finding(s))",
        "es": "[✓] Informe escrito en {path} ({n} hallazgo(s))",
    },
    "fw.error.not_found": {
        "fr": "Firmware introuvable : {path}",
        "en": "Firmware not found: {path}",
        "es": "Firmware no encontrado: {path}",
    },

    # findings firmware_analyzer
    "fw.binwalk.missing.title": {
        "fr": "binwalk non installé — analyse firmware incomplète",
        "en": "binwalk not installed — incomplete firmware analysis",
        "es": "binwalk no instalado — análisis de firmware incompleto",
    },
    "fw.binwalk.missing.desc": {
        "fr": "L'outil binwalk est requis pour l'extraction et la détection de signatures. Installer : pip install binwalk  ou  apt-get install binwalk",
        "en": "binwalk is required for extraction and signature detection. Install: pip install binwalk  or  apt-get install binwalk",
        "es": "binwalk es necesario para la extracción y detección de firmas. Instalar: pip install binwalk  o  apt-get install binwalk",
    },
    "fw.binwalk.missing.rem": {
        "fr": "pip install binwalk",
        "en": "pip install binwalk",
        "es": "pip install binwalk",
    },
    "fw.binwalk.filesystems.title": {
        "fr": "Système(s) de fichiers détecté(s) : {fs}",
        "en": "Filesystem(s) detected: {fs}",
        "es": "Sistema(s) de archivos detectado(s): {fs}",
    },
    "fw.binwalk.filesystems.desc": {
        "fr": "binwalk a détecté {n} type(s) de conteneur(s) dans l'image firmware. L'extraction peut révéler des binaires analysables, des scripts de démarrage et des fichiers de configuration.",
        "en": "binwalk detected {n} container type(s) in the firmware image. Extraction may reveal analysable binaries, boot scripts and configuration files.",
        "es": "binwalk detectó {n} tipo(s) de contenedor(s) en la imagen firmware. La extracción puede revelar binarios analizables, scripts de arranque y archivos de configuración.",
    },
    "fw.binwalk.filesystems.rem": {
        "fr": "Extraire et analyser chaque système de fichiers individuellement.",
        "en": "Extract and analyse each filesystem individually.",
        "es": "Extraer y analizar cada sistema de archivos individualmente.",
    },
    "fw.binwalk.partial.title": {
        "fr": "Extraction binwalk partielle ou échouée",
        "en": "binwalk extraction partial or failed",
        "es": "Extracción binwalk parcial o fallida",
    },
    "fw.binwalk.partial.desc": {
        "fr": "Code de retour : {rc}. L'extraction a peut-être partiellement réussi.",
        "en": "Return code: {rc}. Extraction may have partially succeeded.",
        "es": "Código de retorno: {rc}. La extracción puede haber tenido éxito parcialmente.",
    },
    "fw.binwalk.partial.rem": {
        "fr": "Vérifier les droits d'écriture sur le répertoire d'extraction.",
        "en": "Check write permissions on the extraction directory.",
        "es": "Verificar los permisos de escritura en el directorio de extracción.",
    },
    "fw.r2.missing.title": {
        "fr": "radare2 non installé — analyse ELF ignorée",
        "en": "radare2 not installed — ELF analysis skipped",
        "es": "radare2 no instalado — análisis ELF omitido",
    },
    "fw.r2.missing.desc": {
        "fr": "L'analyse des protections binaires (NX, PIE, Canary, RELRO) nécessite radare2. Installer : apt-get install radare2",
        "en": "Binary protection analysis (NX, PIE, Canary, RELRO) requires radare2. Install: apt-get install radare2",
        "es": "El análisis de protecciones binarias (NX, PIE, Canary, RELRO) requiere radare2. Instalar: apt-get install radare2",
    },
    "fw.r2.missing.rem": {
        "fr": "apt-get install radare2  # ou pip install r2pipe",
        "en": "apt-get install radare2  # or pip install r2pipe",
        "es": "apt-get install radare2  # o pip install r2pipe",
    },
    "fw.elf.unprotected.title": {
        "fr": "Binaires ELF sans protections : {n} trouvé(s) — CWE-1209",
        "en": "ELF binaries missing protections: {n} found — CWE-1209",
        "es": "Binarios ELF sin protecciones: {n} encontrado(s) — CWE-1209",
    },
    "fw.elf.unprotected.desc": {
        "fr": "{n} binaire(s) extrait(s) du firmware manquent de protections mémoire critiques. Un attaquant ayant accès au shell du dispositif peut plus facilement exploiter des vulnérabilités buffer overflow.",
        "en": "{n} binary/binaries extracted from firmware are missing critical memory protections. An attacker with shell access to the device can more easily exploit buffer overflow vulnerabilities.",
        "es": "{n} binario(s) extraído(s) del firmware carecen de protecciones de memoria críticas. Un atacante con acceso al shell del dispositivo puede explotar más fácilmente vulnerabilidades de buffer overflow.",
    },
    "fw.elf.unprotected.rem": {
        "fr": "Recompiler avec : -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now\nVérifier les options du toolchain (Buildroot, Yocto) pour activer ces protections par défaut.",
        "en": "Recompile with: -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now\nCheck toolchain options (Buildroot, Yocto) to enable these protections by default.",
        "es": "Recompilar con: -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now\nVerificar las opciones del toolchain (Buildroot, Yocto) para habilitar estas protecciones por defecto.",
    },
    "fw.elf.ok.title": {
        "fr": "Binaires ELF correctement protégés ({n} analysés)",
        "en": "ELF binaries correctly protected ({n} analysed)",
        "es": "Binarios ELF correctamente protegidos ({n} analizados)",
    },
    "fw.elf.ok.desc": {
        "fr": "Tous les binaires ELF analysés disposent des protections mémoire standard.",
        "en": "All analysed ELF binaries have standard memory protections.",
        "es": "Todos los binarios ELF analizados disponen de las protecciones de memoria estándar.",
    },
    "fw.angr.missing.title": {
        "fr": "angr non installé — analyse symbolique ignorée",
        "en": "angr not installed — symbolic analysis skipped",
        "es": "angr no instalado — análisis simbólico omitido",
    },
    "fw.angr.missing.desc": {
        "fr": "angr (analyse symbolique) n'est pas installé. Pour détecter les buffer overflows dans les binaires ARM/MIPS/x86 : pip install angr (installation ~5 min, ~500MB)",
        "en": "angr (symbolic analysis) is not installed. To detect buffer overflows in ARM/MIPS/x86 binaries: pip install angr (~5 min install, ~500MB)",
        "es": "angr (análisis simbólico) no está instalado. Para detectar buffer overflows en binarios ARM/MIPS/x86: pip install angr (instalación ~5 min, ~500MB)",
    },
    "fw.angr.execstack.title": {
        "fr": "Pile exécutable dans {bin} — CWE-119",
        "en": "Executable stack in {bin} — CWE-119",
        "es": "Pila ejecutable en {bin} — CWE-119",
    },
    "fw.angr.execstack.desc": {
        "fr": "Le binaire a été compilé avec une pile exécutable (GNU_STACK RWX). Un attaquant peut injecter et exécuter du shellcode directement sur la pile.",
        "en": "The binary was compiled with an executable stack (GNU_STACK RWX). An attacker can inject and execute shellcode directly on the stack.",
        "es": "El binario fue compilado con una pila ejecutable (GNU_STACK RWX). Un atacante puede inyectar y ejecutar shellcode directamente en la pila.",
    },
    "fw.angr.execstack.rem": {
        "fr": "Recompiler avec : -Wl,-z,noexecstack",
        "en": "Recompile with: -Wl,-z,noexecstack",
        "es": "Recompilar con: -Wl,-z,noexecstack",
    },
    "fw.angr.dangerous.title": {
        "fr": "Fonctions dangereuses dans {bin} — {funcs}",
        "en": "Dangerous functions in {bin} — {funcs}",
        "es": "Funciones peligrosas en {bin} — {funcs}",
    },
    "fw.angr.dangerous.desc": {
        "fr": "angr a détecté {n} fonction(s) dangereuse(s) importée(s) dans {bin}. Ces fonctions sont connues pour être vulnérables aux buffer overflows et injections de commandes si les entrées ne sont pas validées.",
        "en": "angr detected {n} dangerous imported function(s) in {bin}. These functions are known to be vulnerable to buffer overflows and command injections if inputs are not validated.",
        "es": "angr detectó {n} función(es) peligrosa(s) importada(s) en {bin}. Estas funciones son conocidas por ser vulnerables a buffer overflows e inyecciones de comandos si las entradas no son validadas.",
    },
    "fw.angr.dangerous.rem": {
        "fr": "Remplacer par des alternatives sécurisées : strncpy/strlcpy, fgets, snprintf, strncat. Activer les sanitizers à la compilation : -fsanitize=address,undefined",
        "en": "Replace with safer alternatives: strncpy/strlcpy, fgets, snprintf, strncat. Enable sanitizers at build time: -fsanitize=address,undefined",
        "es": "Reemplazar con alternativas seguras: strncpy/strlcpy, fgets, snprintf, strncat. Activar sanitizers en compilación: -fsanitize=address,undefined",
    },
    "fw.angr.done.title": {
        "fr": "Analyse symbolique angr terminée ({n} binaire(s))",
        "en": "angr symbolic analysis complete ({n} binary/binaries)",
        "es": "Análisis simbólico angr completado ({n} binario(s))",
    },
    "fw.angr.done.desc": {
        "fr": "angr a analysé {analyzed} binaire(s) ELF. {vulns} binaire(s) contiennent des fonctions potentiellement dangereuses.",
        "en": "angr analysed {analyzed} ELF binary/binaries. {vulns} binary/binaries contain potentially dangerous functions.",
        "es": "angr analizó {analyzed} binario(s) ELF. {vulns} binario(s) contienen funciones potencialmente peligrosas.",
    },
    "fw.magic.title": {
        "fr": "Magic bytes détectés : {n} conteneur(s)",
        "en": "Magic bytes detected: {n} container(s)",
        "es": "Magic bytes detectados: {n} contenedor(s)",
    },
    "fw.magic.desc": {
        "fr": "Des signatures de systèmes de fichiers ou de formats compressés ont été trouvées dans l'image brute. Utiliser binwalk pour l'extraction complète.",
        "en": "Filesystem or compressed format signatures were found in the raw image. Use binwalk for full extraction.",
        "es": "Se encontraron firmas de sistemas de archivos o formatos comprimidos en la imagen bruta. Usar binwalk para la extracción completa.",
    },
    "fw.magic.rem": {
        "fr": "binwalk --extract --matryoshka firmware.bin",
        "en": "binwalk --extract --matryoshka firmware.bin",
        "es": "binwalk --extract --matryoshka firmware.bin",
    },
    "fw.entropy.low.title": {
        "fr": "Entropie faible détectée — firmware potentiellement non chiffré",
        "en": "Low entropy detected — firmware potentially unencrypted",
        "es": "Entropía baja detectada — firmware potencialmente sin cifrar",
    },
    "fw.entropy.low.desc": {
        "fr": "L'entropie moyenne du firmware est {entropy:.2f} (< 0.5). Un firmware non chiffré expose son contenu à l'analyse statique complète, facilitant l'extraction de secrets, de clés et de code propriétaire.",
        "en": "Average firmware entropy is {entropy:.2f} (< 0.5). An unencrypted firmware exposes its content to full static analysis, facilitating extraction of secrets, keys and proprietary code.",
        "es": "La entropía media del firmware es {entropy:.2f} (< 0.5). Un firmware sin cifrar expone su contenido al análisis estático completo, facilitando la extracción de secretos, claves y código propietario.",
    },
    "fw.entropy.low.rem": {
        "fr": "Chiffrer le firmware avec AES-256 (boot ROM decrypt). Activer Secure Boot pour vérifier l'authenticité.",
        "en": "Encrypt firmware with AES-256 (boot ROM decrypt). Enable Secure Boot to verify authenticity.",
        "es": "Cifrar el firmware con AES-256 (boot ROM decrypt). Activar Secure Boot para verificar la autenticidad.",
    },
    "fw.strings.desc": {
        "fr": "Détecté par analyse `strings` sur l'image firmware brute. {n} occurrence(s) (tronquées à 3 pour l'affichage).",
        "en": "Detected by `strings` analysis on raw firmware image. {n} occurrence(s) (truncated to 3 for display).",
        "es": "Detectado por análisis `strings` en imagen firmware bruta. {n} ocurrencia(s) (truncado a 3 para visualización).",
    },
    "fw.strings.rem": {
        "fr": "Ne pas embarquer de secrets en clair dans le firmware. Utiliser un stockage sécurisé (eFuse, secure enclave, TPM). Implémenter un mécanisme de provisioning post-production.",
        "en": "Do not embed plaintext secrets in firmware. Use secure storage (eFuse, secure enclave, TPM). Implement a post-production provisioning mechanism.",
        "es": "No incluir secretos en texto claro en el firmware. Usar almacenamiento seguro (eFuse, secure enclave, TPM). Implementar un mecanismo de aprovisionamiento post-producción.",
    },

    # ── volatility_runner.py ─────────────────────────────────────────────────

    "vol.banner": {
        "fr": "Nevelio Volatility 3 Runner v{version}",
        "en": "Nevelio Volatility 3 Runner v{version}",
        "es": "Nevelio Volatility 3 Runner v{version}",
    },
    "vol.report_written": {
        "fr": "[✓] Rapport forensique : {path} ({n} finding(s))",
        "en": "[✓] Forensic report: {path} ({n} finding(s))",
        "es": "[✓] Informe forense: {path} ({n} hallazgo(s))",
    },
    "vol.error.not_found": {
        "fr": "Dump introuvable : {path}",
        "en": "Dump not found: {path}",
        "es": "Dump no encontrado: {path}",
    },
    "vol.missing.title": {
        "fr": "Volatility 3 non installé — analyse forensique ignorée",
        "en": "Volatility 3 not installed — forensic analysis skipped",
        "es": "Volatility 3 no instalado — análisis forense omitido",
    },
    "vol.missing.desc": {
        "fr": "vol3 / volatility3 est requis pour l'analyse du dump mémoire. Installer : pip install volatility3",
        "en": "vol3 / volatility3 is required for memory dump analysis. Install: pip install volatility3",
        "es": "vol3 / volatility3 es necesario para el análisis del dump de memoria. Instalar: pip install volatility3",
    },
    "vol.missing.rem": {
        "fr": "pip install volatility3",
        "en": "pip install volatility3",
        "es": "pip install volatility3",
    },
    "vol.dkom.title": {
        "fr": "DKOM détecté : {n} processus caché(s) — CWE-693",
        "en": "DKOM detected: {n} hidden process(es) — CWE-693",
        "es": "DKOM detectado: {n} proceso(s) oculto(s) — CWE-693",
    },
    "vol.dkom.desc": {
        "fr": "psscan a détecté {n} processus non listés par pslist. Cette divergence indique probablement une manipulation des structures de liste de processus (Direct Kernel Object Manipulation — rootkit technique). PIDs suspects : {pids}",
        "en": "psscan detected {n} processes not listed by pslist. This divergence likely indicates manipulation of process list structures (Direct Kernel Object Manipulation — rootkit technique). Suspicious PIDs: {pids}",
        "es": "psscan detectó {n} procesos no listados por pslist. Esta divergencia indica probablemente una manipulación de las estructuras de lista de procesos (Direct Kernel Object Manipulation — técnica rootkit). PIDs sospechosos: {pids}",
    },
    "vol.dkom.rem": {
        "fr": "Analyser chaque PID suspect avec malfind et dlllist. Comparer avec les connexions réseau (netscan). L'indicateur de compromission le plus fiable est la présence de connexions réseau actives depuis un PID caché.",
        "en": "Analyse each suspicious PID with malfind and dlllist. Correlate with network connections (netscan). The most reliable indicator of compromise is active network connections from a hidden PID.",
        "es": "Analizar cada PID sospechoso con malfind y dlllist. Correlacionar con conexiones de red (netscan). El indicador de compromiso más fiable es la presencia de conexiones de red activas desde un PID oculto.",
    },
    "vol.dkom.ok.title": {
        "fr": "Aucun processus caché détecté ({n} processus analysés)",
        "en": "No hidden processes detected ({n} processes analysed)",
        "es": "Ningún proceso oculto detectado ({n} procesos analizados)",
    },
    "vol.dkom.ok.desc": {
        "fr": "pslist et psscan sont cohérents — pas d'indice de DKOM.",
        "en": "pslist and psscan are consistent — no DKOM evidence.",
        "es": "pslist y psscan son coherentes — sin evidencia de DKOM.",
    },
    "vol.malfind.title": {
        "fr": "Code injecté détecté : {n} région(s) suspecte(s) — CWE-94",
        "en": "Injected code detected: {n} suspicious region(s) — CWE-94",
        "es": "Código inyectado detectado: {n} región(es) sospechosa(s) — CWE-94",
    },
    "vol.malfind.desc": {
        "fr": "malfind a identifié {n} région(s) mémoire avec des caractéristiques d'injection de code (PE header hors de son emplacement normal, ou pages RWX avec patterns shellcode). Technique typique : process hollowing, reflective DLL injection, shellcode injection.",
        "en": "malfind identified {n} memory region(s) with code injection characteristics (PE header outside its normal location, or RWX pages with shellcode patterns). Typical techniques: process hollowing, reflective DLL injection, shellcode injection.",
        "es": "malfind identificó {n} región(es) de memoria con características de inyección de código (PE header fuera de su ubicación normal, o páginas RWX con patrones de shellcode). Técnicas típicas: process hollowing, reflective DLL injection, inyección de shellcode.",
    },
    "vol.malfind.rem": {
        "fr": "Extraire les régions suspectes avec malfind --dump pour analyse statique. Analyser avec YARA (yargen) ou VirusTotal. Corrélation avec les connexions réseau pour identifier les C2.",
        "en": "Extract suspicious regions with malfind --dump for static analysis. Analyse with YARA (yargen) or VirusTotal. Correlate with network connections to identify C2.",
        "es": "Extraer regiones sospechosas con malfind --dump para análisis estático. Analizar con YARA (yargen) o VirusTotal. Correlacionar con conexiones de red para identificar C2.",
    },
    "vol.malfind.ok.title": {
        "fr": "Aucune injection de code détectée par malfind",
        "en": "No code injection detected by malfind",
        "es": "Ninguna inyección de código detectada por malfind",
    },
    "vol.malfind.ok.desc": {
        "fr": "malfind n'a pas trouvé de régions mémoire avec signatures d'injection.",
        "en": "malfind found no memory regions with injection signatures.",
        "es": "malfind no encontró regiones de memoria con firmas de inyección.",
    },
    "vol.hashdump.title": {
        "fr": "Hashes NTLM extraits de la mémoire : {n} compte(s) — CWE-312",
        "en": "NTLM hashes extracted from memory: {n} account(s) — CWE-312",
        "es": "Hashes NTLM extraídos de la memoria: {n} cuenta(s) — CWE-312",
    },
    "vol.hashdump.desc": {
        "fr": "{n} hash(es) NTLM ont été extraits de la mémoire vive. Ces hashes permettent des attaques Pass-the-Hash sans craquer le mot de passe. La présence de hashes NTLM en mémoire est normale mais représente un risque en cas de compromission du système (Mimikatz-style).",
        "en": "{n} NTLM hash(es) extracted from RAM. These hashes enable Pass-the-Hash attacks without cracking the password. NTLM hashes in memory are normal but represent a risk if the system is compromised (Mimikatz-style).",
        "es": "{n} hash(es) NTLM extraídos de la RAM. Estos hashes permiten ataques Pass-the-Hash sin descifrar la contraseña. Los hashes NTLM en memoria son normales pero representan un riesgo si el sistema está comprometido (estilo Mimikatz).",
    },
    "vol.hashdump.rem": {
        "fr": "Activer Windows Credential Guard (Virtualization-Based Security). Configurer lsass en mode protégé (Protected Process Light). Appliquer la politique 'Network security: Do not store LAN Manager hash value'.",
        "en": "Enable Windows Credential Guard (Virtualization-Based Security). Configure lsass in protected mode (Protected Process Light). Apply 'Network security: Do not store LAN Manager hash value' policy.",
        "es": "Activar Windows Credential Guard (Virtualization-Based Security). Configurar lsass en modo protegido (Protected Process Light). Aplicar la política 'Network security: Do not store LAN Manager hash value'.",
    },
    "vol.syscall.title": {
        "fr": "Hooks syscall détectés : {n} entrée(s) modifiée(s) — CWE-693",
        "en": "Syscall hooks detected: {n} modified entry/entries — CWE-693",
        "es": "Hooks syscall detectados: {n} entrada(s) modificada(s) — CWE-693",
    },
    "vol.syscall.desc": {
        "fr": "La table des syscalls Linux contient {n} hook(s). Ce pattern est caractéristique d'un rootkit kernel (LKM rootkit). Les hooks permettent d'intercepter les appels système pour dissimuler des processus, des fichiers, des connexions réseau.",
        "en": "The Linux syscall table contains {n} hook(s). This pattern is characteristic of a kernel rootkit (LKM rootkit). Hooks intercept system calls to hide processes, files and network connections.",
        "es": "La tabla de syscalls de Linux contiene {n} hook(s). Este patrón es característico de un rootkit kernel (LKM rootkit). Los hooks interceptan llamadas al sistema para ocultar procesos, archivos y conexiones de red.",
    },
    "vol.syscall.rem": {
        "fr": "Système considéré comme compromis. Actions immédiates :\n1. Isoler le système du réseau\n2. Créer un dump complet avec avml/LiME\n3. Analyser avec un second kernel (live boot USB)\n4. Réinstaller depuis une image connue saine",
        "en": "System considered compromised. Immediate actions:\n1. Isolate from network\n2. Create full dump with avml/LiME\n3. Analyse with a second kernel (live boot USB)\n4. Reinstall from a known-good image",
        "es": "Sistema considerado comprometido. Acciones inmediatas:\n1. Aislar del sistema de red\n2. Crear dump completo con avml/LiME\n3. Analizar con un segundo kernel (live boot USB)\n4. Reinstalar desde una imagen conocida como sana",
    },
    "vol.network.title": {
        "fr": "Connexions réseau suspectes : {n} sur port(s) C2 connus",
        "en": "Suspicious network connections: {n} on known C2 port(s)",
        "es": "Conexiones de red sospechosas: {n} en puerto(s) C2 conocidos",
    },
    "vol.network.desc": {
        "fr": "Des connexions sur des ports typiquement utilisés par des outils offensifs (Metasploit, netcat backdoors, IRC botnets) ont été détectées.",
        "en": "Connections on ports typically used by offensive tools (Metasploit, netcat backdoors, IRC botnets) were detected.",
        "es": "Se detectaron conexiones en puertos típicamente utilizados por herramientas ofensivas (Metasploit, backdoors netcat, botnets IRC).",
    },
    "vol.network.rem": {
        "fr": "Analyser les processus associés à ces connexions. Comparer avec les processus cachés (DKOM). Bloquer ces connexions au pare-feu et analyser les destinations.",
        "en": "Analyse processes associated with these connections. Compare with hidden processes (DKOM). Block these connections at the firewall and analyse destinations.",
        "es": "Analizar los procesos asociados a estas conexiones. Comparar con procesos ocultos (DKOM). Bloquear estas conexiones en el firewall y analizar los destinos.",
    },

    # ── chipwhisperer_acq.py ─────────────────────────────────────────────────

    "cw.banner": {
        "fr": "\n  Nevelio ChipWhisperer Acquisition v{version}",
        "en": "\n  Nevelio ChipWhisperer Acquisition v{version}",
        "es": "\n  Nevelio ChipWhisperer Adquisición v{version}",
    },
    "cw.info_scope": {
        "fr": "  Scope : {scope}  |  Cible : {target}",
        "en": "  Scope : {scope}  |  Target : {target}",
        "es": "  Scope : {scope}  |  Objetivo : {target}",
    },
    "cw.info_traces": {
        "fr": "  Traces demandées : {n}\n",
        "en": "  Traces requested : {n}\n",
        "es": "  Trazas solicitadas : {n}\n",
    },
    "cw.simulate_forced": {
        "fr": "  [i] Mode simulation activé (--simulate).",
        "en": "  [i] Simulation mode active (--simulate).",
        "es": "  [i] Modo simulación activo (--simulate).",
    },
    "cw.simulate_fallback": {
        "fr": "  [!] ChipWhisperer non détecté — mode simulation.",
        "en": "  [!] ChipWhisperer not detected — simulation mode.",
        "es": "  [!] ChipWhisperer no detectado — modo simulación.",
    },
    "cw.generating": {
        "fr": "  Génération de {n} traces simulées...",
        "en": "  Generating {n} simulated traces...",
        "es": "  Generando {n} trazas simuladas...",
    },
    "cw.scope_ok": {
        "fr": "  [✓] Scope connecté : {scope}",
        "en": "  [✓] Scope connected: {scope}",
        "es": "  [✓] Scope conectado: {scope}",
    },
    "cw.target_ok": {
        "fr": "  [✓] Cible connectée : {target}\n",
        "en": "  [✓] Target connected: {target}\n",
        "es": "  [✓] Objetivo conectado: {target}\n",
    },
    "cw.acq_error": {
        "fr": "  [✗] Erreur acquisition : {error}",
        "en": "  [✗] Acquisition error: {error}",
        "es": "  [✗] Error de adquisición: {error}",
    },
    "cw.fallback_sim": {
        "fr": "  Basculement vers le mode simulation...",
        "en": "  Falling back to simulation mode...",
        "es": "  Cambiando al modo simulación...",
    },
    "cw.timeout": {
        "fr": "  [!] Timeout à la trace {i}/{n}",
        "en": "  [!] Timeout at trace {i}/{n}",
        "es": "  [!] Timeout en traza {i}/{n}",
    },
    "cw.progress": {
        "fr": "  [*] {i}/{n} traces acquises",
        "en": "  [*] {i}/{n} traces acquired",
        "es": "  [*] {i}/{n} trazas adquiridas",
    },
    "cw.done": {
        "fr": "\n  [✓] {n} traces acquises et sauvegardées.",
        "en": "\n  [✓] {n} traces acquired and saved.",
        "es": "\n  [✓] {n} trazas adquiridas y guardadas.",
    },
    "cw.saved": {
        "fr": "[✓] Traces sauvegardées : {path}",
        "en": "[✓] Traces saved: {path}",
        "es": "[✓] Trazas guardadas: {path}",
    },
    "cw.meta_saved": {
        "fr": "[✓] Métadonnées         : {path}",
        "en": "[✓] Metadata           : {path}",
        "es": "[✓] Metadatos          : {path}",
    },
    "cw.error.unknown_target": {
        "fr": "Type de cible inconnu : {target}",
        "en": "Unknown target type: {target}",
        "es": "Tipo de objetivo desconocido: {target}",
    },
    "cw.error.format": {
        "fr": "Format supporté : .npz uniquement",
        "en": "Supported format: .npz only",
        "es": "Formato soportado: solo .npz",
    },

    # ── cpa_analysis.py ──────────────────────────────────────────────────────

    "cpa.banner": {
        "fr": "\n  Nevelio CPA Analysis v{version}\n",
        "en": "\n  Nevelio CPA Analysis v{version}\n",
        "es": "\n  Nevelio CPA Analysis v{version}\n",
    },
    "cpa.simulate_info": {
        "fr": "  [i] Mode simulation — génération de {n} traces AES-128...",
        "en": "  [i] Simulation mode — generating {n} AES-128 traces...",
        "es": "  [i] Modo simulación — generando {n} trazas AES-128...",
    },
    "cpa.secret_key": {
        "fr": "  Clé secrète simulée : {key}\n",
        "en": "  Simulated secret key: {key}\n",
        "es": "  Clave secreta simulada: {key}\n",
    },
    "cpa.error.traces_required": {
        "fr": "[✗] --traces requis (ou --simulate)",
        "en": "[✗] --traces required (or --simulate)",
        "es": "[✗] --traces requerido (o --simulate)",
    },
    "cpa.loading": {
        "fr": "  Chargement des traces : {path}",
        "en": "  Loading traces: {path}",
        "es": "  Cargando trazas: {path}",
    },
    "cpa.shape": {
        "fr": "  {n} traces × {s} échantillons\n",
        "en": "  {n} traces × {s} samples\n",
        "es": "  {n} trazas × {s} muestras\n",
    },
    "cpa.running": {
        "fr": "  [*] Attaque CPA en cours...",
        "en": "  [*] CPA attack in progress...",
        "es": "  [*] Ataque CPA en progreso...",
    },
    "cpa.byte_result": {
        "fr": "  Byte {idx:2d} → 0x{key:02X}  (corrélation max : {corr:.4f})",
        "en": "  Byte {idx:2d} → 0x{key:02X}  (max correlation: {corr:.4f})",
        "es": "  Byte {idx:2d} → 0x{key:02X}  (correlación máx: {corr:.4f})",
    },
    "cpa.key_recovered": {
        "fr": "\n  Clé recouvrée : {key}",
        "en": "\n  Recovered key: {key}",
        "es": "\n  Clave recuperada: {key}",
    },
    "cpa.key_correct": {
        "fr": "  [✓] Clé correctement recouvrée !",
        "en": "  [✓] Key correctly recovered!",
        "es": "  [✓] ¡Clave correctamente recuperada!",
    },
    "cpa.key_wrong": {
        "fr": "  [!] {n}/16 bytes incorrects",
        "en": "  [!] {n}/16 bytes incorrect",
        "es": "  [!] {n}/16 bytes incorrectos",
    },
    "cpa.tvla_running": {
        "fr": "\n  [*] TVLA en cours...",
        "en": "\n  [*] TVLA in progress...",
        "es": "\n  [*] TVLA en progreso...",
    },
    "cpa.tvla_result": {
        "fr": "  TVLA → |t|_max = {t:.2f}  ({status})",
        "en": "  TVLA → |t|_max = {t:.2f}  ({status})",
        "es": "  TVLA → |t|_max = {t:.2f}  ({status})",
    },
    "cpa.tvla_leak": {
        "fr": "FUITE DÉTECTÉE",
        "en": "LEAKAGE DETECTED",
        "es": "FUGA DETECTADA",
    },
    "cpa.tvla_ok": {
        "fr": "Pas de fuite détectée",
        "en": "No leakage detected",
        "es": "Sin fuga detectada",
    },
    "cpa.tvla_error": {
        "fr": "  [!] TVLA non disponible : {error}",
        "en": "  [!] TVLA not available: {error}",
        "es": "  [!] TVLA no disponible: {error}",
    },
    "cpa.key_saved": {
        "fr": "\n  [✓] Clé sauvegardée : {path}",
        "en": "\n  [✓] Key saved: {path}",
        "es": "\n  [✓] Clave guardada: {path}",
    },
    "cpa.json_saved": {
        "fr": "  [✓] Rapport JSON : {path}",
        "en": "  [✓] JSON report: {path}",
        "es": "  [✓] Informe JSON: {path}",
    },
    "cpa.numpy_missing": {
        "fr": "[✗] numpy requis : pip install numpy",
        "en": "[✗] numpy required: pip install numpy",
        "es": "[✗] numpy requerido: pip install numpy",
    },
    "cpa.matplotlib_missing": {
        "fr": "  [!] matplotlib non disponible — visualisation ignorée.",
        "en": "  [!] matplotlib not available — visualisation skipped.",
        "es": "  [!] matplotlib no disponible — visualización omitida.",
    },
    "cpa.plot_saved": {
        "fr": "  [✓] Traces sauvegardées : {path}",
        "en": "  [✓] Traces saved: {path}",
        "es": "  [✓] Trazas guardadas: {path}",
    },
    "cpa.cpa_saved": {
        "fr": "  [✓] Résultats CPA sauvegardés : {path}",
        "en": "  [✓] CPA results saved: {path}",
        "es": "  [✓] Resultados CPA guardados: {path}",
    },
    "cpa.tvla_saved": {
        "fr": "  [✓] TVLA sauvegardé : {path}",
        "en": "  [✓] TVLA saved: {path}",
        "es": "  [✓] TVLA guardado: {path}",
    },

    # ── Matplotlib labels (graphs) ───────────────────────────────────────────

    "plot.amplitude": {
        "fr": "Amplitude",
        "en": "Amplitude",
        "es": "Amplitud",
    },
    "plot.cpa_title": {
        "fr": "CPA — Corrélation max par hypothèse de clé",
        "en": "CPA — Max correlation per key hypothesis",
        "es": "CPA — Correlación máxima por hipótesis de clave",
    },
    "plot.tvla_title": {
        "fr": "TVLA — t de Welch (|t| > 4.5 = fuite significative)",
        "en": "TVLA — Welch t-test (|t| > 4.5 = significant leakage)",
        "es": "TVLA — t de Welch (|t| > 4.5 = fuga significativa)",
    },
    "plot.tvla_leak_label": {
        "fr": "Fuite détectée",
        "en": "Leakage detected",
        "es": "Fuga detectada",
    },
    "plot.byte_label": {
        "fr": "Byte {idx} → 0x{key:02X}",
        "en": "Byte {idx} → 0x{key:02X}",
        "es": "Byte {idx} → 0x{key:02X}",
    },
}

# ── Translation function ──────────────────────────────────────────────────────

def t(__key: str, **kwargs) -> str:
    """
    Translate `__key` to the current language, with optional interpolation.
    Falls back to French, then to the key itself if not found.
    The `__key` name avoids shadowing kwargs like key=0x2b in CPA results.
    Example: t("fw.report_written", path="/tmp/out.json", n=5)
             t("cpa.byte_result", idx=0, key=0x2b, corr=0.98)
    """
    entry = _T.get(__key)
    if entry is None:
        return __key  # key not found → return key as-is

    text = entry.get(_LANG) or entry.get("fr") or __key

    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError):
            pass  # if interpolation fails, return raw text

    return text
