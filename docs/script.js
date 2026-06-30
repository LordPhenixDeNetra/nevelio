  // ── i18n ──────────────────────────────────────────────────────────────
  const TRANSLATIONS = {
    fr: {
      'search.placeholder': 'Rechercher…',
      'theme.toggle': 'Changer de thème',
      'copy.btn': 'Copier',
      'copy.done': '✓ Copié',
      'search.no-results': 'Aucun résultat',
      // Nav
      'nav.start': 'Démarrage',
      'nav.installation': 'Installation',
      'nav.legal': 'Disclaimer légal',
      'nav.config': 'Configuration',
      'nav.commands': 'Commandes',
      'nav.sub.target': '↳ Cible & spec',
      'nav.sub.profiles': '↳ Profils',
      'nav.sub.modules': '↳ Modules',
      'nav.sub.auth': '↳ Authentification',
      'nav.sub.output': '↳ Sortie',
      'nav.sub.modes': '↳ Modes spéciaux',
      'nav.tui': 'TUI Dashboard',
      'nav.attack-modules': "Modules d'attaque",
      'nav.outputs': 'Sorties & intégrations',
      'nav.formats': 'Formats de sortie',
      'nav.ai': 'Suggestions IA',
      'nav.cicd': 'CI/CD',
      'nav.scenarios': 'Scénarios pratiques',
      'nav.reference': 'Référence',
      'nav.i18n': 'Internationalisation',
      'nav.flags': 'Tous les flags',
      // Hero
      'hero.tagline': "Outil de test de pénétration d'API REST et GraphQL, écrit en Rust.",
      'hero.btn.start': '⚡ Démarrer',
      'hero.btn.cli': '📖 Référence CLI',
      'hero.btn.md': '📝 Version Markdown',
      'hero.stat.modules': "Modules d'attaque",
      'hero.stat.checks': 'Vérifications',
      'hero.stat.formats': 'Formats de sortie',
      'hero.stat.tests': 'Tests',
      // TOC
      'toc.title': 'Table des matières',
      'toc.1': 'Installation',
      'toc.2': 'Disclaimer légal',
      'toc.3': 'Configuration (init)',
      'toc.4': 'Commande scan',
      'toc.5': 'TUI Dashboard',
      'toc.6': "10 Modules d'attaque",
      'toc.7': 'Formats de sortie',
      'toc.8': 'Suggestions IA',
      'toc.9': 'Commande report',
      'toc.10': 'Commande modules',
      'toc.11': 'Intégration CI/CD',
      'toc.12': 'Scénarios pratiques',
      'toc.13': 'Référence des flags',
      // Install
      'install.title': 'Installation',
      'install.prereqs': 'Prérequis',
      'install.rust.title': 'Rust stable ≥ 1.75',
      'install.rust.desc': 'Installer via <code>rustup update stable</code>',
      'install.net.title': 'Accès réseau à la cible',
      'install.net.desc': 'HTTPS recommandé, HTTP supporté',
      'install.auth.title': 'Autorisation écrite',
      'install.auth.desc': 'Obligation légale dans toutes les juridictions',
      'install.build': 'Compilation',
      'install.global': 'Installation globale (optionnel)',
      // Legal
      'legal.title': 'Disclaimer légal',
      'legal.warning': "Nevelio est conçu <strong>exclusivement</strong> pour des systèmes que vous possédez ou pour lesquels vous disposez d'une <strong>autorisation écrite explicite</strong>.",
      'legal.first-run': 'Premier lancement',
      'legal.first-run.desc': 'Au premier scan, Nevelio affiche un avertissement et demande confirmation :',
      'legal.persist': 'Persistance automatique',
      'legal.persist.desc': 'Après acceptation, un marqueur est écrit dans <code>~/.config/nevelio/legal_accepted</code>.',
      'legal.noninteractive': 'Mode non interactif (CI/CD)',
      // Config
      'config.title': 'Configuration — nevelio init',
      'config.desc': 'Génère un fichier <code>.nevelio.toml</code> commenté dans le répertoire courant :',
      'config.fields': 'Référence des champs',
      'config.col.field': 'Champ',
      'config.col.type': 'Type',
      'config.col.default': 'Défaut',
      'config.col.desc': 'Description',
      'config.target.desc': "URL de base de l'API cible",
      'config.spec.desc': 'Spec OpenAPI (fichier local ou URL)',
      'config.profile.desc': 'Profil de scan',
      'config.modules.desc': 'Modules à exécuter',
      'config.concurrency.desc': 'Requêtes simultanées',
      'config.rate.desc': 'Req/s maximum',
      'config.timeout.desc': 'Timeout par requête',
      'config.auth.desc': 'Header Authorization complet',
      'config.proxy.desc': 'Proxy HTTP (Burp Suite, etc.)',
      'config.outdir.desc': 'Répertoire de sortie',
      'config.failon.desc': "Seuil d'échec CI",
      'config.priority': "<strong>Priorité :</strong> les flags CLI écrasent toujours <code>.nevelio.toml</code>, qui écrase les valeurs par défaut.",
      // Scan
      'scan.title': 'Commande scan',
      'scan.target-spec': 'Cible et spec',
      'scan.col.flag': 'Flag',
      'scan.col.desc': 'Description',
      'scan.col.example': 'Exemple',
      'scan.target.desc': "URL de base de l'API",
      'scan.url.desc': 'Alias de --target',
      'scan.spec.desc': 'Spec OpenAPI, Postman v2.1, Insomnia v4 ou HAR (auto-détecté)',
      'scan.profiles': 'Profils de scan',
      'scan.stealth.meta': '1 req simultanée · 2 req/s',
      'scan.stealth.tag': 'Production sensible',
      'scan.stealth.desc': 'Évite les alertes IDS/WAF. Scan lent mais discret.',
      'scan.normal.meta': '5 req simultanées · 10 req/s',
      'scan.normal.tag': 'Défaut recommandé',
      'scan.normal.desc': 'Équilibre vitesse/discrétion. Idéal pour le staging.',
      'scan.aggressive.meta': '20 req simultanées · 50 req/s',
      'scan.aggressive.tag': 'Lab uniquement',
      'scan.aggressive.desc': 'Scan rapide. Ne pas utiliser en production.',
      'scan.modules': 'Sélection de modules',
      'scan.modules.desc': 'Par défaut, tous les modules sont exécutés. Pour restreindre :',
      'scan.auth': 'Authentification et proxy',
      'scan.output': 'Sortie et rapports',
      'scan.modes': 'Modes spéciaux',
      // Modes
      'mode.resume.desc': 'Reprendre un scan interrompu depuis <code>--out-dir</code>',
      'mode.dryrun.desc': 'Simuler sans envoyer de requêtes réelles',
      'mode.notui.desc': 'Désactiver le dashboard TUI (CI/CD, pipes)',
      'mode.ai.desc': 'Suggestions IA après le scan (nécessite <code>ANTHROPIC_API_KEY</code>)',
      'mode.verbose.desc': 'Logs détaillés et requêtes HTTP',
      'mode.acceptlegal.desc': 'Accepter le disclaimer sans prompt',
      'mode.nocolor.desc': 'Désactiver les couleurs ANSI (logs CI)',
      // TUI
      'tui.title': 'TUI Dashboard',
      'tui.desc': "Le dashboard ratatui s'active automatiquement quand la sortie est un <strong>terminal interactif</strong> (TTY détecté) et que <code>--no-tui</code> est absent.",
      'tui.feat.progress.title': 'Barre de progression',
      'tui.feat.progress.desc': 'Avancement global avec ETA estimé en temps réel',
      'tui.feat.modules.title': 'État des modules',
      'tui.feat.modules.desc': 'En attente, en cours ou terminé pour chaque module',
      'tui.feat.findings.title': 'Findings en direct',
      'tui.feat.findings.desc': 'Vulnérabilités découvertes affichées immédiatement',
      // Modules
      'modules.title': "Modules d'attaque",
      // Formats
      'formats.title': 'Formats de sortie',
      'formats.json.use': 'Format canonique — toujours écrit',
      'formats.html.use': 'Rapport interactif — défaut',
      'formats.md.use': 'Wikis, PRs, Confluence',
      'formats.junit.use': 'Jenkins, GitLab CI',
      'formats.sarif.use': 'GitHub Advanced Security',
      'formats.json-structure': "Structure d'un finding JSON",
      'formats.html-features': 'Rapport HTML — fonctionnalités',
      'formats.feat.filter.title': 'Filtre par sévérité',
      'formats.feat.filter.desc': 'Boutons Critical / High / Medium / Low / Info',
      'formats.feat.theme.title': 'Thème clair/sombre',
      'formats.feat.theme.desc': 'Toggle persisté en localStorage',
      'formats.feat.accordion.title': 'Accordéon',
      'formats.feat.accordion.desc': 'Chaque finding collapsible pour une lecture claire',
      // AI
      'ai.title': 'Suggestions IA via Claude',
      'ai.desc': "Nevelio peut générer des <strong>recommandations de remédiation détaillées</strong> pour chaque finding, via l'API Claude d'Anthropic.",
      'ai.model-info': "Modèle utilisé : <code>claude-haiku-4-5-20251001</code>. Sortie : <code>&lt;out-dir&gt;/ai_suggestions.md</code>",
      'ai.missing-key': "Si <code>ANTHROPIC_API_KEY</code> est absent, Nevelio affiche un avertissement <strong>avant le scan</strong> et continue normalement sans les suggestions.",
      // Report
      'report.title': 'Commande <code>report</code> / <code>convert</code>',
      'report.desc': 'Convertit un <code>findings.json</code> existant en un autre format, <strong>sans relancer le scan</strong>.',
      'report.col.required': 'Requis',
      'report.yes': 'Oui',
      'report.no': 'Non',
      'report.input.desc': 'Chemin vers le <code>findings.json</code> source',
      'report.format.desc': 'Format cible',
      // Modules-cmd
      'modules-cmd.title': 'Commande <code>modules</code>',
      // CI/CD
      'cicd.title': 'Intégration CI/CD',
      'cicd.tip': 'Combinaison recommandée pour tout pipeline CI : <code>--accept-legal --no-tui --no-color --fail-on high</code>',
      'cicd.col.practice': 'Pratique',
      'cicd.col.why': 'Pourquoi',
      'cicd.accept-legal.why': 'Évite le blocage sur prompt interactif',
      'cicd.no-tui.why': 'Le TUI nécessite un TTY absent en CI',
      'cicd.no-color.why': 'Les codes ANSI polluent les logs CI',
      'cicd.fail-on.why': 'Bloque les PRs avec vulnérabilités critiques',
      'cicd.profile.why': "Ne pas saturer l'environnement de staging",
      'cicd.api-key.why': 'Ne jamais écrire la clé en clair',
      'cicd.sarif.why': 'Intégration native GitHub Security',
      'cicd.junit.why': 'Intégration native des rapports de test',
      // Scenarios
      'scenarios.title': 'Scénarios pratiques',
      'scenarios.tab.a': 'A — Express',
      'scenarios.tab.b': 'B — Professionnel',
      'scenarios.tab.c': 'C — Burp Suite',
      'scenarios.tab.d': 'D — IA + multi-format',
      'scenarios.tab.e': 'E — Reprise',
      'scenarios.tab.f': 'F — GraphQL',
      'scenarios.a.title': 'Audit rapide sans spec OpenAPI',
      'scenarios.a.desc': 'Idéal pour une première prise en main ou une cible sans spec disponible.',
      'scenarios.b.title': 'Audit professionnel complet',
      'scenarios.c.title': 'Audit avec interception Burp Suite',
      'scenarios.d.title': 'Scan avec suggestions IA et multi-format',
      'scenarios.e.title': 'Reprise après interruption',
      'scenarios.f.title': "Audit d'une API GraphQL",
      // i18n section
      'i18n.title': 'Internationalisation',
      'i18n.desc': "Nevelio supporte <strong>3 langues</strong> — français (<code>fr</code>), anglais (<code>en</code>), espagnol (<code>es</code>). Tous les messages CLI, le TUI, le disclaimer légal, les suggestions IA et le rapport HTML sont traduits automatiquement.",
      'i18n.detection': 'Détection automatique',
      'i18n.detection.desc': "La langue est résolue dans cet ordre de priorité :",
      'i18n.col.priority': 'Priorité',
      'i18n.col.source': 'Source',
      'i18n.src.flag': 'Flag <code>--lang</code>',
      'i18n.src.env': 'Variable <code>NEVELIO_LANG</code>',
      'i18n.src.sys': 'Variable système <code>$LANGUAGE</code> / <code>$LANG</code>',
      'i18n.src.default': 'Défaut',
      'i18n.normalize': 'La normalisation est automatique : <code>fr_FR.UTF-8</code>, <code>fr-FR</code> et <code>fr</code> donnent tous <code>fr</code>.',
      'i18n.examples': 'Exemples',
      'i18n.legal-multilang': 'Disclaimer légal multilingue',
      'i18n.legal-multilang.desc': 'Le texte légal affiché au premier lancement est traduit. La réponse positive varie selon la langue :',
      'i18n.col.lang': 'Langue',
      'i18n.col.answers': 'Réponses acceptées',
      'i18n.lang.fr': 'Français',
      'i18n.lang.en': 'Anglais',
      'i18n.lang.es': 'Espagnol',
      'i18n.html-report': 'Rapport HTML localisé',
      'i18n.html-report.desc': 'Le rapport HTML généré (<code>report.html</code>) hérite de la langue du scan. Tous ses labels (Cible / Target / Objetivo, Description, Recommandation…) sont traduits automatiquement.',
      'i18n.ai-localized': 'Suggestions IA localisées',
      'i18n.ai-localized.desc': "Avec <code>--ai-suggestions</code>, le prompt envoyé à Claude est rédigé dans la langue sélectionnée — les suggestions reçues sont donc dans la même langue.",
      // Flags ref
      'flags.title': 'Référence complète des flags',
      'flags.scan-h3': 'nevelio scan',
      'flags.col.type': 'Type',
      'flags.spec.desc': 'Spec OpenAPI (JSON ou YAML)',
      'flags.type.list': 'liste',
      'flags.module.desc': 'Modules à exécuter (espace-séparés)',
      'flags.type.int': 'entier',
      'flags.rate.desc': 'Requêtes par seconde max',
      'flags.type.seconds': 'secondes',
      'flags.timeout.desc': 'Timeout par requête',
      'flags.proxy.desc': 'Proxy HTTP',
      'flags.output.desc': 'Format de sortie (défaut: html)',
      'flags.type.path': 'chemin',
      'flags.type.bool': 'booléen',
      'flags.notui.desc': 'Désactiver le TUI dashboard',
      'flags.ai.desc': 'Suggestions IA (ANTHROPIC_API_KEY requis)',
      'flags.global-h3': 'Flags globaux (toutes commandes)',
      'flags.lang.desc': 'Langue : <code>fr</code> | <code>en</code> | <code>es</code> (détection auto via <code>$LANG</code> si absent)',
      'flags.report-h3': 'nevelio report / convert',
      'flags.input.desc': 'Fichier findings.json source',
      'flags.env-h3': "Variables d'environnement",
      'flags.col.variable': 'Variable',
      'flags.anthropic-key.desc': 'Clé API Claude (requis pour --ai-suggestions)',
      'flags.nevelio-lang.desc': 'Forcer la langue sans flag (<code>fr</code> / <code>en</code> / <code>es</code>). Prioritaire sur <code>$LANG</code>.',
      // Module cards
      'mod.ac.idor': 'IDOR numérique (CWE-639)',
      'mod.ac.priv': 'Élévation de privilèges (CWE-269)',
      'mod.bl.rate': 'Rate limiting absent',
      'mod.bl.negative': 'Valeurs négatives / prix',
      'mod.gql.introspection': 'Introspection exposée (CWE-200)',
      'mod.auth.detail': 'Module auth — Détail',
      'mod.injection.detail': 'Module injection — Détail',
      'mod.access.detail': 'Module access-control — Détail',
      'mod.graphql.detail': 'Module graphql — Détail',
      'mod.infra.checks': 'Module infra — Vérifications',
      'mod.business.checks': 'Module business-logic — Vérifications',
      // Check descriptions
      'check.auth.missing.desc': 'Teste chaque endpoint <strong>sans header Authorization</strong>. Un code 200/201 indique une authentification manquante.',
      'check.example-finding': 'Exemple de finding :',
      'check.jwt.none.desc': 'Envoie un JWT avec <code>"alg": "none"</code> et signature vide. Si le serveur l\'accepte, il ne valide pas la signature.',
      'check.jwt.none.fix': '<strong>Remédiation :</strong> Rejeter explicitement l\'algorithme "none". Utiliser RS256 ou ES256.',
      'check.jwt.weak.desc': 'Tente de valider la signature HMAC-SHA256 avec des secrets faibles communs : <code>secret</code>, <code>password</code>, <code>123456</code>, <code>changeme</code>…',
      'check.jwt.claims.desc': 'Modifie les claims <code>role</code> → admin, <code>is_admin</code> → true, et re-signe avec le secret faible découvert.',
      'check.basic.brute.desc': 'Sur les endpoints avec <code>WWW-Authenticate: Basic</code>, teste un dictionnaire de couples user:password communs.',
      'check.sqli.intro': '4 techniques sur chaque paramètre :',
      'check.col.technique': 'Technique',
      'check.col.detection': 'Détection',
      'check.sqli.timebased.det': 'Délai ≥ 4s',
      'check.sqli.errorbased.det': 'Message SQL dans réponse',
      'check.sqli.unionbased.det': 'Données injectées',
      'check.sqli.booleanbased.det': 'Contenu différent',
      'check.col.engine': 'Moteur',
      'check.col.result': 'Résultat',
      'check.cmdi.detection': 'Détection : délai (sleep) ou présence de <code>uid=</code> dans la réponse.',
      'check.idor.desc': 'Substitue les IDs dans l\'URL par des valeurs voisines (<code>/users/42</code> → <code>/users/41</code>) ou des UUIDs aléatoires. Compare les réponses pour détecter un accès à des ressources d\'autres utilisateurs.',
      'check.bfla.desc': 'Teste les endpoints <code>/admin/*</code>, <code>/management/*</code>, <code>/internal/*</code> avec le token utilisateur standard. Un code 200 indique une autorisation mal configurée par rôle.',
      'check.introspection.desc': 'Si le serveur répond avec le schéma complet, la structure interne est exposée à un attaquant.',
      'check.depthdos.desc': 'Sans limite de profondeur, le serveur peut subir une surcharge CPU/mémoire.',
      'check.rate.desc': 'Envoie 20 requêtes rapides et vérifie l\'absence de réponse <code>429 Too Many Requests</code>. Sans rate limiting, login/OTP/reset sont vulnérables au brute force.',
      'check.race.desc': 'Envoie simultanément 10 requêtes identiques (achat, réservation, coupon) et détecte si plusieurs répondent avec succès alors qu\'une seule devrait l\'être.',
      // Infra table
      'infra.col.check': 'Vérification',
      'infra.col.severity': 'Sévérité',
      'infra.col.desc': 'Description',
      'infra.cors.desc': '<code>Origin: evil.com</code> reflété dans la réponse',
      'infra.hsts.desc': 'Pas de <code>Strict-Transport-Security</code> sur HTTPS',
      'infra.hsts.name': 'HSTS absent',
      'infra.secheaders.desc': 'X-Content-Type-Options, X-Frame-Options, X-XSS-Protection',
      'infra.secheaders.name': 'Security headers',
      'infra.server.desc': 'Header <code>Server:</code> exposant la version exacte',
      'infra.server.name': 'Server disclosure',
      'infra.csp.desc': 'Absent ou permissif (unsafe-inline, *)',
      'infra.cookie.desc': 'Secure, HttpOnly, SameSite manquants',
      'infra.tls.desc': 'TLS 1.0 / 1.1 accepté (RFC 8996)',
      'infra.tls.name': 'TLS obsolète',
      'infra.secrets.desc': 'Clés AWS, tokens GitHub, clés PEM…',
      'infra.secrets.name': 'Secrets dans réponses',
      'infra.stacktrace.desc': 'NullPointerException, Traceback… dans les erreurs',
      'cicd.tab.best': 'Bonnes pratiques',
      // Footer
      'footer.text': 'Nevelio v0.6 — API Security Scanner | nevelio-hw v0.5.0 — Hardware Security — Usage autorisé uniquement',
      // Hardware extension
      'nav.hardware': 'Extension Hardware',
      'nav.hw.modules': '↳ Modules',
      'nav.hw.python': '↳ Outils Python',
      'nav.hw.quickstart': '↳ Démarrage rapide',
      'hw.title': 'Extension Hardware Security — nevelio-hw',
      'hw.desc': 'En complément du scanner API (couche 7), <strong>nevelio-hw</strong> audite les vulnérabilités au niveau hardware, firmware, noyau et canaux auxiliaires.<br>Version actuelle&nbsp;: <strong>v0.5.0</strong> — 72/85 tâches — 50 tests — 9 crates.',
      'hw.quickstart.title': 'Démarrage rapide',
      'hw.modules.title': 'Modules (9 crates)',
      'hw.col.coverage': 'Couverture',
      'hw.col.severity': 'Sévérité max',
      'hw.python.title': 'Outils Python',
      'hw.col.usage': 'Usage',
      'hw.mod.cpu': 'Spectre, Meltdown, Retbleed, TAA, MDS, microcode, NX/SMEP/SMAP',
      'hw.mod.firmware': 'Secure Boot UEFI, flashrom, mises à jour BIOS/LVFS',
      'hw.mod.dma': 'IOMMU/VT-d, niveau de sécurité Thunderbolt, PCIe',
      'hw.mod.side': 'Oracle de timing HTTP (RDTSC), Flush+Reload cache L3, AES-NI',
      'hw.mod.jtag': 'Sondes JTAG/UART, STM32 RDP Level 0, firmware (binwalk + angr)',
      'hw.mod.memory': 'Rowhammer, ECC/TRR, swap+KASLR, Volatility forensics (DKOM, malfind)',
      'hw.mod.fpga': 'IOMMU strict, Thunderbolt, leechcore FFI, Verilog PCIe TLP',
      'hw.py.firmware': 'binwalk + strings (7 patterns) + r2pipe ELF + angr (fonctions dangereuses)',
      'hw.py.volatility': 'pslist vs psscan (DKOM), malfind, hashdump, check_syscall (hooks rootkit)',
      'hw.py.cw': 'Acquisition traces CW Nano/Lite/Pro — mode <code>--simulate</code> sans hardware',
      'hw.py.cpa': 'CPA AES-128 (Pearson), TVLA Welch/SCALib, visualisation matplotlib PNG',
      'hw.legal.title': 'Usage légal uniquement.',
      'hw.legal.desc': 'Voir <a href="../hardware/LEGAL.md"><code>hardware/LEGAL.md</code></a> — Code Pénal 323-1/323-8, NIS2, CFAA. Un audit sans autorisation écrite est illégal. Les tests actifs (Rowhammer, dump RAM) doivent être réalisés sur des machines de lab dédiées.',
      'hw.docs.link': 'Documentation complète :',
      'hw.install.link': 'Installation :',
    },

    en: {
      'search.placeholder': 'Search…',
      'theme.toggle': 'Toggle theme',
      'copy.btn': 'Copy',
      'copy.done': '✓ Copied',
      'search.no-results': 'No results',
      // Nav
      'nav.start': 'Getting started',
      'nav.installation': 'Installation',
      'nav.legal': 'Legal disclaimer',
      'nav.config': 'Configuration',
      'nav.commands': 'Commands',
      'nav.sub.target': '↳ Target & spec',
      'nav.sub.profiles': '↳ Profiles',
      'nav.sub.modules': '↳ Modules',
      'nav.sub.auth': '↳ Authentication',
      'nav.sub.output': '↳ Output',
      'nav.sub.modes': '↳ Special modes',
      'nav.tui': 'TUI Dashboard',
      'nav.attack-modules': 'Attack modules',
      'nav.outputs': 'Outputs & integrations',
      'nav.formats': 'Output formats',
      'nav.ai': 'AI suggestions',
      'nav.cicd': 'CI/CD',
      'nav.scenarios': 'Practical scenarios',
      'nav.reference': 'Reference',
      'nav.i18n': 'Internationalisation',
      'nav.flags': 'All flags',
      // Hero
      'hero.tagline': 'REST and GraphQL API penetration testing tool, written in Rust.',
      'hero.btn.start': '⚡ Get started',
      'hero.btn.cli': '📖 CLI Reference',
      'hero.btn.md': '📝 Markdown version',
      'hero.stat.modules': 'Attack modules',
      'hero.stat.checks': 'Checks',
      'hero.stat.formats': 'Output formats',
      'hero.stat.tests': 'Tests',
      // TOC
      'toc.title': 'Table of contents',
      'toc.1': 'Installation',
      'toc.2': 'Legal disclaimer',
      'toc.3': 'Configuration (init)',
      'toc.4': 'scan command',
      'toc.5': 'TUI Dashboard',
      'toc.6': '10 Attack modules',
      'toc.7': 'Output formats',
      'toc.8': 'AI suggestions',
      'toc.9': 'report command',
      'toc.10': 'modules command',
      'toc.11': 'CI/CD integration',
      'toc.12': 'Practical scenarios',
      'toc.13': 'Flags reference',
      // Install
      'install.title': 'Installation',
      'install.prereqs': 'Prerequisites',
      'install.rust.title': 'Rust stable ≥ 1.75',
      'install.rust.desc': 'Install via <code>rustup update stable</code>',
      'install.net.title': 'Network access to target',
      'install.net.desc': 'HTTPS recommended, HTTP supported',
      'install.auth.title': 'Written authorisation',
      'install.auth.desc': 'Legal requirement in all jurisdictions',
      'install.build': 'Build',
      'install.global': 'Global install (optional)',
      // Legal
      'legal.title': 'Legal disclaimer',
      'legal.warning': 'Nevelio is designed <strong>exclusively</strong> for systems you own or for which you have <strong>explicit written authorisation</strong>.',
      'legal.first-run': 'First run',
      'legal.first-run.desc': 'On the first scan, Nevelio displays a warning and asks for confirmation:',
      'legal.persist': 'Automatic persistence',
      'legal.persist.desc': 'After acceptance, a marker is written to <code>~/.config/nevelio/legal_accepted</code>.',
      'legal.noninteractive': 'Non-interactive mode (CI/CD)',
      // Config
      'config.title': 'Configuration — nevelio init',
      'config.desc': 'Generates a commented <code>.nevelio.toml</code> file in the current directory:',
      'config.fields': 'Field reference',
      'config.col.field': 'Field',
      'config.col.type': 'Type',
      'config.col.default': 'Default',
      'config.col.desc': 'Description',
      'config.target.desc': 'Base URL of the target API',
      'config.spec.desc': 'OpenAPI spec (local file or URL)',
      'config.profile.desc': 'Scan profile',
      'config.modules.desc': 'Modules to run',
      'config.concurrency.desc': 'Concurrent requests',
      'config.rate.desc': 'Max req/s',
      'config.timeout.desc': 'Per-request timeout',
      'config.auth.desc': 'Full Authorization header',
      'config.proxy.desc': 'HTTP proxy (Burp Suite, etc.)',
      'config.outdir.desc': 'Output directory',
      'config.failon.desc': 'CI failure threshold',
      'config.priority': '<strong>Priority:</strong> CLI flags always override <code>.nevelio.toml</code>, which overrides defaults.',
      // Scan
      'scan.title': 'scan command',
      'scan.target-spec': 'Target & spec',
      'scan.col.flag': 'Flag',
      'scan.col.desc': 'Description',
      'scan.col.example': 'Example',
      'scan.target.desc': 'Base URL of the API',
      'scan.url.desc': 'Alias for --target',
      'scan.spec.desc': 'OpenAPI spec, Postman v2.1, Insomnia v4 or HAR (auto-detected)',
      'scan.profiles': 'Scan profiles',
      'scan.stealth.meta': '1 concurrent req · 2 req/s',
      'scan.stealth.tag': 'Sensitive production',
      'scan.stealth.desc': 'Avoids IDS/WAF alerts. Slow but stealthy scan.',
      'scan.normal.meta': '5 concurrent reqs · 10 req/s',
      'scan.normal.tag': 'Recommended default',
      'scan.normal.desc': 'Balances speed and stealth. Ideal for staging.',
      'scan.aggressive.meta': '20 concurrent reqs · 50 req/s',
      'scan.aggressive.tag': 'Lab only',
      'scan.aggressive.desc': 'Fast scan. Do not use in production.',
      'scan.modules': 'Module selection',
      'scan.modules.desc': 'By default, all modules are run. To restrict:',
      'scan.auth': 'Authentication & proxy',
      'scan.output': 'Output & reports',
      'scan.modes': 'Special modes',
      // Modes
      'mode.resume.desc': 'Resume an interrupted scan from <code>--out-dir</code>',
      'mode.dryrun.desc': 'Simulate without sending real requests',
      'mode.notui.desc': 'Disable the TUI dashboard (CI/CD, pipes)',
      'mode.ai.desc': 'AI suggestions after scan (requires <code>ANTHROPIC_API_KEY</code>)',
      'mode.verbose.desc': 'Detailed logs and HTTP requests',
      'mode.acceptlegal.desc': 'Accept disclaimer without prompt',
      'mode.nocolor.desc': 'Disable ANSI colours (CI logs)',
      // TUI
      'tui.title': 'TUI Dashboard',
      'tui.desc': 'The ratatui dashboard activates automatically when output is an <strong>interactive terminal</strong> (TTY detected) and <code>--no-tui</code> is absent.',
      'tui.feat.progress.title': 'Progress bar',
      'tui.feat.progress.desc': 'Overall progress with real-time ETA estimate',
      'tui.feat.modules.title': 'Module status',
      'tui.feat.modules.desc': 'Waiting, running or done for each module',
      'tui.feat.findings.title': 'Live findings',
      'tui.feat.findings.desc': 'Vulnerabilities displayed as discovered',
      // Modules
      'modules.title': 'Attack modules',
      // Formats
      'formats.title': 'Output formats',
      'formats.json.use': 'Canonical format — always written',
      'formats.html.use': 'Interactive report — default',
      'formats.md.use': 'Wikis, PRs, Confluence',
      'formats.junit.use': 'Jenkins, GitLab CI',
      'formats.sarif.use': 'GitHub Advanced Security',
      'formats.json-structure': 'JSON finding structure',
      'formats.html-features': 'HTML report — features',
      'formats.feat.filter.title': 'Severity filter',
      'formats.feat.filter.desc': 'Critical / High / Medium / Low / Info buttons',
      'formats.feat.theme.title': 'Light/dark theme',
      'formats.feat.theme.desc': 'Toggle persisted in localStorage',
      'formats.feat.accordion.title': 'Accordion',
      'formats.feat.accordion.desc': 'Each finding collapsible for easy reading',
      // AI
      'ai.title': 'AI suggestions via Claude',
      'ai.desc': 'Nevelio can generate <strong>detailed remediation recommendations</strong> for each finding, via the Anthropic Claude API.',
      'ai.model-info': 'Model used: <code>claude-haiku-4-5-20251001</code>. Output: <code>&lt;out-dir&gt;/ai_suggestions.md</code>',
      'ai.missing-key': 'If <code>ANTHROPIC_API_KEY</code> is absent, Nevelio displays a warning <strong>before the scan</strong> and continues normally without suggestions.',
      // Report
      'report.title': '<code>report</code> / <code>convert</code> command',
      'report.desc': 'Converts an existing <code>findings.json</code> to another format, <strong>without re-running the scan</strong>.',
      'report.col.required': 'Required',
      'report.yes': 'Yes',
      'report.no': 'No',
      'report.input.desc': 'Path to the source <code>findings.json</code>',
      'report.format.desc': 'Target format',
      // Modules-cmd
      'modules-cmd.title': '<code>modules</code> command',
      // CI/CD
      'cicd.title': 'CI/CD integration',
      'cicd.tip': 'Recommended combination for any CI pipeline: <code>--accept-legal --no-tui --no-color --fail-on high</code>',
      'cicd.col.practice': 'Practice',
      'cicd.col.why': 'Why',
      'cicd.accept-legal.why': 'Prevents blocking on interactive prompt',
      'cicd.no-tui.why': 'TUI requires a TTY unavailable in CI',
      'cicd.no-color.why': 'ANSI codes pollute CI logs',
      'cicd.fail-on.why': 'Blocks PRs with critical vulnerabilities',
      'cicd.profile.why': 'Avoid saturating the staging environment',
      'cicd.api-key.why': 'Never write the key in plaintext',
      'cicd.sarif.why': 'Native GitHub Security integration',
      'cicd.junit.why': 'Native test report integration',
      // Scenarios
      'scenarios.title': 'Practical scenarios',
      'scenarios.tab.a': 'A — Express',
      'scenarios.tab.b': 'B — Professional',
      'scenarios.tab.c': 'C — Burp Suite',
      'scenarios.tab.d': 'D — AI + multi-format',
      'scenarios.tab.e': 'E — Resume',
      'scenarios.tab.f': 'F — GraphQL',
      'scenarios.a.title': 'Quick audit without OpenAPI spec',
      'scenarios.a.desc': 'Ideal for a first run or a target without an available spec.',
      'scenarios.b.title': 'Full professional audit',
      'scenarios.c.title': 'Audit with Burp Suite interception',
      'scenarios.d.title': 'Scan with AI suggestions and multi-format',
      'scenarios.e.title': 'Resume after interruption',
      'scenarios.f.title': 'GraphQL API audit',
      // i18n section
      'i18n.title': 'Internationalisation',
      'i18n.desc': 'Nevelio supports <strong>3 languages</strong> — French (<code>fr</code>), English (<code>en</code>), Spanish (<code>es</code>). All CLI messages, the TUI, legal disclaimer, AI suggestions and the HTML report are translated automatically.',
      'i18n.detection': 'Automatic detection',
      'i18n.detection.desc': 'The language is resolved in this priority order:',
      'i18n.col.priority': 'Priority',
      'i18n.col.source': 'Source',
      'i18n.src.flag': '<code>--lang</code> flag',
      'i18n.src.env': '<code>NEVELIO_LANG</code> variable',
      'i18n.src.sys': 'System variable <code>$LANGUAGE</code> / <code>$LANG</code>',
      'i18n.src.default': 'Default',
      'i18n.normalize': 'Normalisation is automatic: <code>fr_FR.UTF-8</code>, <code>fr-FR</code> and <code>fr</code> all resolve to <code>fr</code>.',
      'i18n.examples': 'Examples',
      'i18n.legal-multilang': 'Multilingual legal disclaimer',
      'i18n.legal-multilang.desc': 'The legal text displayed on first run is translated. The positive response varies by language:',
      'i18n.col.lang': 'Language',
      'i18n.col.answers': 'Accepted answers',
      'i18n.lang.fr': 'French',
      'i18n.lang.en': 'English',
      'i18n.lang.es': 'Spanish',
      'i18n.html-report': 'Localised HTML report',
      'i18n.html-report.desc': 'The generated HTML report (<code>report.html</code>) inherits the scan language. All labels (Target / Cible / Objetivo, Description, Recommendation…) are translated automatically.',
      'i18n.ai-localized': 'Localised AI suggestions',
      'i18n.ai-localized.desc': 'With <code>--ai-suggestions</code>, the prompt sent to Claude is written in the selected language — suggestions received are therefore in that language.',
      // Flags ref
      'flags.title': 'Complete flags reference',
      'flags.scan-h3': 'nevelio scan',
      'flags.col.type': 'Type',
      'flags.spec.desc': 'OpenAPI spec (JSON or YAML)',
      'flags.type.list': 'list',
      'flags.module.desc': 'Modules to run (space-separated)',
      'flags.type.int': 'integer',
      'flags.rate.desc': 'Max requests per second',
      'flags.type.seconds': 'seconds',
      'flags.timeout.desc': 'Per-request timeout',
      'flags.proxy.desc': 'HTTP proxy',
      'flags.output.desc': 'Output format (default: html)',
      'flags.type.path': 'path',
      'flags.type.bool': 'boolean',
      'flags.notui.desc': 'Disable TUI dashboard',
      'flags.ai.desc': 'AI suggestions (ANTHROPIC_API_KEY required)',
      'flags.global-h3': 'Global flags (all commands)',
      'flags.lang.desc': 'Language: <code>fr</code> | <code>en</code> | <code>es</code> (auto-detected via <code>$LANG</code> if absent)',
      'flags.report-h3': 'nevelio report / convert',
      'flags.input.desc': 'Source findings.json file',
      'flags.env-h3': 'Environment variables',
      'flags.col.variable': 'Variable',
      'flags.anthropic-key.desc': 'Claude API key (required for --ai-suggestions)',
      'flags.nevelio-lang.desc': 'Force language without flag (<code>fr</code> / <code>en</code> / <code>es</code>). Takes priority over <code>$LANG</code>.',
      // Module cards
      'mod.ac.idor': 'Numeric IDOR (CWE-639)',
      'mod.ac.priv': 'Privilege escalation (CWE-269)',
      'mod.bl.rate': 'Rate limiting absent',
      'mod.bl.negative': 'Negative values / price',
      'mod.gql.introspection': 'Exposed introspection (CWE-200)',
      'mod.auth.detail': 'Module auth — Detail',
      'mod.injection.detail': 'Module injection — Detail',
      'mod.access.detail': 'Module access-control — Detail',
      'mod.graphql.detail': 'Module graphql — Detail',
      'mod.infra.checks': 'Module infra — Checks',
      'mod.business.checks': 'Module business-logic — Checks',
      // Check descriptions
      'check.auth.missing.desc': 'Tests each endpoint <strong>without an Authorization header</strong>. A 200/201 response indicates missing authentication.',
      'check.example-finding': 'Finding example:',
      'check.jwt.none.desc': 'Sends a JWT with <code>"alg": "none"</code> and empty signature. If the server accepts it, it does not validate the signature.',
      'check.jwt.none.fix': '<strong>Remediation:</strong> Explicitly reject the "none" algorithm. Use RS256 or ES256.',
      'check.jwt.weak.desc': 'Attempts to validate the HMAC-SHA256 signature with common weak secrets: <code>secret</code>, <code>password</code>, <code>123456</code>, <code>changeme</code>…',
      'check.jwt.claims.desc': 'Modifies claims <code>role</code> → admin, <code>is_admin</code> → true, and re-signs with the discovered weak secret.',
      'check.basic.brute.desc': 'On endpoints with <code>WWW-Authenticate: Basic</code>, tests a dictionary of common user:password pairs.',
      'check.sqli.intro': '4 techniques on each parameter:',
      'check.col.technique': 'Technique',
      'check.col.detection': 'Detection',
      'check.sqli.timebased.det': 'Delay ≥ 4s',
      'check.sqli.errorbased.det': 'SQL message in response',
      'check.sqli.unionbased.det': 'Injected data',
      'check.sqli.booleanbased.det': 'Different content',
      'check.col.engine': 'Engine',
      'check.col.result': 'Result',
      'check.cmdi.detection': 'Detection: delay (sleep) or presence of <code>uid=</code> in the response.',
      'check.idor.desc': 'Substitutes IDs in the URL with adjacent values (<code>/users/42</code> → <code>/users/41</code>) or random UUIDs. Compares responses to detect access to other users\' resources.',
      'check.bfla.desc': 'Tests <code>/admin/*</code>, <code>/management/*</code>, <code>/internal/*</code> endpoints with the standard user token. A 200 response indicates misconfigured role-level authorisation.',
      'check.introspection.desc': 'If the server responds with the full schema, the internal structure is exposed to an attacker.',
      'check.depthdos.desc': 'Without a depth limit, the server can suffer CPU/memory overload.',
      'check.rate.desc': 'Sends 20 rapid requests and checks for the absence of a <code>429 Too Many Requests</code> response. Without rate limiting, login/OTP/reset are vulnerable to brute force.',
      'check.race.desc': 'Simultaneously sends 10 identical requests (purchase, booking, coupon) and detects whether multiple succeed when only one should.',
      // Infra table
      'infra.col.check': 'Check',
      'infra.col.severity': 'Severity',
      'infra.col.desc': 'Description',
      'infra.cors.desc': '<code>Origin: evil.com</code> reflected in the response',
      'infra.hsts.desc': 'No <code>Strict-Transport-Security</code> on HTTPS',
      'infra.hsts.name': 'Missing HSTS',
      'infra.secheaders.desc': 'X-Content-Type-Options, X-Frame-Options, X-XSS-Protection',
      'infra.secheaders.name': 'Security headers',
      'infra.server.desc': 'Header <code>Server:</code> exposing the exact version',
      'infra.server.name': 'Server disclosure',
      'infra.csp.desc': 'Absent or permissive (unsafe-inline, *)',
      'infra.cookie.desc': 'Missing Secure, HttpOnly, SameSite',
      'infra.tls.desc': 'TLS 1.0 / 1.1 accepted (RFC 8996)',
      'infra.tls.name': 'Obsolete TLS',
      'infra.secrets.desc': 'AWS keys, GitHub tokens, PEM keys…',
      'infra.secrets.name': 'Secrets in responses',
      'infra.stacktrace.desc': 'NullPointerException, Traceback… in error responses',
      'cicd.tab.best': 'Best practices',
      // Footer
      'footer.text': 'Nevelio v0.6 — API Security Scanner | nevelio-hw v0.5.0 — Hardware Security — Authorised use only',
      // Hardware extension
      'nav.hardware': 'Hardware Extension',
      'nav.hw.modules': '↳ Modules',
      'nav.hw.python': '↳ Python Tools',
      'nav.hw.quickstart': '↳ Quick start',
      'hw.title': 'Hardware Security Extension — nevelio-hw',
      'hw.desc': 'Alongside the API scanner (layer 7), <strong>nevelio-hw</strong> audits vulnerabilities at the hardware, firmware, kernel and side-channel levels.<br>Current version: <strong>v0.5.0</strong> — 72/85 tasks — 50 tests — 9 crates.',
      'hw.quickstart.title': 'Quick start',
      'hw.modules.title': 'Modules (9 crates)',
      'hw.col.coverage': 'Coverage',
      'hw.col.severity': 'Max severity',
      'hw.python.title': 'Python Tools',
      'hw.col.usage': 'Usage',
      'hw.mod.cpu': 'Spectre, Meltdown, Retbleed, TAA, MDS, microcode, NX/SMEP/SMAP',
      'hw.mod.firmware': 'Secure Boot UEFI, flashrom, BIOS/LVFS updates',
      'hw.mod.dma': 'IOMMU/VT-d, Thunderbolt security level, PCIe',
      'hw.mod.side': 'HTTP timing oracle (RDTSC), Flush+Reload L3 cache, AES-NI',
      'hw.mod.jtag': 'JTAG/UART probes, STM32 RDP Level 0, firmware (binwalk + angr)',
      'hw.mod.memory': 'Rowhammer, ECC/TRR, swap+KASLR, Volatility forensics (DKOM, malfind)',
      'hw.mod.fpga': 'IOMMU strict mode, Thunderbolt, leechcore FFI, Verilog PCIe TLP',
      'hw.py.firmware': 'binwalk + strings (7 patterns) + r2pipe ELF + angr (dangerous functions)',
      'hw.py.volatility': 'pslist vs psscan (DKOM), malfind, hashdump, check_syscall (rootkit hooks)',
      'hw.py.cw': 'CW Nano/Lite/Pro trace acquisition — <code>--simulate</code> mode without hardware',
      'hw.py.cpa': 'AES-128 CPA (Pearson), TVLA Welch/SCALib, matplotlib PNG visualisation',
      'hw.legal.title': 'Authorised use only.',
      'hw.legal.desc': 'See <a href="../hardware/LEGAL.md"><code>hardware/LEGAL.md</code></a> — Criminal Code 323-1/323-8, NIS2, CFAA. Auditing without written authorisation is illegal. Active tests (Rowhammer, RAM dump) must be run on dedicated lab machines.',
      'hw.docs.link': 'Full documentation:',
      'hw.install.link': 'Installation:',
    },

    es: {
      'search.placeholder': 'Buscar…',
      'theme.toggle': 'Cambiar tema',
      'copy.btn': 'Copiar',
      'copy.done': '✓ Copiado',
      'search.no-results': 'Sin resultados',
      // Nav
      'nav.start': 'Inicio',
      'nav.installation': 'Instalación',
      'nav.legal': 'Aviso legal',
      'nav.config': 'Configuración',
      'nav.commands': 'Comandos',
      'nav.sub.target': '↳ Objetivo & spec',
      'nav.sub.profiles': '↳ Perfiles',
      'nav.sub.modules': '↳ Módulos',
      'nav.sub.auth': '↳ Autenticación',
      'nav.sub.output': '↳ Salida',
      'nav.sub.modes': '↳ Modos especiales',
      'nav.tui': 'Panel TUI',
      'nav.attack-modules': 'Módulos de ataque',
      'nav.outputs': 'Salidas & integraciones',
      'nav.formats': 'Formatos de salida',
      'nav.ai': 'Sugerencias IA',
      'nav.cicd': 'CI/CD',
      'nav.scenarios': 'Escenarios prácticos',
      'nav.reference': 'Referencia',
      'nav.i18n': 'Internacionalización',
      'nav.flags': 'Todos los flags',
      // Hero
      'hero.tagline': 'Herramienta de pruebas de penetración para APIs REST y GraphQL, escrita en Rust.',
      'hero.btn.start': '⚡ Empezar',
      'hero.btn.cli': '📖 Referencia CLI',
      'hero.btn.md': '📝 Versión Markdown',
      'hero.stat.modules': 'Módulos de ataque',
      'hero.stat.checks': 'Verificaciones',
      'hero.stat.formats': 'Formatos de salida',
      'hero.stat.tests': 'Tests',
      // TOC
      'toc.title': 'Tabla de contenidos',
      'toc.1': 'Instalación',
      'toc.2': 'Aviso legal',
      'toc.3': 'Configuración (init)',
      'toc.4': 'Comando scan',
      'toc.5': 'Panel TUI',
      'toc.6': '10 Módulos de ataque',
      'toc.7': 'Formatos de salida',
      'toc.8': 'Sugerencias IA',
      'toc.9': 'Comando report',
      'toc.10': 'Comando modules',
      'toc.11': 'Integración CI/CD',
      'toc.12': 'Escenarios prácticos',
      'toc.13': 'Referencia de flags',
      // Install
      'install.title': 'Instalación',
      'install.prereqs': 'Requisitos previos',
      'install.rust.title': 'Rust estable ≥ 1.75',
      'install.rust.desc': 'Instalar via <code>rustup update stable</code>',
      'install.net.title': 'Acceso de red al objetivo',
      'install.net.desc': 'HTTPS recomendado, HTTP compatible',
      'install.auth.title': 'Autorización por escrito',
      'install.auth.desc': 'Obligación legal en todas las jurisdicciones',
      'install.build': 'Compilación',
      'install.global': 'Instalación global (opcional)',
      // Legal
      'legal.title': 'Aviso legal',
      'legal.warning': 'Nevelio está diseñado <strong>exclusivamente</strong> para sistemas que usted posee o para los que tiene <strong>autorización escrita explícita</strong>.',
      'legal.first-run': 'Primera ejecución',
      'legal.first-run.desc': 'En el primer escaneo, Nevelio muestra una advertencia y solicita confirmación:',
      'legal.persist': 'Persistencia automática',
      'legal.persist.desc': 'Tras la aceptación, se escribe un marcador en <code>~/.config/nevelio/legal_accepted</code>.',
      'legal.noninteractive': 'Modo no interactivo (CI/CD)',
      // Config
      'config.title': 'Configuración — nevelio init',
      'config.desc': 'Genera un archivo <code>.nevelio.toml</code> comentado en el directorio actual:',
      'config.fields': 'Referencia de campos',
      'config.col.field': 'Campo',
      'config.col.type': 'Tipo',
      'config.col.default': 'Defecto',
      'config.col.desc': 'Descripción',
      'config.target.desc': 'URL base de la API objetivo',
      'config.spec.desc': 'Spec OpenAPI (archivo local o URL)',
      'config.profile.desc': 'Perfil de escaneo',
      'config.modules.desc': 'Módulos a ejecutar',
      'config.concurrency.desc': 'Solicitudes simultáneas',
      'config.rate.desc': 'Máx solicitudes/s',
      'config.timeout.desc': 'Tiempo de espera por solicitud',
      'config.auth.desc': 'Cabecera Authorization completa',
      'config.proxy.desc': 'Proxy HTTP (Burp Suite, etc.)',
      'config.outdir.desc': 'Directorio de salida',
      'config.failon.desc': 'Umbral de fallo CI',
      'config.priority': '<strong>Prioridad:</strong> los flags CLI siempre anulan <code>.nevelio.toml</code>, que anula los valores por defecto.',
      // Scan
      'scan.title': 'Comando scan',
      'scan.target-spec': 'Objetivo y spec',
      'scan.col.flag': 'Flag',
      'scan.col.desc': 'Descripción',
      'scan.col.example': 'Ejemplo',
      'scan.target.desc': 'URL base de la API',
      'scan.url.desc': 'Alias de --target',
      'scan.spec.desc': 'Spec OpenAPI, Postman v2.1, Insomnia v4 o HAR (auto-detectado)',
      'scan.profiles': 'Perfiles de escaneo',
      'scan.stealth.meta': '1 solicitud simultánea · 2 sol/s',
      'scan.stealth.tag': 'Producción sensible',
      'scan.stealth.desc': 'Evita alertas IDS/WAF. Escaneo lento pero discreto.',
      'scan.normal.meta': '5 solicitudes simultáneas · 10 sol/s',
      'scan.normal.tag': 'Defecto recomendado',
      'scan.normal.desc': 'Equilibrio velocidad/discreción. Ideal para staging.',
      'scan.aggressive.meta': '20 solicitudes simultáneas · 50 sol/s',
      'scan.aggressive.tag': 'Solo en laboratorio',
      'scan.aggressive.desc': 'Escaneo rápido. No usar en producción.',
      'scan.modules': 'Selección de módulos',
      'scan.modules.desc': 'Por defecto se ejecutan todos los módulos. Para restringir:',
      'scan.auth': 'Autenticación y proxy',
      'scan.output': 'Salida e informes',
      'scan.modes': 'Modos especiales',
      // Modes
      'mode.resume.desc': 'Reanudar un escaneo interrumpido desde <code>--out-dir</code>',
      'mode.dryrun.desc': 'Simular sin enviar solicitudes reales',
      'mode.notui.desc': 'Deshabilitar el panel TUI (CI/CD, pipes)',
      'mode.ai.desc': 'Sugerencias IA tras el escaneo (requiere <code>ANTHROPIC_API_KEY</code>)',
      'mode.verbose.desc': 'Registros detallados y solicitudes HTTP',
      'mode.acceptlegal.desc': 'Aceptar el aviso legal sin solicitud',
      'mode.nocolor.desc': 'Deshabilitar colores ANSI (logs CI)',
      // TUI
      'tui.title': 'Panel TUI',
      'tui.desc': 'El panel ratatui se activa automáticamente cuando la salida es un <strong>terminal interactivo</strong> (TTY detectado) y <code>--no-tui</code> está ausente.',
      'tui.feat.progress.title': 'Barra de progreso',
      'tui.feat.progress.desc': 'Progreso global con estimación ETA en tiempo real',
      'tui.feat.modules.title': 'Estado de módulos',
      'tui.feat.modules.desc': 'En espera, en curso o terminado para cada módulo',
      'tui.feat.findings.title': 'Hallazgos en directo',
      'tui.feat.findings.desc': 'Vulnerabilidades mostradas a medida que se descubren',
      // Modules
      'modules.title': 'Módulos de ataque',
      // Formats
      'formats.title': 'Formatos de salida',
      'formats.json.use': 'Formato canónico — siempre escrito',
      'formats.html.use': 'Informe interactivo — defecto',
      'formats.md.use': 'Wikis, PRs, Confluence',
      'formats.junit.use': 'Jenkins, GitLab CI',
      'formats.sarif.use': 'GitHub Advanced Security',
      'formats.json-structure': 'Estructura de un hallazgo JSON',
      'formats.html-features': 'Informe HTML — características',
      'formats.feat.filter.title': 'Filtro por severidad',
      'formats.feat.filter.desc': 'Botones Critical / High / Medium / Low / Info',
      'formats.feat.theme.title': 'Tema claro/oscuro',
      'formats.feat.theme.desc': 'Toggle persistido en localStorage',
      'formats.feat.accordion.title': 'Acordeón',
      'formats.feat.accordion.desc': 'Cada hallazgo plegable para facilitar la lectura',
      // AI
      'ai.title': 'Sugerencias IA via Claude',
      'ai.desc': 'Nevelio puede generar <strong>recomendaciones de remediación detalladas</strong> para cada hallazgo, via la API Claude de Anthropic.',
      'ai.model-info': 'Modelo usado: <code>claude-haiku-4-5-20251001</code>. Salida: <code>&lt;out-dir&gt;/ai_suggestions.md</code>',
      'ai.missing-key': 'Si <code>ANTHROPIC_API_KEY</code> está ausente, Nevelio muestra una advertencia <strong>antes del escaneo</strong> y continúa normalmente sin sugerencias.',
      // Report
      'report.title': 'Comando <code>report</code> / <code>convert</code>',
      'report.desc': 'Convierte un <code>findings.json</code> existente a otro formato, <strong>sin relanzar el escaneo</strong>.',
      'report.col.required': 'Requerido',
      'report.yes': 'Sí',
      'report.no': 'No',
      'report.input.desc': 'Ruta al <code>findings.json</code> fuente',
      'report.format.desc': 'Formato objetivo',
      // Modules-cmd
      'modules-cmd.title': 'Comando <code>modules</code>',
      // CI/CD
      'cicd.title': 'Integración CI/CD',
      'cicd.tip': 'Combinación recomendada para cualquier pipeline CI: <code>--accept-legal --no-tui --no-color --fail-on high</code>',
      'cicd.col.practice': 'Práctica',
      'cicd.col.why': 'Por qué',
      'cicd.accept-legal.why': 'Evita el bloqueo en el prompt interactivo',
      'cicd.no-tui.why': 'El TUI necesita un TTY ausente en CI',
      'cicd.no-color.why': 'Los códigos ANSI ensucian los logs CI',
      'cicd.fail-on.why': 'Bloquea PRs con vulnerabilidades críticas',
      'cicd.profile.why': 'No saturar el entorno de staging',
      'cicd.api-key.why': 'Nunca escribir la clave en texto plano',
      'cicd.sarif.why': 'Integración nativa de GitHub Security',
      'cicd.junit.why': 'Integración nativa de informes de prueba',
      // Scenarios
      'scenarios.title': 'Escenarios prácticos',
      'scenarios.tab.a': 'A — Exprés',
      'scenarios.tab.b': 'B — Profesional',
      'scenarios.tab.c': 'C — Burp Suite',
      'scenarios.tab.d': 'D — IA + multi-formato',
      'scenarios.tab.e': 'E — Reanudación',
      'scenarios.tab.f': 'F — GraphQL',
      'scenarios.a.title': 'Auditoría rápida sin spec OpenAPI',
      'scenarios.a.desc': 'Ideal para una primera prueba o un objetivo sin spec disponible.',
      'scenarios.b.title': 'Auditoría profesional completa',
      'scenarios.c.title': 'Auditoría con intercepción Burp Suite',
      'scenarios.d.title': 'Escaneo con sugerencias IA y multi-formato',
      'scenarios.e.title': 'Reanudación tras interrupción',
      'scenarios.f.title': 'Auditoría de una API GraphQL',
      // i18n section
      'i18n.title': 'Internacionalización',
      'i18n.desc': 'Nevelio admite <strong>3 idiomas</strong> — francés (<code>fr</code>), inglés (<code>en</code>), español (<code>es</code>). Todos los mensajes CLI, el TUI, el aviso legal, las sugerencias IA y el informe HTML se traducen automáticamente.',
      'i18n.detection': 'Detección automática',
      'i18n.detection.desc': 'El idioma se resuelve en este orden de prioridad:',
      'i18n.col.priority': 'Prioridad',
      'i18n.col.source': 'Fuente',
      'i18n.src.flag': 'Flag <code>--lang</code>',
      'i18n.src.env': 'Variable <code>NEVELIO_LANG</code>',
      'i18n.src.sys': 'Variable del sistema <code>$LANGUAGE</code> / <code>$LANG</code>',
      'i18n.src.default': 'Defecto',
      'i18n.normalize': 'La normalización es automática: <code>fr_FR.UTF-8</code>, <code>fr-FR</code> y <code>fr</code> dan todos <code>fr</code>.',
      'i18n.examples': 'Ejemplos',
      'i18n.legal-multilang': 'Aviso legal multilingüe',
      'i18n.legal-multilang.desc': 'El texto legal mostrado en la primera ejecución está traducido. La respuesta positiva varía según el idioma:',
      'i18n.col.lang': 'Idioma',
      'i18n.col.answers': 'Respuestas aceptadas',
      'i18n.lang.fr': 'Francés',
      'i18n.lang.en': 'Inglés',
      'i18n.lang.es': 'Español',
      'i18n.html-report': 'Informe HTML localizado',
      'i18n.html-report.desc': 'El informe HTML generado (<code>report.html</code>) hereda el idioma del escaneo. Todas sus etiquetas (Objetivo / Target / Cible, Descripción, Recomendación…) se traducen automáticamente.',
      'i18n.ai-localized': 'Sugerencias IA localizadas',
      'i18n.ai-localized.desc': 'Con <code>--ai-suggestions</code>, el prompt enviado a Claude está redactado en el idioma seleccionado — las sugerencias recibidas están por lo tanto en el mismo idioma.',
      // Flags ref
      'flags.title': 'Referencia completa de flags',
      'flags.scan-h3': 'nevelio scan',
      'flags.col.type': 'Tipo',
      'flags.spec.desc': 'Spec OpenAPI (JSON o YAML)',
      'flags.type.list': 'lista',
      'flags.module.desc': 'Módulos a ejecutar (separados por espacio)',
      'flags.type.int': 'entero',
      'flags.rate.desc': 'Máx solicitudes por segundo',
      'flags.type.seconds': 'segundos',
      'flags.timeout.desc': 'Tiempo de espera por solicitud',
      'flags.proxy.desc': 'Proxy HTTP',
      'flags.output.desc': 'Formato de salida (defecto: html)',
      'flags.type.path': 'ruta',
      'flags.type.bool': 'booleano',
      'flags.notui.desc': 'Deshabilitar el panel TUI',
      'flags.ai.desc': 'Sugerencias IA (requiere ANTHROPIC_API_KEY)',
      'flags.global-h3': 'Flags globales (todos los comandos)',
      'flags.lang.desc': 'Idioma: <code>fr</code> | <code>en</code> | <code>es</code> (detección auto via <code>$LANG</code> si ausente)',
      'flags.report-h3': 'nevelio report / convert',
      'flags.input.desc': 'Archivo findings.json fuente',
      'flags.env-h3': 'Variables de entorno',
      'flags.col.variable': 'Variable',
      'flags.anthropic-key.desc': 'Clave API Claude (requerida para --ai-suggestions)',
      'flags.nevelio-lang.desc': 'Forzar idioma sin flag (<code>fr</code> / <code>en</code> / <code>es</code>). Prioritario sobre <code>$LANG</code>.',
      // Module cards
      'mod.ac.idor': 'IDOR numérico (CWE-639)',
      'mod.ac.priv': 'Escalada de privilegios (CWE-269)',
      'mod.bl.rate': 'Rate limiting ausente',
      'mod.bl.negative': 'Valores negativos / precio',
      'mod.gql.introspection': 'Introspección expuesta (CWE-200)',
      'mod.auth.detail': 'Módulo auth — Detalle',
      'mod.injection.detail': 'Módulo injection — Detalle',
      'mod.access.detail': 'Módulo access-control — Detalle',
      'mod.graphql.detail': 'Módulo graphql — Detalle',
      'mod.infra.checks': 'Módulo infra — Verificaciones',
      'mod.business.checks': 'Módulo business-logic — Verificaciones',
      // Check descriptions
      'check.auth.missing.desc': 'Prueba cada endpoint <strong>sin cabecera Authorization</strong>. Un código 200/201 indica autenticación ausente.',
      'check.example-finding': 'Ejemplo de hallazgo:',
      'check.jwt.none.desc': 'Envía un JWT con <code>"alg": "none"</code> y firma vacía. Si el servidor lo acepta, no valida la firma.',
      'check.jwt.none.fix': '<strong>Remediación:</strong> Rechazar explícitamente el algoritmo "none". Usar RS256 o ES256.',
      'check.jwt.weak.desc': 'Intenta validar la firma HMAC-SHA256 con secretos débiles comunes: <code>secret</code>, <code>password</code>, <code>123456</code>, <code>changeme</code>…',
      'check.jwt.claims.desc': 'Modifica los claims <code>role</code> → admin, <code>is_admin</code> → true, y re-firma con el secreto débil descubierto.',
      'check.basic.brute.desc': 'En endpoints con <code>WWW-Authenticate: Basic</code>, prueba un diccionario de pares user:password comunes.',
      'check.sqli.intro': '4 técnicas en cada parámetro:',
      'check.col.technique': 'Técnica',
      'check.col.detection': 'Detección',
      'check.sqli.timebased.det': 'Retraso ≥ 4s',
      'check.sqli.errorbased.det': 'Mensaje SQL en respuesta',
      'check.sqli.unionbased.det': 'Datos inyectados',
      'check.sqli.booleanbased.det': 'Contenido diferente',
      'check.col.engine': 'Motor',
      'check.col.result': 'Resultado',
      'check.cmdi.detection': 'Detección: retraso (sleep) o presencia de <code>uid=</code> en la respuesta.',
      'check.idor.desc': 'Sustituye los IDs en la URL por valores adyacentes (<code>/users/42</code> → <code>/users/41</code>) o UUIDs aleatorios. Compara las respuestas para detectar acceso a recursos de otros usuarios.',
      'check.bfla.desc': 'Prueba los endpoints <code>/admin/*</code>, <code>/management/*</code>, <code>/internal/*</code> con el token de usuario estándar. Un código 200 indica autorización mal configurada por rol.',
      'check.introspection.desc': 'Si el servidor responde con el esquema completo, la estructura interna queda expuesta a un atacante.',
      'check.depthdos.desc': 'Sin límite de profundidad, el servidor puede sufrir sobrecarga de CPU/memoria.',
      'check.rate.desc': 'Envía 20 solicitudes rápidas y verifica la ausencia de respuesta <code>429 Too Many Requests</code>. Sin rate limiting, login/OTP/reset son vulnerables a fuerza bruta.',
      'check.race.desc': 'Envía simultáneamente 10 solicitudes idénticas (compra, reserva, cupón) y detecta si varias responden con éxito cuando solo una debería.',
      // Infra table
      'infra.col.check': 'Verificación',
      'infra.col.severity': 'Severidad',
      'infra.col.desc': 'Descripción',
      'infra.cors.desc': '<code>Origin: evil.com</code> reflejado en la respuesta',
      'infra.hsts.desc': 'Sin <code>Strict-Transport-Security</code> en HTTPS',
      'infra.hsts.name': 'HSTS ausente',
      'infra.secheaders.desc': 'X-Content-Type-Options, X-Frame-Options, X-XSS-Protection',
      'infra.secheaders.name': 'Cabeceras de seguridad',
      'infra.server.desc': 'Cabecera <code>Server:</code> exponiendo la versión exacta',
      'infra.server.name': 'Divulgación del servidor',
      'infra.csp.desc': 'Ausente o permisiva (unsafe-inline, *)',
      'infra.cookie.desc': 'Faltan Secure, HttpOnly, SameSite',
      'infra.tls.desc': 'TLS 1.0 / 1.1 aceptado (RFC 8996)',
      'infra.tls.name': 'TLS obsoleto',
      'infra.secrets.desc': 'Claves AWS, tokens GitHub, claves PEM…',
      'infra.secrets.name': 'Secretos en respuestas',
      'infra.stacktrace.desc': 'NullPointerException, Traceback… en errores',
      'cicd.tab.best': 'Buenas prácticas',
      // Footer
      'footer.text': 'Nevelio v0.6 — API Security Scanner | nevelio-hw v0.5.0 — Hardware Security — Solo uso autorizado',
      // Hardware extension
      'nav.hardware': 'Extensión Hardware',
      'nav.hw.modules': '↳ Módulos',
      'nav.hw.python': '↳ Herramientas Python',
      'nav.hw.quickstart': '↳ Inicio rápido',
      'hw.title': 'Extensión de Seguridad Hardware — nevelio-hw',
      'hw.desc': 'Junto al escáner de API (capa 7), <strong>nevelio-hw</strong> audita vulnerabilidades a nivel hardware, firmware, kernel y canales auxiliares.<br>Versión actual: <strong>v0.5.0</strong> — 72/85 tareas — 50 tests — 9 crates.',
      'hw.quickstart.title': 'Inicio rápido',
      'hw.modules.title': 'Módulos (9 crates)',
      'hw.col.coverage': 'Cobertura',
      'hw.col.severity': 'Severidad máx.',
      'hw.python.title': 'Herramientas Python',
      'hw.col.usage': 'Uso',
      'hw.mod.cpu': 'Spectre, Meltdown, Retbleed, TAA, MDS, microcódigo, NX/SMEP/SMAP',
      'hw.mod.firmware': 'Secure Boot UEFI, flashrom, actualizaciones BIOS/LVFS',
      'hw.mod.dma': 'IOMMU/VT-d, nivel de seguridad Thunderbolt, PCIe',
      'hw.mod.side': 'Oráculo de timing HTTP (RDTSC), Flush+Reload caché L3, AES-NI',
      'hw.mod.jtag': 'Sondas JTAG/UART, STM32 RDP Level 0, firmware (binwalk + angr)',
      'hw.mod.memory': 'Rowhammer, ECC/TRR, swap+KASLR, Volatility forensics (DKOM, malfind)',
      'hw.mod.fpga': 'IOMMU modo estricto, Thunderbolt, leechcore FFI, Verilog PCIe TLP',
      'hw.py.firmware': 'binwalk + strings (7 patrones) + r2pipe ELF + angr (funciones peligrosas)',
      'hw.py.volatility': 'pslist vs psscan (DKOM), malfind, hashdump, check_syscall (hooks rootkit)',
      'hw.py.cw': 'Adquisición de trazas CW Nano/Lite/Pro — modo <code>--simulate</code> sin hardware',
      'hw.py.cpa': 'CPA AES-128 (Pearson), TVLA Welch/SCALib, visualización matplotlib PNG',
      'hw.legal.title': 'Solo uso autorizado.',
      'hw.legal.desc': 'Ver <a href="../hardware/LEGAL.md"><code>hardware/LEGAL.md</code></a> — Código Penal 323-1/323-8, NIS2, CFAA. Auditar sin autorización escrita es ilegal. Las pruebas activas (Rowhammer, volcado RAM) deben realizarse en máquinas de laboratorio dedicadas.',
      'hw.docs.link': 'Documentación completa:',
      'hw.install.link': 'Instalación:',
    },
  };

  let currentLang = 'fr';

  function rebuildSearchIndex() {
    searchData.length = 0;
    document.querySelectorAll('.doc-section').forEach(section => {
      const title = section.querySelector('h2')?.textContent?.trim() || '';
      const sectionId = section.id;
      section.querySelectorAll('h3, h4').forEach(h => {
        searchData.push({ title: h.textContent.trim(), section: title, id: h.id || sectionId, preview: '' });
      });
      section.querySelectorAll('p').forEach(p => {
        const text = p.textContent.trim();
        if (text.length > 20) {
          searchData.push({ title, section: title, id: sectionId, preview: text.slice(0, 80) + '…' });
        }
      });
    });
  }

  function applyLang(locale) {
    if (!TRANSLATIONS[locale]) locale = 'fr';
    currentLang = locale;
    document.documentElement.lang = locale;
    localStorage.setItem('nevelio-lang', locale);
    document.querySelectorAll('.lang-btn').forEach(b => b.classList.toggle('active', b.dataset.lang === locale));
    const t = TRANSLATIONS[locale];
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.dataset.i18n;
      if (!t[key]) return;
      if (el.dataset.i18nHtml) {
        el.innerHTML = t[key];
      } else {
        el.textContent = t[key];
      }
    });
    document.querySelectorAll('[data-i18n-attr]').forEach(el => {
      el.dataset.i18nAttr.split(' ').forEach(pair => {
        const [attr, key] = pair.split(':');
        if (t[key]) el.setAttribute(attr, t[key]);
      });
    });
    rebuildSearchIndex();
  }

  // ── Highlight.js ──────────────────────────────────────────────────────
  hljs.highlightAll();

  // ── Theme toggle ─────────────────────────────────────────────────────
  const root = document.documentElement;

  function toggleTheme() {
    const isDark = root.getAttribute('data-theme') === 'dark';
    root.setAttribute('data-theme', isDark ? 'light' : 'dark');
    document.getElementById('hljs-theme').href = isDark
      ? 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css'
      : 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css';
    localStorage.setItem('nevelio-theme', isDark ? 'light' : 'dark');
  }

  // Restore saved theme
  const savedTheme = localStorage.getItem('nevelio-theme');
  if (savedTheme && savedTheme !== 'dark') {
    root.setAttribute('data-theme', 'light');
    document.getElementById('hljs-theme').href =
      'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css';
  }

  // ── Sidebar toggle (mobile) ───────────────────────────────────────────
  function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
  }

  // Close sidebar on nav link click (mobile)
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => {
      document.getElementById('sidebar').classList.remove('open');
    });
  });

  // ── Accordion ─────────────────────────────────────────────────────────
  function toggleCheck(header) {
    const body = header.nextElementSibling;
    const isOpen = header.classList.contains('open');
    header.classList.toggle('open', !isOpen);
    body.classList.toggle('open', !isOpen);
  }

  // ── Tabs ──────────────────────────────────────────────────────────────
  function switchTab(btn, panelId) {
    const tabList = btn.closest('.tab-list, .tab-bar');
    const tabs = btn.closest('.tabs, .tab-group');

    tabList.querySelectorAll('.tab-btn, .tab').forEach(b => b.classList.remove('active'));
    tabs.querySelectorAll('.tab-panel, .tab-content').forEach(p => p.classList.remove('active'));

    btn.classList.add('active');
    document.getElementById(panelId).classList.add('active');
  }

  // ── Copy button ───────────────────────────────────────────────────────
  function copyCode(btn) {
    const pre = btn.closest('.code-block').querySelector('pre');
    navigator.clipboard.writeText(pre.innerText).then(() => {
      const t = TRANSLATIONS[currentLang] || TRANSLATIONS.fr;
      btn.textContent = t['copy.done'] || '✓ Copié';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = t['copy.btn'] || 'Copier';
        btn.classList.remove('copied');
      }, 2000);
    });
  }

  // ── Active nav link on scroll ─────────────────────────────────────────
  const sections = document.querySelectorAll('.doc-section, #hero');
  const navLinks = document.querySelectorAll('.nav-link[href^="#"]');

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        navLinks.forEach(link => {
          link.classList.toggle('active', link.getAttribute('href') === '#' + id);
        });
      }
    });
  }, { rootMargin: '-10% 0px -80% 0px' });

  sections.forEach(s => observer.observe(s));

  // ── Search ────────────────────────────────────────────────────────────
  const searchData = [];
  const searchInput = document.getElementById('searchInput');
  const searchResults = document.getElementById('searchResults');

  rebuildSearchIndex();

  searchInput.addEventListener('input', () => {
    const q = searchInput.value.trim().toLowerCase();
    if (!q) { searchResults.classList.remove('visible'); return; }

    const hits = searchData.filter(d =>
      d.title.toLowerCase().includes(q) || d.preview.toLowerCase().includes(q)
    ).slice(0, 8);

    const t = TRANSLATIONS[currentLang] || TRANSLATIONS.fr;
    if (!hits.length) {
      searchResults.innerHTML = `<div class="search-result-item" style="color:var(--text-muted)">${t['search.no-results'] || 'Aucun résultat'}</div>`;
    } else {
      searchResults.innerHTML = hits.map(h => `
        <a class="search-result-item" href="#${h.id}" onclick="searchResults.classList.remove('visible');searchInput.value=''">
          <div class="search-result-title">${highlight(h.title, q)}</div>
          <div class="search-result-section">${h.section}</div>
          ${h.preview ? `<div class="search-result-preview">${highlight(h.preview, q)}</div>` : ''}
        </a>
      `).join('');
    }
    searchResults.classList.add('visible');
  });

  function highlight(text, q) {
    const re = new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return text.replace(re, '<mark>$1</mark>');
  }

  document.addEventListener('click', e => {
    if (!e.target.closest('#searchResults') && !e.target.closest('.header-search')) {
      searchResults.classList.remove('visible');
    }
  });

  searchInput.addEventListener('keydown', e => {
    if (e.key === 'Escape') { searchResults.classList.remove('visible'); searchInput.value = ''; }
  });

  // ── Language init ─────────────────────────────────────────────────────
  currentLang = (function () {
    const saved = localStorage.getItem('nevelio-lang');
    if (saved && TRANSLATIONS[saved]) return saved;
    const bl = (navigator.language || 'fr').slice(0, 2).toLowerCase();
    return TRANSLATIONS[bl] ? bl : 'fr';
  })();
  applyLang(currentLang);
