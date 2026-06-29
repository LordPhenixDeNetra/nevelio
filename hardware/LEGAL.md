# Avertissements légaux — Nevelio Hardware Security

> **LIRE ATTENTIVEMENT AVANT TOUTE UTILISATION**
>
> L'utilisation de cet outil sur des systèmes pour lesquels vous n'avez pas
> d'autorisation écrite préalable est **illégale** dans la quasi-totalité des
> juridictions et peut entraîner des poursuites pénales.

---

## 1. Cadre légal français

### Code Pénal — Infractions aux STAD

La loi française protège les systèmes de traitement automatisé de données (STAD)
par les articles **323-1 à 323-8** du Code Pénal (loi Godfrain, modifiée).

| Article | Infraction | Peine maximale |
|---|---|---|
| 323-1 | Accès frauduleux à un système informatique | 3 ans + 100 000 € |
| 323-1 (al. 2) | Accès + suppression ou modification de données | 5 ans + 150 000 € |
| 323-1 (al. 3) | Accès à un STAD d'État ou infrastructure critique | 7 ans + 300 000 € |
| 323-2 | Entrave ou faux dans un STAD | 5 ans + 150 000 € |
| 323-3 | Introduction frauduleuse de données | 5 ans + 150 000 € |
| 323-3-1 | Détention/fourniture d'un outil de piratage | 2 ans + 60 000 € |
| 323-4 | Association de malfaiteurs informatique | Peines aggravées |
| 323-7 | Tentative | Mêmes peines |
| 323-8 | Personne morale | Amende × 5 |

**Un audit de sécurité sans autorisation écrite de l'organisation cible constitue**
**une infraction aux articles 323-1 à 323-3.**

### Agences de référence (France)

- **ANSSI** (Agence nationale de la sécurité des systèmes d'information) — [ssi.gouv.fr](https://www.ssi.gouv.fr)
- Pour les organismes d'importance vitale (OIV) : règlement SAIV, article L1332-6-1 du Code de la défense.

---

## 2. Droit européen

### NIS2 (Directive 2022/2555)

La directive NIS2 (Network and Information Security), transposée en droit national
des États membres avant octobre 2024, impose :
- Des obligations de sécurité aux entités essentielles et importantes.
- Le signalement des incidents majeurs sous 24h (alerte précoce) et 72h (rapport).
- Des sanctions pouvant atteindre **10 M€ ou 2% du CA mondial** (entités essentielles).

Les tests de pénétration **doivent être autorisés** et documentés dans le cadre d'un
programme de gestion des risques formel (Art. 21 NIS2).

### Cyber Resilience Act (CRA — Règlement UE 2024/2847)

Le CRA impose aux fabricants de produits numériques (firmware, IoT, matériel connecté) :
- Des exigences de cybersécurité par conception (security by design).
- La mise à disposition de mises à jour de sécurité pendant la durée de vie du produit.
- La déclaration des vulnérabilités activement exploitées sous **24h** à l'ENISA et autorité nationale.

L'utilisation de cet outil dans le cadre d'une évaluation CRA requiert un accord formel
avec le fabricant.

### RGPD (Règlement 2016/679)

- **Article 32** : obligation de mettre en place des mesures techniques de sécurité.
- **Article 35** : analyse d'impact (DPIA) requise pour les traitements à haut risque.
- Un audit qui accède à des données personnelles (RAM dump, logs, fichiers de config)
  doit être couvert par un DPA (Data Processing Agreement) ou une DPIA.

---

## 3. Droit américain

### CFAA (Computer Fraud and Abuse Act — 18 U.S.C. § 1030)

Le CFAA interdit l'accès non autorisé à un système protégé. Les peines incluent :
- Jusqu'à **10 ans** de prison pour une première infraction intentionnelle.
- Jusqu'à **20 ans** en cas de récidive ou d'atteinte à l'infrastructure critique.
- **Responsabilité civile** : les victimes peuvent poursuivre en dommages et intérêts.

La notion d'« autorisation » est interprétée strictement — un accord verbal
ne suffit pas. Un pentest contract signé est indispensable.

### ECPA (Electronic Communications Privacy Act — 18 U.S.C. § 2511)

Protège les communications électroniques contre l'interception non autorisée.
Les dumps mémoire capturant des communications en cours peuvent tomber sous le ECPA.

### Législations étatiques

Plusieurs États (Californie CCPA, New York SHIELD Act, Texas Penal Code 33.01…)
ajoutent des niveaux de protection supplémentaires.

---

## 4. Usages autorisés

L'utilisation de `nevelio-hw` est légale et éthique dans les cas suivants :

**✅ Autorisé :**
- Tests sur des systèmes dont vous êtes le propriétaire ou l'administrateur désigné.
- Pentest contractualisé avec autorisation écrite signée (scope, durée, périmètre).
- Recherche en sécurité en laboratoire isolé (machines dédiées, sans données de production).
- Compétitions CTF (Capture The Flag) sur l'infrastructure officielle.
- Formation en cybersécurité sur des VMs ou matériels dédiés à cet effet.
- Bug Bounty dans le périmètre explicitement défini par le programme.
- Audit interne mandaté par la direction avec lettre de mission.

**❌ Interdit :**
- Test sur des systèmes tiers sans autorisation écrite.
- Utilisation en production sans arrêt préalable des services affectés.
- Collecte ou exfiltration de données personnelles sans DPA/DPIA.
- Tests Rowhammer sur machines partagées, en production ou avec données sensibles.
- Utilisation pour nuire, espionner, ou compromettre des tiers.
- Contournement de mesures de sécurité à des fins autres que l'audit autorisé.

---

## 5. Modèle de lettre d'autorisation (template)

```
AUTORISATION D'AUDIT DE SÉCURITÉ MATÉRIELLE

Entre :
  [Nom de l'organisation], représentée par [Prénom Nom], [Fonction],
  ci-après dénommée « le Client »,

Et :
  [Prestataire], ci-après dénommé « l'Auditeur »,

Il est convenu ce qui suit :

1. PÉRIMÈTRE : L'Auditeur est autorisé à effectuer des tests de sécurité
   sur les systèmes suivants : [liste des systèmes, adresses IP, matériels].

2. DURÉE : Du [date début] au [date fin].

3. MÉTHODES AUTORISÉES : Analyse passive, dump mémoire (sur machines de
   test dédiées uniquement), test JTAG, analyse firmware.

4. EXCLUSIONS : [liste des systèmes exclus, environnements de production].

5. CONFIDENTIALITÉ : Les résultats de l'audit sont confidentiels et destinés
   exclusivement au Client.

6. PROPRIÉTÉ : Toutes les données collectées sont la propriété du Client
   et doivent être détruites à l'issue de l'audit.

Fait à [ville], le [date].

Signature Client :                    Signature Auditeur :
```

---

## 6. Disclaimer de l'outil

Nevelio Hardware Security (`nevelio-hw`) est fourni **tel quel**, à des fins
éducatives et d'audit de sécurité autorisé.

Les auteurs et contributeurs déclinent toute responsabilité pour :
- Toute utilisation en dehors du cadre légal décrit ci-dessus.
- Tout dommage matériel causé par les tests actifs (Rowhammer, flashrom, etc.).
- Toute conséquence découlant d'une utilisation non autorisée.

**En lançant cet outil, vous attestez avoir lu et accepté ces conditions,**
**disposer des autorisations nécessaires, et assumer l'entière responsabilité**
**de votre usage.**

---

## 7. Signalement de vulnérabilités (Responsible Disclosure)

Si vous découvrez une vulnérabilité dans un produit tiers au cours d'un audit :
- **France** : signalement via le dispositif ANSSI ou le CERT-FR ([cert.ssi.gouv.fr](https://www.cert.ssi.gouv.fr)).
- **UE** : notifier l'ENISA et l'autorité compétente selon NIS2 Art. 23.
- **USA** : CISA Coordinated Vulnerability Disclosure ([cisa.gov/report](https://www.cisa.gov/report)).
- **Fabricant** : contacter l'équipe PSIRT du fabricant concerné.

Ne publiez pas de preuve de concept (PoC) avant la mise à disposition d'un correctif
(délai de grâce standard : **90 jours**).
