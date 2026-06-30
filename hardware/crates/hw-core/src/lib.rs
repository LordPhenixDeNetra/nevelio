//! # hw-core
//!
//! Bibliothèque centrale de Nevelio Hardware Security.
//!
//! Fournit les types communs ([`HardwareFinding`], [`HwSeverity`], [`HwScanContext`]),
//! le trait [`HwModule`] implémenté par chaque module d'audit, et les utilitaires
//! de rapport ([`HwReport`], [`HwHtmlReporter`]).

use serde::{Deserialize, Serialize};
use std::fmt;

mod report;
mod html;
pub use report::{HwReport, HwSummary};
pub use html::HwHtmlReporter;

// ── Contexte de scan ──────────────────────────────────────────────────────────

/// Paramètres transmis à chaque module lors d'un scan.
///
/// Créé par `hw-cli` et passé à [`HwModule::run`].
#[derive(Debug, Clone, Default)]
pub struct HwScanContext {
    /// Si `true`, ignorer les opérations destructives (flashrom, Rowhammer, dump RAM…).
    pub dry_run: bool,
    /// URL ou chemin cible optionnel.
    /// Utilisé par `hw-sidechannel` (timing oracle) et `hw-memory` (dump `.lime`).
    pub target: Option<String>,
    /// Affichage détaillé dans hw-cli.
    pub verbose: bool,
}

// ── Sévérité ──────────────────────────────────────────────────────────────────

/// Niveau de sévérité d'un finding matériel.
///
/// Ordre croissant : `Informative < Low < Medium < High < Critical`.
/// Correspond aux niveaux CVSS v3 et aux conventions nevelio.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HwSeverity {
    Informative,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for HwSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical    => write!(f, "CRITICAL"),
            Self::High        => write!(f, "HIGH"),
            Self::Medium      => write!(f, "MEDIUM"),
            Self::Low         => write!(f, "LOW"),
            Self::Informative => write!(f, "INFORMATIVE"),
        }
    }
}

// ── Finding ───────────────────────────────────────────────────────────────────

/// Résultat d'un check de sécurité matérielle.
///
/// Chaque module produit un `Vec<HardwareFinding>`. Les findings sont triés
/// par sévérité décroissante avant d'être inclus dans [`HwReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareFinding {
    /// Titre court (≤ 80 caractères).
    pub title:       String,
    /// Description complète avec contexte technique.
    pub description: String,
    /// Niveau de sévérité CVSS.
    pub severity:    HwSeverity,
    /// Identifiant du module source (ex: `"hw-cpu"`, `"hw-memory"`).
    pub module:      String,
    /// Numéro CWE associé, si applicable.
    pub cwe:         Option<u32>,
    /// Score CVSS v3 Base Score.
    pub cvss:        Option<f32>,
    /// Preuve ou données brutes ayant déclenché le finding.
    pub evidence:    String,
    /// Recommandation de remédiation.
    pub remediation: String,
}

impl HardwareFinding {
    /// Construit un nouveau `HardwareFinding`.
    ///
    /// # Exemple
    /// ```
    /// use hw_core::{HardwareFinding, HwSeverity};
    ///
    /// let f = HardwareFinding::new(
    ///     "Secure Boot désactivé",
    ///     "Le Secure Boot UEFI n'est pas actif sur ce système.",
    ///     HwSeverity::High,
    ///     "hw-firmware",
    ///     Some(1326), Some(7.5),
    ///     "mokutil --sb-state: SecureBoot disabled",
    ///     "Activer Secure Boot dans le BIOS/UEFI.",
    /// );
    /// assert_eq!(f.cwe, Some(1326));
    /// ```
    pub fn new(
        title:       impl Into<String>,
        description: impl Into<String>,
        severity:    HwSeverity,
        module:      impl Into<String>,
        cwe:         Option<u32>,
        cvss:        Option<f32>,
        evidence:    impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            title:       title.into(),
            description: description.into(),
            severity,
            module:      module.into(),
            cwe,
            cvss,
            evidence:    evidence.into(),
            remediation: remediation.into(),
        }
    }
}

// ── Trait module ──────────────────────────────────────────────────────────────

/// Trait implémenté par chaque module d'audit hardware.
///
/// Les modules sont découverts et exécutés séquentiellement par `hw-cli`.
/// Chaque module doit être sans état (`Send + Sync`) et ne jamais paniquer.
pub trait HwModule: Send + Sync {
    /// Nom court du module, utilisé pour le filtrage (`--modules hw-cpu,hw-memory`).
    fn name(&self)        -> &'static str;
    /// Description d'une ligne affichée dans `nevelio-hw modules list`.
    fn description(&self) -> &'static str;
    /// Lance l'audit et retourne la liste des findings.
    ///
    /// En cas d'erreur interne, retourner un finding `Informative` plutôt que paniquer.
    fn run(&self, ctx: &HwScanContext) -> Vec<HardwareFinding>;
}

// ── Helpers subprocess ────────────────────────────────────────────────────────

/// Exécute une commande système et retourne sa sortie `stdout`.
///
/// Retourne `None` si le programme n'existe pas ou si l'exécution échoue.
/// Ne propage jamais d'erreur — les modules d'audit ne doivent pas paniquer.
pub fn run_command(program: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Lit un fichier sysfs Linux et retourne son contenu trimmé.
///
/// Retourne `None` si le fichier n'existe pas (non-Linux ou fonctionnalité absente).
pub fn read_sysfs(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(HwSeverity::Critical > HwSeverity::High);
        assert!(HwSeverity::High    > HwSeverity::Medium);
        assert!(HwSeverity::Medium  > HwSeverity::Low);
        assert!(HwSeverity::Low     > HwSeverity::Informative);
    }

    #[test]
    fn finding_display() {
        let f = HardwareFinding::new(
            "Test", "desc", HwSeverity::Critical, "hw-cpu",
            Some(1342), Some(8.1), "evidence", "remediation",
        );
        assert_eq!(f.severity.to_string(), "CRITICAL");
        assert_eq!(f.cwe, Some(1342));
    }

    #[test]
    fn scan_context_defaults() {
        let ctx = HwScanContext::default();
        assert!(!ctx.dry_run);
        assert!(ctx.target.is_none());
    }
}
