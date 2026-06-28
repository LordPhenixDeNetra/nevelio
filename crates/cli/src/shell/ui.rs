use colored::Colorize;

use super::ShellCtx;

pub(super) fn print_banner() {
    println!();
    println!("{}", "  ╔══════════════════════════════════════════════╗".cyan());
    println!("{}", "  ║        Nevelio — Shell Interactif             ║".cyan());
    println!("{}", "  ╚══════════════════════════════════════════════╝".cyan());
    println!("  Tapez {} pour les commandes, {} pour quitter.\n", "help".bold(), "quit".bold());
}

pub(super) fn print_help() {
    println!();
    println!("  {}", "Commandes disponibles :".bold());
    println!();
    let cmds = [
        ("target <url>", "Définir la cible (ou afficher la cible actuelle)"),
        ("spec <path>",  "Définir le fichier spec (OpenAPI/Postman/HAR)"),
        ("token <token>","Définir le token d'authentification"),
        ("scan",         "Lancer un scan complet sur la cible"),
        ("list",         "Lister les endpoints découverts"),
        ("show <N>",     "Détails de l'endpoint numéro N"),
        ("findings",     "Afficher les findings du dernier scan"),
        ("replay <N>",   "Rejouer la requête vers l'endpoint N"),
        ("export",       "Exporter les findings en JSON"),
        ("clear",        "Effacer la session (endpoints + findings)"),
        ("status",       "Afficher l'état de la session"),
        ("help",         "Afficher cette aide"),
        ("quit",         "Quitter le shell"),
    ];
    for (cmd, desc) in cmds {
        println!("  {:<20} {}", cmd.bold(), desc.dimmed());
    }
    println!();
}

pub(super) fn print_status(ctx: &ShellCtx) {
    println!("  Cible    : {}", ctx.target.as_deref().unwrap_or("(non définie)").cyan());
    println!("  Spec     : {}", ctx.spec.as_deref().unwrap_or("(aucune)").dimmed());
    println!("  Token    : {}", if ctx.auth_token.is_some() { "défini" } else { "(aucun)" });
    println!("  Endpoints: {}", ctx.endpoints.len());
    println!("  Findings : {}", ctx.findings.len());
    println!("  Out dir  : {}", ctx.out_dir.display().to_string().dimmed());
}
