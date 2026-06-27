use anyhow::{Context, Result};
use colored::Colorize;
use nevelio_reporting::{HtmlReporter, ScanReport};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::args::ServeArgs;

pub async fn handle_serve(args: ServeArgs) -> Result<()> {
    let dir = args.dir.unwrap_or_else(|| PathBuf::from("./nevelio-results"));
    let port = args.port;

    let html_bytes = load_or_generate_html(&dir, args.findings.as_deref())
        .context("Impossible de charger le rapport")?;
    let html = Arc::new(html_bytes);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Port {} déjà utilisé ou accès refusé.", port))?;

    let url = format!("http://127.0.0.1:{}", port);
    println!();
    println!(
        "  {}  {}",
        "Dashboard Nevelio →".bold(),
        url.cyan().bold()
    );
    println!("  Ctrl+C pour arrêter.\n");

    if !args.no_open {
        open_browser(&url);
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let html = Arc::clone(&html);
        tokio::spawn(serve_connection(stream, html));
    }
}

// ── Loaders ───────────────────────────────────────────────────────────────────

fn load_or_generate_html(dir: &Path, findings: Option<&Path>) -> Result<Vec<u8>> {
    // Use pre-generated HTML if available
    let html_path = dir.join("report.html");
    if html_path.exists() {
        return Ok(std::fs::read(&html_path)?);
    }

    // Generate from findings.json
    let json_path = findings
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| dir.join("findings.json"));

    let content = std::fs::read_to_string(&json_path)
        .with_context(|| format!("Fichier introuvable : {}", json_path.display()))?;
    let report: ScanReport =
        serde_json::from_str(&content).context("Format findings.json invalide")?;

    let html = HtmlReporter::generate(&report)?;
    Ok(html.into_bytes())
}

// ── HTTP server ───────────────────────────────────────────────────────────────

async fn serve_connection(mut stream: tokio::net::TcpStream, html: Arc<Vec<u8>>) {
    let mut buf = [0u8; 4096];
    let _ = stream.read(&mut buf).await;

    let request = std::str::from_utf8(&buf).unwrap_or("");
    let path = parse_request_path(request);

    if path.starts_with("/favicon") {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        html.len()
    );
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(&html).await;
}

fn parse_request_path(request: &str) -> &str {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
}

// ── Browser ───────────────────────────────────────────────────────────────────

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", url])
        .spawn();
}
