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

    // Collect all available scan history (findings-*.json + findings.json)
    let history = collect_scan_history(&dir);
    let html_bytes = build_dashboard_html(&dir, args.findings.as_deref(), &history)
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
    if !history.is_empty() {
        println!("  Historique : {} scan(s) disponible(s)", history.len());
    }
    println!("  Ctrl+C pour arrêter.\n");

    if !args.no_open {
        open_browser(&url);
    }

    // State for serving: HTML + JSON findings for the API endpoint
    let dir = Arc::new(dir);
    loop {
        let (stream, _) = listener.accept().await?;
        let html = Arc::clone(&html);
        let dir = Arc::clone(&dir);
        tokio::spawn(serve_connection(stream, html, dir));
    }
}

// ── Scan history ──────────────────────────────────────────────────────────────

fn collect_scan_history(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();

    // Primary findings.json
    let primary = dir.join("findings.json");
    if primary.exists() {
        files.push(primary);
    }

    // Timestamped snapshots: findings-YYYYMMDD-HHMMSS.json, findings-1.json, etc.
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut extras: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("findings") && n.ends_with(".json") && n != "findings.json")
                    .unwrap_or(false)
            })
            .collect();
        extras.sort();
        files.extend(extras);
    }

    files
}

// ── Dashboard HTML with filters + history + diff ─────────────────────────────

fn build_dashboard_html(
    dir: &Path,
    explicit_findings: Option<&Path>,
    history: &[PathBuf],
) -> Result<Vec<u8>> {
    // Load the primary report
    let json_path = explicit_findings
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| dir.join("findings.json"));

    let report = if json_path.exists() {
        let content = std::fs::read_to_string(&json_path)
            .with_context(|| format!("Fichier introuvable : {}", json_path.display()))?;
        let r: ScanReport = serde_json::from_str(&content).context("Format findings.json invalide")?;
        r
    } else if let Ok(report_html) = std::fs::read(dir.join("report.html")) {
        // Serve pre-generated HTML as-is
        return Ok(report_html);
    } else {
        anyhow::bail!("Aucun fichier findings.json trouvé dans {}", dir.display());
    };

    // Build the enhanced HTML with filters, history, diff
    let base_html = HtmlReporter::generate(&report)?;
    let enhanced = inject_dashboard_features(&base_html, &report, history);
    Ok(enhanced.into_bytes())
}

/// Inject JavaScript-powered filters, history sidebar, and diff view into the HTML report.
fn inject_dashboard_features(html: &str, report: &ScanReport, history: &[PathBuf]) -> String {
    let history_items: String = history
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("scan");
            let label = if i == 0 { format!("{} (actuel)", name) } else { name.to_string() };
            format!(
                r#"<li><a href="/api/history/{}" onclick="loadHistory({}); return false;">{}</a></li>"#,
                i, i, label
            )
        })
        .collect();

    let dashboard_js = format!(
        r#"
<style>
/* ── Dashboard controls ── */
#nevelio-dashboard {{
  position: fixed; top: 0; right: 0; width: 320px; height: 100vh;
  background: #1a1a2e; color: #e0e0e0; padding: 16px; overflow-y: auto;
  font-family: monospace; font-size: 13px; z-index: 9999;
  box-shadow: -4px 0 20px rgba(0,0,0,0.5);
}}
#nevelio-dashboard h3 {{ color: #4fc3f7; margin-top: 0; }}
#nevelio-dashboard select, #nevelio-dashboard input {{
  width: 100%; padding: 4px; margin: 4px 0; background: #2a2a4a;
  color: #e0e0e0; border: 1px solid #4fc3f7; border-radius: 3px;
}}
.nev-btn {{ background: #4fc3f7; color: #000; border: none; padding: 6px 12px;
  cursor: pointer; border-radius: 3px; margin: 4px 2px; width: 48%; }}
.nev-btn:hover {{ background: #29b6f6; }}
#nev-history ul {{ list-style: none; padding: 0; }}
#nev-history a {{ color: #81d4fa; text-decoration: none; font-size: 11px; }}
#nev-stats {{ background: #2a2a4a; padding: 8px; border-radius: 4px; margin: 8px 0; }}
.nev-badge {{ display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin: 1px; }}
.sev-CRITICAL {{ background: #b71c1c; }}
.sev-HIGH {{ background: #e65100; }}
.sev-MEDIUM {{ background: #f57f17; color: #000; }}
.sev-LOW {{ background: #1565c0; }}
.sev-INFORMATIVE {{ background: #37474f; }}
body {{ margin-right: 340px; }}
</style>

<div id="nevelio-dashboard">
  <h3>🛡 Nevelio Dashboard</h3>
  <div id="nev-stats">
    <b>Target:</b> {target}<br>
    <b>Risk:</b> {risk_score} / 10.0 — <span class="nev-badge sev-{risk_label_upper}">{risk_label}</span><br>
    <b>Findings:</b> {total}
    <span class="nev-badge sev-CRITICAL">{critical} CRIT</span>
    <span class="nev-badge sev-HIGH">{high} HIGH</span>
    <span class="nev-badge sev-MEDIUM">{medium} MED</span>
  </div>

  <h4 style="color:#4fc3f7">🔍 Filtres</h4>
  <select id="nev-filter-sev" onchange="applyFilters()">
    <option value="">Toutes les sévérités</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFORMATIVE">Informative</option>
  </select>
  <input type="text" id="nev-filter-module" placeholder="Module (ex: auth, injection...)"
         oninput="applyFilters()">
  <input type="text" id="nev-filter-endpoint" placeholder="Endpoint contient..."
         oninput="applyFilters()">
  <button class="nev-btn" onclick="clearFilters()">✖ Effacer</button>
  <button class="nev-btn" onclick="exportFiltered()">⬇ Export CSV</button>

  <h4 style="color:#4fc3f7">📅 Historique</h4>
  <div id="nev-history">
    {history_items}
  </div>

  <h4 style="color:#4fc3f7">⚡ Actions</h4>
  <button class="nev-btn" onclick="window.print()">🖨 Imprimer</button>
  <button class="nev-btn" onclick="location.reload()">🔄 Recharger</button>
</div>

<script>
// ── Filter engine ──
function applyFilters() {{
  const sev = document.getElementById('nev-filter-sev').value.toLowerCase();
  const mod = document.getElementById('nev-filter-module').value.toLowerCase();
  const ep = document.getElementById('nev-filter-endpoint').value.toLowerCase();

  // Target finding cards/rows — common HTML report patterns
  const rows = document.querySelectorAll(
    '.finding, .finding-card, .finding-row, tr[data-severity], [class*="finding"]'
  );
  let visible = 0;
  rows.forEach(row => {{
    const text = row.textContent.toLowerCase();
    const sevMatch = !sev || text.includes(sev);
    const modMatch = !mod || text.includes(mod);
    const epMatch = !ep || text.includes(ep);
    if (sevMatch && modMatch && epMatch) {{
      row.style.display = '';
      visible++;
    }} else {{
      row.style.display = 'none';
    }}
  }});

  // Fallback: search in all text if no structured elements found
  if (rows.length === 0 && (sev || mod || ep)) {{
    document.querySelectorAll('table tr').forEach(tr => {{
      if (!tr.closest('thead')) {{
        const text = tr.textContent.toLowerCase();
        tr.style.display = (!sev || text.includes(sev)) &&
                           (!mod || text.includes(mod)) &&
                           (!ep || text.includes(ep)) ? '' : 'none';
        visible++;
      }}
    }});
  }}
}}

function clearFilters() {{
  document.getElementById('nev-filter-sev').value = '';
  document.getElementById('nev-filter-module').value = '';
  document.getElementById('nev-filter-endpoint').value = '';
  document.querySelectorAll('.finding, .finding-card, .finding-row, tr').forEach(
    el => el.style.display = ''
  );
}}

function exportFiltered() {{
  const rows = [];
  rows.push(['Severity', 'Module', 'Endpoint', 'Method', 'Title', 'CVSS'].join(','));
  document.querySelectorAll('table tr').forEach(tr => {{
    if (tr.style.display !== 'none' && !tr.closest('thead')) {{
      const cells = [...tr.querySelectorAll('td')].map(td => '"' + td.textContent.trim().replace(/"/g, '""') + '"');
      if (cells.length > 0) rows.push(cells.join(','));
    }}
  }});
  const blob = new Blob([rows.join('\n')], {{type: 'text/csv'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'nevelio-findings.csv';
  a.click();
}}

function loadHistory(idx) {{
  fetch('/api/history/' + idx)
    .then(r => r.json())
    .then(data => {{
      const info = document.getElementById('nev-history-info');
      if (info) {{
        info.textContent = 'Scan #' + idx + ': ' + (data.findings || []).length + ' finding(s)';
      }}
    }})
    .catch(() => {{}});
}}

// Keyboard shortcuts
document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') clearFilters();
  if (e.ctrlKey && e.key === 'f') {{
    e.preventDefault();
    document.getElementById('nev-filter-endpoint').focus();
  }}
}});
</script>
"#,
        target = report.target,
        risk_score = report.summary.risk_score,
        risk_label = report.summary.risk_label,
        risk_label_upper = report.summary.risk_label.to_uppercase(),
        total = report.summary.total,
        critical = report.summary.critical,
        high = report.summary.high,
        medium = report.summary.medium,
        history_items = if history_items.is_empty() {
            "<p style='color:#666'>Aucun historique</p>".to_string()
        } else {
            format!("<ul>{}</ul>", history_items)
        }
    );

    // Inject before </body>
    if let Some(pos) = html.rfind("</body>") {
        let mut result = html[..pos].to_string();
        result.push_str(&dashboard_js);
        result.push_str(&html[pos..]);
        result
    } else {
        format!("{}{}", html, dashboard_js)
    }
}

// ── HTTP server ───────────────────────────────────────────────────────────────

async fn serve_connection(
    mut stream: tokio::net::TcpStream,
    html: Arc<Vec<u8>>,
    dir: Arc<PathBuf>,
) {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let path = parse_request_path(request).to_string();

    // Route: /api/history/<N> → return Nth findings.json as JSON
    if let Some(idx_str) = path.strip_prefix("/api/history/") {
        if let Ok(idx) = idx_str.trim_matches('/').parse::<usize>() {
            let history = collect_scan_history(&dir);
            if let Some(fpath) = history.get(idx) {
                if let Ok(content) = std::fs::read(fpath) {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                        content.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&content).await;
                    return;
                }
            }
        }
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}").await;
        return;
    }

    // Route: /api/findings → return current findings.json
    if path == "/api/findings" {
        let fpath = dir.join("findings.json");
        if let Ok(content) = std::fs::read(&fpath) {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                content.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&content).await;
            return;
        }
    }

    // Route: favicon
    if path.starts_with("/favicon") {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }

    // Default: serve the dashboard HTML
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
