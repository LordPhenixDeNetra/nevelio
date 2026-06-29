use crate::{HwReport, HwSeverity};

pub struct HwHtmlReporter;

impl HwHtmlReporter {
    pub fn generate(report: &HwReport) -> String {
        let rows = report.findings.iter().enumerate().map(|(i, f)| {
            let sev_class = match f.severity {
                HwSeverity::Critical    => "sev-critical",
                HwSeverity::High        => "sev-high",
                HwSeverity::Medium      => "sev-medium",
                HwSeverity::Low         => "sev-low",
                HwSeverity::Informative => "sev-info",
            };
            let cwe  = f.cwe.map(|c| format!("CWE-{}", c)).unwrap_or_else(|| "—".into());
            let cvss = f.cvss.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "—".into());
            format!(
                r#"<tr>
  <td>{}</td>
  <td><span class="badge {sev_class}">{}</span></td>
  <td class="module">{}</td>
  <td><strong>{}</strong><br><small class="desc">{}</small></td>
  <td class="cwe">{cwe}</td>
  <td>{cvss}</td>
  <td class="remediation">{}</td>
</tr>"#,
                i + 1,
                f.severity,
                f.module,
                escape_html(&f.title),
                escape_html(&f.description),
                escape_html(&f.remediation),
                sev_class = sev_class,
            )
        }).collect::<Vec<_>>().join("\n");

        format!(r#"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nevelio Hardware Security — Rapport</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; padding: 24px; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 4px; color: #58a6ff; }}
  .meta {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }}
  .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 12px 20px; text-align: center; min-width: 90px; }}
  .stat .num {{ font-size: 1.8rem; font-weight: 700; }}
  .stat .lbl {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{ background: #161b22; color: #8b949e; text-transform: uppercase;
        font-size: 0.75rem; padding: 10px 14px; text-align: left;
        border-bottom: 1px solid #30363d; }}
  td {{ padding: 12px 14px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: 0.75rem; font-weight: 600; }}
  .sev-critical {{ background: #6e1b1b; color: #ff7b7b; }}
  .sev-high     {{ background: #4a2000; color: #ffa657; }}
  .sev-medium   {{ background: #3d2c00; color: #e3b341; }}
  .sev-low      {{ background: #0c2a4a; color: #79c0ff; }}
  .sev-info     {{ background: #1c2128; color: #8b949e; }}
  .module {{ color: #58a6ff; font-size: 0.82rem; white-space: nowrap; }}
  .cwe    {{ color: #8b949e; white-space: nowrap; font-size: 0.82rem; }}
  .desc   {{ color: #8b949e; display: block; margin-top: 4px; }}
  .remediation {{ color: #3fb950; font-size: 0.82rem; max-width: 260px; }}
  .no-findings {{ text-align: center; padding: 48px; color: #3fb950; font-size: 1.1rem; }}
</style>
</head>
<body>
<h1>⚙ Nevelio Hardware Security</h1>
<p class="meta">Hôte : <strong>{hostname}</strong> · Généré le : {generated_at}</p>

<div class="summary">
  <div class="stat"><div class="num">{total}</div><div class="lbl">Total</div></div>
  <div class="stat"><div class="num" style="color:#ff7b7b">{critical}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:#ffa657">{high}</div><div class="lbl">High</div></div>
  <div class="stat"><div class="num" style="color:#e3b341">{medium}</div><div class="lbl">Medium</div></div>
  <div class="stat"><div class="num" style="color:#79c0ff">{low}</div><div class="lbl">Low</div></div>
  <div class="stat"><div class="num" style="color:#8b949e">{informative}</div><div class="lbl">Info</div></div>
</div>

{findings_section}

</body>
</html>"#,
            hostname      = escape_html(&report.hostname),
            generated_at  = report.generated_at,
            total         = report.summary.total,
            critical      = report.summary.critical,
            high          = report.summary.high,
            medium        = report.summary.medium,
            low           = report.summary.low,
            informative   = report.summary.informative,
            findings_section = if report.findings.is_empty() {
                r#"<div class="no-findings">✓ Aucun finding détecté — système correctement configuré.</div>"#.to_string()
            } else {
                format!(r#"<table>
<thead><tr>
  <th>#</th><th>Sévérité</th><th>Module</th><th>Finding</th>
  <th>CWE</th><th>CVSS</th><th>Remédiation</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>"#)
            },
        )
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}
