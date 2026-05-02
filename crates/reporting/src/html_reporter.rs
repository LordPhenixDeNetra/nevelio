use anyhow::{Context, Result};
use chrono::Utc;
use std::path::Path;
use tera::Tera;

use crate::report_types::ScanReport;

const TEMPLATE: &str = include_str!("../templates/report.html");
const CSS: &str = include_str!("../templates/report.css");
const JS: &str = include_str!("../templates/report.js");

pub struct HtmlReporter;

impl HtmlReporter {
    pub fn generate(report: &ScanReport) -> Result<String> {
        let mut tera = Tera::default();
        tera.add_raw_template("report.css", CSS)
            .context("Failed to load CSS template")?;
        tera.add_raw_template("report.js", JS)
            .context("Failed to load JS template")?;
        tera.add_raw_template("report.html", TEMPLATE)
            .context("Failed to load HTML template")?;

        let mut ctx = tera::Context::new();
        ctx.insert("scan", &serde_json::to_value(report)?);
        ctx.insert("generated_at", &Utc::now().format("%Y-%m-%d %H:%M UTC").to_string());

        tera.render("report.html", &ctx)
            .context("Failed to render HTML report")
    }

    pub fn write_to_file(report: &ScanReport, path: &Path) -> Result<()> {
        let html = Self::generate(report)?;
        std::fs::write(path, html)?;
        Ok(())
    }
}
