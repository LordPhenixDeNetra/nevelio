use std::io;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;
use rust_i18n::t;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};

use nevelio_core::types::{Finding, Severity};

/// Events sent from the async scan loop to the blocking TUI thread.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ScanEvent {
    ModuleStarted { name: String },
    ModuleFinished { name: String },
    FindingFound(Box<Finding>),
    EndpointScanned { total: usize, done: usize },
    ScanComplete,
    Error(String),
}

struct ModuleState {
    name: String,
    done: bool,
}

struct TuiApp {
    modules: Vec<ModuleState>,
    findings: Vec<Finding>,
    endpoints_total: usize,
    endpoints_done: usize,
    start: Instant,
    done: bool,
    last_error: Option<String>,
}

impl TuiApp {
    fn new(module_names: &[String]) -> Self {
        Self {
            modules: module_names
                .iter()
                .map(|n| ModuleState { name: n.clone(), done: false })
                .collect(),
            findings: Vec::new(),
            endpoints_total: 0,
            endpoints_done: 0,
            start: Instant::now(),
            done: false,
            last_error: None,
        }
    }

    fn apply(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::ModuleStarted { .. } => {}
            ScanEvent::ModuleFinished { name } => {
                if let Some(m) = self.modules.iter_mut().find(|m| m.name == name) {
                    m.done = true;
                }
            }
            ScanEvent::FindingFound(f) => self.findings.push(*f),
            ScanEvent::EndpointScanned { total, done } => {
                self.endpoints_total = total;
                self.endpoints_done = done;
            }
            ScanEvent::ScanComplete => self.done = true,
            ScanEvent::Error(e) => self.last_error = Some(e),
        }
    }

    fn severity_counts(&self) -> (usize, usize, usize, usize, usize) {
        let c = self.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let h = self.findings.iter().filter(|f| f.severity == Severity::High).count();
        let m = self.findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let l = self.findings.iter().filter(|f| f.severity == Severity::Low).count();
        let i = self.findings.iter().filter(|f| f.severity == Severity::Informative).count();
        (c, h, m, l, i)
    }
}

fn severity_color(s: &Severity) -> Color {
    match s {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Green,
        Severity::Informative => Color::Cyan,
    }
}

fn draw(f: &mut Frame, app: &TuiApp) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.area());

    draw_header(f, app, outer[0]);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(outer[1]);

    draw_modules(f, app, main[0]);
    draw_findings(f, app, main[1]);
    draw_footer(f, app, outer[2]);
}

fn draw_header(f: &mut Frame, app: &TuiApp, area: Rect) {
    let elapsed = app.start.elapsed().as_secs();
    let status = if app.done {
        t!("tui.done").to_string()
    } else {
        t!("tui.in_progress", secs = elapsed).to_string()
    };

    let progress = if app.endpoints_total > 0 {
        (app.endpoints_done as f64 / app.endpoints_total as f64).min(1.0)
    } else {
        0.0
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(t!("tui.header_title", count = app.endpoints_total, status = status.as_str()).to_string())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
        .ratio(progress)
        .label(format!("{}/{}", app.endpoints_done, app.endpoints_total));

    f.render_widget(gauge, area);
}

fn draw_modules(f: &mut Frame, app: &TuiApp, area: Rect) {
    let items: Vec<ListItem> = app
        .modules
        .iter()
        .map(|m| {
            let (icon, style) = if m.done {
                ("✓", Style::default().fg(Color::Green))
            } else {
                ("○", Style::default().fg(Color::DarkGray))
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", icon), style),
                Span::raw(m.name.clone()),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(t!("tui.modules_panel").to_string())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    f.render_widget(list, area);
}

fn draw_findings(f: &mut Frame, app: &TuiApp, area: Rect) {
    let header = Row::new(vec![
        Cell::from(t!("tui.col_severity").to_string()).style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from(t!("tui.col_module").to_string()).style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from(t!("tui.col_title").to_string()).style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from(t!("tui.col_endpoint").to_string()).style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = app
        .findings
        .iter()
        .rev()
        .take(50)
        .map(|f| {
            let sev = f.severity.to_string();
            Row::new(vec![
                Cell::from(sev).style(Style::default().fg(severity_color(&f.severity))),
                Cell::from(f.module.as_str()),
                Cell::from(f.title.as_str()),
                Cell::from(f.endpoint.as_str()),
            ])
        })
        .collect();

    let (c, h, m, l, i) = app.severity_counts();
    let title = t!(
        "tui.findings_panel",
        total = app.findings.len(),
        c = c, h = h, m = m, l = l, i = i
    ).to_string();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Min(30),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    f.render_widget(table, area);
}

fn draw_footer(f: &mut Frame, app: &TuiApp, area: Rect) {
    let msg = if let Some(ref err) = app.last_error {
        t!("tui.error", msg = err.as_str()).to_string()
    } else if app.done {
        t!("tui.scan_done").to_string()
    } else {
        t!("tui.cancel").to_string()
    };

    let paragraph = Paragraph::new(msg)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Left);

    f.render_widget(paragraph, area);
}

/// Blocking TUI loop. Run in a std::thread so terminal I/O doesn't block the async executor.
pub fn run_tui_blocking(
    rx: mpsc::Receiver<ScanEvent>,
    module_names: Vec<String>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(&module_names);
    let tick = Duration::from_millis(100);

    loop {
        terminal.draw(|f| draw(f, &app))?;

        // Drain pending scan events (non-blocking)
        loop {
            match rx.try_recv() {
                Ok(ev) => app.apply(ev),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    app.done = true;
                    break;
                }
            }
        }

        // Check keyboard input (non-blocking poll)
        if event::poll(tick)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press
                    && (key.code == KeyCode::Char('q') || key.code == KeyCode::Esc)
                {
                    break;
                }
            }
        }

        // If scan completed, stay until user presses q
        // (loop continues — user sees results and can quit manually)
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
