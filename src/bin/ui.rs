use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::Semaphore;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use sni_spoof_rs::config::{self, Config, ListenerConfig};
use sni_spoof_rs::scan::{self, ProbeOutcome, ProbeResult};
use sni_spoof_rs::{platform_privilege_hint, start_proxy, xray, RunningProxy};

const LOG_MAX: usize = 300;
const RESULT_MAX: usize = 800;
const STATE_FILE: &str = "sni-spoof-rs-ui-state.json";
#[cfg(windows)]
const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

fn main() -> eframe::Result<()> {
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "-h" || arg == "--help")
    {
        println!("sni-spoof-rs-ui -- native desktop UI for sni-spoof-rs");
        println!();
        println!("USAGE:");
        println!("  sni-spoof-rs-ui");
        return Ok(());
    }

    let log = UiLog::default();
    install_ui_tracing(log.clone());

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 860.0])
            .with_min_inner_size([720.0, 620.0])
            .with_title(format!("sni-spoof-rs {}", env!("CARGO_PKG_VERSION"))),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "sni-spoof-rs",
        options,
        Box::new(move |cc| {
            let initial_light_mode = load_ui_state()
                .map(|state| state.light_mode)
                .unwrap_or(true);
            apply_theme(&cc.egui_ctx, initial_light_mode);
            Ok(Box::new(App::new(log)))
        }),
    )
}

#[derive(Clone)]
struct UiLog {
    lines: Arc<Mutex<VecDeque<String>>>,
    revision: Arc<AtomicU64>,
    enabled: Arc<AtomicBool>,
}

impl Default for UiLog {
    fn default() -> Self {
        Self {
            lines: Arc::new(Mutex::new(VecDeque::new())),
            revision: Arc::new(AtomicU64::new(0)),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl UiLog {
    fn push(&self, line: impl Into<String>) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let mut lines = self.lines.lock().unwrap();
        lines.push_back(line.into());
        while lines.len() > LOG_MAX {
            lines.pop_front();
        }
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<String> {
        self.lines.lock().unwrap().iter().cloned().collect()
    }

    fn restore(&self, restored: Vec<String>) {
        let mut lines = self.lines.lock().unwrap();
        *lines = restored.into_iter().rev().take(LOG_MAX).collect();
        lines.make_contiguous().reverse();
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    fn clear(&self) {
        self.lines.lock().unwrap().clear();
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.clear();
        }
    }

    fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
struct LogMakeWriter {
    log: UiLog,
}

struct LogWriter {
    log: UiLog,
}

impl<'a> MakeWriter<'a> for LogMakeWriter {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter {
            log: self.log.clone(),
        }
    }
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            self.log.push(line.to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn install_ui_tracing(log: UiLog) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(LogMakeWriter { log })
        .with_ansi(false)
        .try_init();
}

fn apply_theme(ctx: &egui::Context, light_mode: bool) {
    let mut visuals = if light_mode {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };

    if light_mode {
        visuals.panel_fill = egui::Color32::from_rgb(246, 248, 252);
        visuals.window_fill = egui::Color32::from_rgb(255, 255, 255);
        visuals.extreme_bg_color = egui::Color32::from_rgb(232, 238, 247);
        visuals.faint_bg_color = egui::Color32::from_rgb(239, 244, 250);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(239, 244, 250);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(225, 237, 255);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(209, 228, 255);
        visuals.selection.bg_fill = egui::Color32::from_rgb(47, 111, 237);
        visuals.hyperlink_color = egui::Color32::from_rgb(28, 100, 242);
    } else {
        visuals.panel_fill = egui::Color32::from_rgb(6, 6, 7);
        visuals.window_fill = egui::Color32::from_rgb(10, 10, 11);
        visuals.extreme_bg_color = egui::Color32::from_rgb(0, 0, 0);
        visuals.faint_bg_color = egui::Color32::from_rgb(22, 16, 17);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(18, 18, 19);
        visuals.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(244, 238, 238);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(45, 18, 20);
        visuals.widgets.hovered.fg_stroke.color = egui::Color32::from_rgb(255, 246, 246);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(83, 20, 24);
        visuals.widgets.active.fg_stroke.color = egui::Color32::from_rgb(255, 250, 250);
        visuals.selection.bg_fill = egui::Color32::from_rgb(185, 28, 28);
        visuals.hyperlink_color = egui::Color32::from_rgb(248, 113, 113);
    }

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    ctx.set_style(style);
}

#[derive(Clone, Copy)]
struct Palette {
    panel_fill: egui::Color32,
    top_fill: egui::Color32,
    section_fill: egui::Color32,
    border: egui::Color32,
    text: egui::Color32,
    muted: egui::Color32,
    neutral_fill: egui::Color32,
    neutral_text: egui::Color32,
    success_fill: egui::Color32,
    primary_fill: egui::Color32,
    danger_fill: egui::Color32,
    warning_fill: egui::Color32,
    stopped_fill: egui::Color32,
}

fn palette(light_mode: bool) -> Palette {
    if light_mode {
        Palette {
            panel_fill: egui::Color32::from_rgb(246, 248, 252),
            top_fill: egui::Color32::from_rgb(245, 249, 255),
            section_fill: egui::Color32::from_rgb(255, 255, 255),
            border: egui::Color32::from_rgb(219, 226, 236),
            text: egui::Color32::from_rgb(22, 33, 54),
            muted: egui::Color32::from_rgb(88, 99, 118),
            neutral_fill: egui::Color32::from_rgb(231, 237, 247),
            neutral_text: egui::Color32::from_rgb(39, 52, 75),
            success_fill: egui::Color32::from_rgb(25, 135, 84),
            primary_fill: egui::Color32::from_rgb(47, 111, 237),
            danger_fill: egui::Color32::from_rgb(214, 51, 72),
            warning_fill: egui::Color32::from_rgb(245, 124, 0),
            stopped_fill: egui::Color32::from_rgb(120, 132, 150),
        }
    } else {
        Palette {
            panel_fill: egui::Color32::from_rgb(6, 6, 7),
            top_fill: egui::Color32::from_rgb(10, 10, 11),
            section_fill: egui::Color32::from_rgb(15, 15, 16),
            border: egui::Color32::from_rgb(83, 24, 28),
            text: egui::Color32::from_rgb(250, 250, 250),
            muted: egui::Color32::from_rgb(214, 203, 203),
            neutral_fill: egui::Color32::from_rgb(31, 31, 33),
            neutral_text: egui::Color32::from_rgb(244, 238, 238),
            success_fill: egui::Color32::from_rgb(153, 27, 27),
            primary_fill: egui::Color32::from_rgb(185, 28, 28),
            danger_fill: egui::Color32::from_rgb(220, 38, 38),
            warning_fill: egui::Color32::from_rgb(127, 29, 29),
            stopped_fill: egui::Color32::from_rgb(64, 64, 64),
        }
    }
}

fn section_frame(palette: Palette) -> egui::Frame {
    egui::Frame::group(&egui::Style::default())
        .fill(palette.section_fill)
        .stroke(egui::Stroke::new(1.0_f32, palette.border))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(14.0))
}

fn section_header(ui: &mut egui::Ui, title: &str, accent: egui::Color32, palette: Palette) {
    ui.horizontal(|ui| {
        egui::Frame::default()
            .fill(accent)
            .rounding(egui::Rounding::same(3.0))
            .inner_margin(egui::Margin::symmetric(3.0, 10.0))
            .show(ui, |_| {});
        ui.heading(egui::RichText::new(title).color(palette.text));
    });
}

fn status_pill(ui: &mut egui::Ui, text: &str, fill: egui::Color32) {
    egui::Frame::default()
        .fill(fill)
        .rounding(egui::Rounding::same(999.0))
        .inner_margin(egui::Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(text)
                    .color(egui::Color32::WHITE)
                    .strong(),
            );
        });
}

fn filled_button(text: &str, fill: egui::Color32) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(egui::Color32::WHITE)
            .strong(),
    )
    .fill(fill)
}

fn neutral_button(text: &str, palette: Palette) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(text).color(palette.neutral_text))
        .fill(palette.neutral_fill)
}

struct App {
    form: FormState,
    proxy: Option<RunningProxy>,
    xray: Option<XrayRuntime>,
    log: UiLog,
    status: String,
    import_text: String,
    selected_import: usize,
    xray_path: String,
    xray_http_listen: String,
    xray_socks_listen: String,
    xray_tun_enabled: bool,
    xray_log_level: String,
    xray_rx: Option<Receiver<XrayMsg>>,
    ip_check_rx: Option<Receiver<IpCheckMsg>>,
    connection_status: ConnectionStatus,
    logging_enabled: bool,
    light_mode: bool,
    scan_target: String,
    scan_timeout_secs: String,
    scan_concurrency: String,
    scan_rx: Option<Receiver<ScanMsg>>,
    scan_started: Option<Instant>,
    scan_total: usize,
    scan_done: usize,
    scan_ok: usize,
    scan_results: Vec<ProbeResult>,
    saved_log_revision: u64,
    last_auto_save: Instant,
}

impl App {
    fn new(log: UiLog) -> Self {
        let saved = load_ui_state();
        let logging_enabled = saved
            .as_ref()
            .map(|state| state.logging_enabled)
            .unwrap_or(true);
        log.set_enabled(logging_enabled);
        if logging_enabled {
            if let Some(state) = &saved {
                log.restore(state.log_lines.clone());
            }
        }
        let cfg = config::load("config.json").unwrap_or_default();
        let form = saved
            .as_ref()
            .map(|state| state.form.clone())
            .unwrap_or_else(|| FormState::from_config(&cfg));
        let xray_path = saved
            .as_ref()
            .map(|state| state.xray_path.clone())
            .filter(|path| {
                let trimmed = path.trim();
                !trimmed.is_empty() && Path::new(trimmed).exists()
            })
            .unwrap_or_else(default_xray_path);
        let scan_target = saved
            .as_ref()
            .map(|state| state.scan_target.clone())
            .filter(|target| !target.trim().is_empty())
            .unwrap_or_else(|| form.connect.clone());
        let saved_log_revision = log.revision();
        Self {
            scan_target,
            form,
            proxy: None,
            xray: None,
            log,
            status: format!("Ready. {}", platform_privilege_hint()),
            import_text: saved
                .as_ref()
                .map(|state| state.import_text.clone())
                .unwrap_or_default(),
            selected_import: saved
                .as_ref()
                .map(|state| state.selected_import)
                .unwrap_or_default(),
            xray_path,
            xray_http_listen: saved
                .as_ref()
                .map(|state| state.xray_http_listen.clone())
                .filter(|listen| !listen.trim().is_empty())
                .unwrap_or_else(|| "127.0.0.1:1080".into()),
            xray_socks_listen: saved
                .as_ref()
                .and_then(|state| state.xray_socks_listen.clone())
                .filter(|listen| !listen.trim().is_empty())
                .unwrap_or_else(|| "127.0.0.1:1081".into()),
            xray_tun_enabled: saved
                .as_ref()
                .map(|state| state.xray_tun_enabled)
                .unwrap_or(false),
            xray_log_level: saved
                .as_ref()
                .map(|state| state.xray_log_level.clone())
                .filter(|level| !level.trim().is_empty())
                .unwrap_or_else(|| "warning".into()),
            xray_rx: None,
            ip_check_rx: None,
            connection_status: ConnectionStatus::Idle,
            logging_enabled,
            light_mode: saved.as_ref().map(|state| state.light_mode).unwrap_or(true),
            scan_timeout_secs: saved
                .as_ref()
                .map(|state| state.scan_timeout_secs.clone())
                .filter(|timeout| !timeout.trim().is_empty())
                .unwrap_or_else(|| scan::DEFAULT_TIMEOUT_SECS.to_string()),
            scan_concurrency: saved
                .as_ref()
                .map(|state| state.scan_concurrency.clone())
                .filter(|concurrency| !concurrency.trim().is_empty())
                .unwrap_or_else(|| scan::DEFAULT_CONCURRENCY.to_string()),
            scan_rx: None,
            scan_started: None,
            scan_total: 0,
            scan_done: 0,
            scan_ok: 0,
            scan_results: Vec::new(),
            saved_log_revision,
            last_auto_save: Instant::now(),
        }
    }

    fn poll_scan(&mut self) {
        let mut msgs = Vec::new();
        if let Some(rx) = &self.scan_rx {
            while let Ok(msg) = rx.try_recv() {
                msgs.push(msg);
            }
        }

        for msg in msgs {
            match msg {
                ScanMsg::Started(total) => {
                    self.scan_total = total;
                    self.scan_done = 0;
                    self.scan_ok = 0;
                    self.scan_results.clear();
                    self.scan_started = Some(Instant::now());
                }
                ScanMsg::Result(result) => {
                    self.scan_done += 1;
                    if matches!(result.outcome, ProbeOutcome::Ok) {
                        self.scan_ok += 1;
                    }
                    self.scan_results.push(result);
                    if self.scan_results.len() > RESULT_MAX {
                        self.scan_results.remove(0);
                    }
                }
                ScanMsg::Finished => {
                    self.status = format!(
                        "Scan finished: {} ok out of {}",
                        self.scan_ok, self.scan_done
                    );
                    self.scan_rx = None;
                }
                ScanMsg::Failed(e) => {
                    self.status = format!("Scan failed: {}", e);
                    self.scan_rx = None;
                }
            }
        }
    }

    fn poll_xray(&mut self) {
        if let Some(rx) = &self.xray_rx {
            match rx.try_recv() {
                Ok(XrayMsg::Downloaded(Ok(path))) => {
                    self.xray_path = path.clone();
                    self.status = format!("Xray downloaded to {}", path);
                    self.log.push(format!("xray downloaded to {}", path));
                    self.save_state();
                    self.xray_rx = None;
                }
                Ok(XrayMsg::Downloaded(Err(e))) => {
                    self.status = format!("Xray download failed: {}", e);
                    self.log.push(format!("xray download failed: {}", e));
                    self.xray_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.xray_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }

        if let Some(xray) = &mut self.xray {
            match xray.child.try_wait() {
                Ok(Some(status)) => {
                    self.status = format!("Xray stopped: {}", status);
                    self.log.push(format!("xray stopped: {}", status));
                    self.xray = None;
                }
                Ok(None) => {}
                Err(e) => {
                    self.status = format!("Xray status failed: {}", e);
                    self.log.push(format!("xray status failed: {}", e));
                    self.xray = None;
                }
            }
        }
    }

    fn poll_ip_check(&mut self) {
        if let Some(rx) = &self.ip_check_rx {
            match rx.try_recv() {
                Ok(IpCheckMsg::Checked(Ok(ip))) => {
                    self.connection_status = ConnectionStatus::Connected(ip.clone());
                    self.status = format!("Connected. Public IP via proxy: {}", ip);
                    self.log
                        .push(format!("connection check ok; public IP {}", ip));
                    self.ip_check_rx = None;
                }
                Ok(IpCheckMsg::Checked(Err(e))) => {
                    self.connection_status = ConnectionStatus::Failed(e.clone());
                    self.status = format!("Connection check failed: {}", e);
                    self.log.push(format!("connection check failed: {}", e));
                    self.ip_check_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.connection_status = ConnectionStatus::Failed("checker stopped".into());
                    self.ip_check_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    fn start_proxy(&mut self) -> bool {
        if self.proxy.is_some() {
            return true;
        }
        match self.form.to_config().and_then(|cfg| {
            start_proxy(cfg).map_err(|e| format!("{} ({})", e, platform_privilege_hint()))
        }) {
            Ok(proxy) => {
                self.status = "Proxy started".into();
                self.log.push("proxy started from UI");
                self.proxy = Some(proxy);
                true
            }
            Err(e) => {
                self.status = format!("Start failed: {}", e);
                self.log.push(format!("start failed: {}", e));
                false
            }
        }
    }

    fn stop_proxy(&mut self) {
        if let Some(mut proxy) = self.proxy.take() {
            proxy.stop();
            self.status = "Proxy stopped".into();
            self.log.push("proxy stopped from UI");
            self.reset_connection_status();
        }
    }

    fn start_xray(&mut self) -> bool {
        if self.xray.is_some() {
            return true;
        }
        if let Err(e) = self.ensure_no_proxy_loop() {
            self.status = e.clone();
            self.log.push(e);
            return false;
        }
        self.refresh_xray_path();
        let Some(line) = self.selected_import_line() else {
            self.status = "Paste a VLESS or Trojan link before starting Xray".into();
            return false;
        };

        let share = match xray::parse_share_link(line) {
            Ok(share) => share,
            Err(e) => {
                self.status = format!("Xray import failed: {}", e);
                return false;
            }
        };

        if let Err(e) = validate_tun_runtime(self.xray_tun_enabled, &self.xray_path) {
            self.status = e.clone();
            self.log.push(e);
            return false;
        }

        let config = match build_xray_config(
            &share,
            &self.form.listen,
            &self.xray_http_listen,
            &self.xray_socks_listen,
            self.xray_tun_enabled,
            &self.xray_log_level,
        ) {
            Ok(config) => config,
            Err(e) => {
                self.status = format!("Xray config failed: {}", e);
                return false;
            }
        };

        let config_path =
            std::env::temp_dir().join(format!("sni-spoof-rs-xray-{}.json", std::process::id()));
        if let Err(e) = std::fs::write(&config_path, config) {
            self.status = format!("Failed to write Xray config: {}", e);
            return false;
        }

        let xray_bin = self.xray_path.trim();
        let mut command = if xray_bin.is_empty() {
            Command::new("xray")
        } else {
            Command::new(xray_bin)
        };
        let mut child = match command
            .arg("run")
            .arg("-config")
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let _ = std::fs::remove_file(&config_path);
                self.status = format!("Failed to start Xray: {}", e);
                return false;
            }
        };

        if let Some(stdout) = child.stdout.take() {
            spawn_output_reader(stdout, self.log.clone(), "xray");
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_output_reader(stderr, self.log.clone(), "xray");
        }

        self.status = format!(
            "Xray proxy started: HTTP/HTTPS {}, SOCKS5 {}",
            self.xray_http_listen, self.xray_socks_listen
        );
        self.log.push(format!(
            "xray started; HTTP/HTTPS proxy {}, SOCKS5 proxy {}",
            self.xray_http_listen, self.xray_socks_listen
        ));
        self.xray = Some(XrayRuntime { child, config_path });
        if self.proxy.is_some() {
            self.start_ip_check();
        }
        true
    }

    fn stop_xray(&mut self) {
        if let Some(mut xray) = self.xray.take() {
            xray.stop();
            self.status = "Xray stopped".into();
            self.log.push("xray stopped from UI");
            self.reset_connection_status();
        }
    }

    fn start_ip_check(&mut self) {
        if self.ip_check_rx.is_some() {
            return;
        }
        let proxy_url =
            match connection_check_proxy_url(&self.xray_http_listen, &self.xray_socks_listen) {
                Ok(proxy_url) => proxy_url,
                Err(e) => {
                    self.connection_status = ConnectionStatus::Failed(e.clone());
                    self.status = format!("Connection check failed: {}", e);
                    return;
                }
            };

        let (tx, rx) = std::sync::mpsc::channel();
        self.ip_check_rx = Some(rx);
        self.connection_status = ConnectionStatus::Checking;
        self.status = "Checking public IP through Xray proxy...".into();
        self.log
            .push(format!("checking public IP through {}", proxy_url));
        std::thread::spawn(move || {
            let result = fetch_public_ip_through_proxy(&proxy_url);
            let _ = tx.send(IpCheckMsg::Checked(result));
        });
    }

    fn reset_connection_status(&mut self) {
        self.ip_check_rx = None;
        self.connection_status = ConnectionStatus::Idle;
    }

    fn start_all_in_one(&mut self) {
        self.stop_all();
        if !self.import_xray() {
            return;
        }
        if self.start_proxy() {
            self.start_xray();
        }
    }

    fn refresh_xray_path(&mut self) {
        if self.xray_path.trim().is_empty() || self.xray_path.trim() == "xray" {
            let discovered = default_xray_path();
            if discovered != "xray" {
                self.xray_path = discovered;
            }
        }
    }

    fn stop_all(&mut self) {
        self.stop_xray();
        self.stop_proxy();
    }

    fn ensure_no_proxy_loop(&self) -> Result<(), String> {
        let listen = self
            .form
            .listen
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid listen address: {}", e))?;
        let connect = self
            .form
            .connect
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid connect address: {}", e))?;

        if is_proxy_loop(listen, connect) {
            Err(format!(
                "Refusing proxy loop: listen {} connects to {}",
                listen, connect
            ))
        } else {
            Ok(())
        }
    }

    fn selected_import_line(&self) -> Option<&str> {
        selected_share_line(&self.import_text, self.selected_import)
    }

    fn clamp_selected_import(&mut self) {
        let count = share_line_count(&self.import_text);
        if count == 0 {
            self.selected_import = 0;
        } else if self.selected_import >= count {
            self.selected_import = count - 1;
        }
    }

    fn snapshot_state(&self) -> UiState {
        UiState {
            form: self.form.clone(),
            import_text: self.import_text.clone(),
            selected_import: self.selected_import,
            xray_path: self.xray_path.clone(),
            xray_http_listen: self.xray_http_listen.clone(),
            xray_socks_listen: Some(self.xray_socks_listen.clone()),
            xray_tun_enabled: self.xray_tun_enabled,
            xray_log_level: self.xray_log_level.clone(),
            logging_enabled: self.logging_enabled,
            light_mode: self.light_mode,
            scan_target: self.scan_target.clone(),
            scan_timeout_secs: self.scan_timeout_secs.clone(),
            scan_concurrency: self.scan_concurrency.clone(),
            log_lines: if self.logging_enabled {
                self.log.snapshot()
            } else {
                Vec::new()
            },
        }
    }

    fn save_state(&mut self) {
        match serde_json::to_string_pretty(&self.snapshot_state()) {
            Ok(body) => {
                if let Err(e) = std::fs::write(ui_state_path(), body) {
                    self.log.push(format!("state save failed: {}", e));
                } else {
                    self.saved_log_revision = self.log.revision();
                    self.last_auto_save = Instant::now();
                }
            }
            Err(e) => self.log.push(format!("state serialize failed: {}", e)),
        }
    }

    fn autosave_logs_if_dirty(&mut self) {
        let revision = self.log.revision();
        if revision != self.saved_log_revision
            && self.last_auto_save.elapsed() >= Duration::from_secs(2)
        {
            self.save_state();
        }
    }

    fn export_logs(&mut self) {
        let lines = self.log.snapshot();
        let path = log_export_path();
        let body = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        match std::fs::write(&path, body) {
            Ok(()) => {
                self.status = format!("Logs exported to {}", path.display());
                self.log
                    .push(format!("logs exported to {}", path.display()));
                self.save_state();
            }
            Err(e) => {
                self.status = format!("Log export failed: {}", e);
                self.log.push(format!("log export failed: {}", e));
            }
        }
    }

    fn download_xray(&mut self) {
        if self.xray_rx.is_some() {
            return;
        }
        let Some(url) = xray_download_url() else {
            self.status = "No Xray download URL for this platform".into();
            return;
        };
        let dest_dir = xray_data_dir();
        let (tx, rx) = std::sync::mpsc::channel();
        self.xray_rx = Some(rx);
        self.status = format!("Downloading Xray to {}...", dest_dir.display());
        self.log.push(format!(
            "downloading xray from {} to {}",
            url,
            dest_dir.display()
        ));
        std::thread::spawn(move || {
            let result = download_xray_to(&url, &dest_dir);
            let _ = tx.send(XrayMsg::Downloaded(result));
        });
    }

    fn load_config(&mut self) {
        match config::load("config.json") {
            Ok(cfg) => {
                self.form = FormState::from_config(&cfg);
                self.scan_target = self.form.connect.clone();
                self.status = "Loaded config.json".into();
                self.save_state();
            }
            Err(e) => self.status = format!("Load failed: {}", e),
        }
    }

    fn save_config(&mut self) {
        match self
            .form
            .to_config()
            .and_then(|cfg| config::to_pretty_json(&cfg).map_err(|e| e.to_string()))
            .and_then(|body| std::fs::write("config.json", body).map_err(|e| e.to_string()))
        {
            Ok(()) => {
                self.status = "Saved config.json".into();
                self.save_state();
            }
            Err(e) => self.status = format!("Save failed: {}", e),
        }
    }

    fn import_xray(&mut self) -> bool {
        self.clamp_selected_import();
        let Some(line) = self.selected_import_line() else {
            self.status = "Paste a VLESS, VMess, or Trojan link first".into();
            return false;
        };

        match xray::parse_share_link(line) {
            Ok(share) => match xray::resolve_upstream_host(&share) {
                Ok(addrs) if !addrs.is_empty() => {
                    let selected = addrs
                        .iter()
                        .copied()
                        .find(SocketAddr::is_ipv4)
                        .unwrap_or(addrs[0]);
                    if selected.ip().is_loopback() || selected.ip().is_unspecified() {
                        self.status = format!(
                            "Could not infer a remote upstream from {}. Add a real host/sni or paste the original remote link.",
                            share.host
                        );
                        return false;
                    }
                    let listen = match self.form.listen.trim().parse::<SocketAddr>() {
                        Ok(listen) => listen,
                        Err(e) => {
                            self.status = format!("Invalid listen address: {}", e);
                            return false;
                        }
                    };
                    if is_proxy_loop(listen, selected) {
                        self.status = format!(
                            "Refusing proxy loop: listen {} would connect to {}",
                            listen, selected
                        );
                        return false;
                    }
                    self.form.connect = selected.to_string();
                    self.scan_target = self.form.connect.clone();
                    if self.form.fake_sni.trim().is_empty() {
                        self.form.fake_sni = "security.vercel.com".into();
                    }
                    self.status = format!(
                        "Imported {} {} via {} -> {}",
                        share.protocol,
                        share.label(),
                        share.upstream_host(),
                        selected
                    );
                    self.save_state();
                    true
                }
                Ok(_) => {
                    self.status = format!("No addresses found for {}", share.host);
                    false
                }
                Err(e) => {
                    self.status = format!("Resolve failed for {}: {}", share.host, e);
                    false
                }
            },
            Err(e) => {
                self.status = format!("Import failed: {}", e);
                false
            }
        }
    }

    fn start_scan(&mut self, snis: Vec<String>) {
        if self.scan_rx.is_some() {
            return;
        }
        let target = match self.scan_target.parse::<SocketAddr>() {
            Ok(v) => v,
            Err(e) => {
                self.status = format!("Invalid scan target: {}", e);
                return;
            }
        };
        let timeout = match self.scan_timeout_secs.parse::<u64>() {
            Ok(v) if v > 0 => Duration::from_secs(v),
            _ => {
                self.status = "Invalid scan timeout".into();
                return;
            }
        };
        let concurrency = match self.scan_concurrency.parse::<usize>() {
            Ok(v) if v > 0 => v,
            _ => {
                self.status = "Invalid scan concurrency".into();
                return;
            }
        };

        let (tx, rx) = std::sync::mpsc::channel();
        self.scan_rx = Some(rx);
        self.status = format!("Scanning {} SNI candidate(s)", snis.len());
        spawn_scan(tx, target, timeout, concurrency, snis);
    }

    fn bind_xray_local(&mut self) {
        self.xray_http_listen = "127.0.0.1:1080".into();
        self.xray_socks_listen = "127.0.0.1:1081".into();
        self.status = "Xray proxies set to local-only bindings".into();
        self.save_state();
    }

    fn bind_xray_lan(&mut self) {
        self.xray_http_listen = "0.0.0.0:1080".into();
        self.xray_socks_listen = "0.0.0.0:1081".into();
        self.form.listen = replace_socket_host(&self.form.listen, "0.0.0.0");
        self.status = "Xray proxies set to LAN bindings".into();
        self.save_state();
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.stop_all();
        self.save_state();
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.clamp_selected_import();
        apply_theme(ctx, self.light_mode);
        let palette = palette(self.light_mode);
        self.poll_scan();
        self.poll_xray();
        self.poll_ip_check();
        if self.proxy.as_ref().is_some_and(|p| !p.is_running()) {
            self.proxy = None;
            self.status = "Proxy stopped".into();
            self.reset_connection_status();
        }
        if self.scan_rx.is_some()
            || self.xray_rx.is_some()
            || self.ip_check_rx.is_some()
            || self.xray.is_some()
        {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        egui::TopBottomPanel::top("top")
            .frame(
                egui::Frame::default()
                    .fill(palette.top_fill)
                    .inner_margin(egui::Margin::symmetric(16.0, 12.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.heading(
                        egui::RichText::new(format!("sni-spoof-rs {}", env!("CARGO_PKG_VERSION")))
                            .color(palette.text),
                    );
                    status_pill(
                        ui,
                        if self.proxy.is_some() {
                            "Proxy running"
                        } else {
                            "Proxy stopped"
                        },
                        if self.proxy.is_some() {
                            palette.success_fill
                        } else {
                            palette.stopped_fill
                        },
                    );
                    status_pill(
                        ui,
                        if self.xray.is_some() {
                            "Xray running"
                        } else {
                            "Xray stopped"
                        },
                        if self.xray.is_some() {
                            palette.primary_fill
                        } else {
                            palette.stopped_fill
                        },
                    );
                    let (ip_text, ip_fill) = self.connection_status.pill(palette);
                    status_pill(ui, &ip_text, ip_fill);
                    ui.separator();
                    ui.label(egui::RichText::new(&self.status).color(palette.muted));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.checkbox(&mut self.light_mode, "Light").changed() {
                            self.save_state();
                        }
                        ui.hyperlink_to(
                            "GitHub repo",
                            "https://github.com/therealaleph/sni-spoofing-rust",
                        );
                    });
                });
            });

        egui::TopBottomPanel::bottom("logs_panel")
            .resizable(true)
            .min_height(170.0)
            .default_height(300.0)
            .frame(
                egui::Frame::default()
                    .fill(palette.panel_fill)
                    .inner_margin(egui::Margin::symmetric(16.0, 10.0)),
            )
            .show(ctx, |ui| {
                self.draw_controls(ui, palette);
                ui.add_space(10.0);
                self.draw_logs(ui, palette);
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(palette.panel_fill)
                    .inner_margin(egui::Margin::symmetric(16.0, 14.0)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.draw_import(ui, palette);
                    ui.add_space(10.0);
                    self.draw_config(ui, palette);
                    ui.add_space(10.0);
                    self.draw_scanner(ui, palette);
                });
            });
        self.autosave_logs_if_dirty();
    }
}

impl App {
    fn draw_controls(&mut self, ui: &mut egui::Ui, palette: Palette) {
        section_frame(palette).show(ui, |ui| {
            let running = self.proxy.is_some();
            let xray_running = self.xray.is_some();
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !running || !xray_running,
                        filled_button("Start all-in-one", palette.success_fill),
                    )
                    .clicked()
                {
                    self.start_all_in_one();
                }
                if ui
                    .add_enabled(
                        running || xray_running,
                        filled_button("Stop all", palette.danger_fill),
                    )
                    .clicked()
                {
                    self.stop_all();
                }
                if ui
                    .add_enabled(!running, filled_button("Start proxy", palette.primary_fill))
                    .clicked()
                {
                    self.start_proxy();
                }
                if ui
                    .add_enabled(running, filled_button("Stop proxy", palette.stopped_fill))
                    .clicked()
                {
                    self.stop_proxy();
                }
                if ui
                    .add_enabled(
                        !xray_running,
                        filled_button("Start Xray", palette.primary_fill),
                    )
                    .clicked()
                {
                    self.start_xray();
                }
                if ui
                    .add_enabled(
                        xray_running,
                        filled_button("Stop Xray", palette.warning_fill),
                    )
                    .clicked()
                {
                    self.stop_xray();
                }
                if ui.add(neutral_button("Load", palette)).clicked() {
                    self.load_config();
                }
                if ui.add(neutral_button("Save", palette)).clicked() {
                    self.save_config();
                }
                if ui
                    .add_enabled(
                        self.xray.is_some() && self.ip_check_rx.is_none(),
                        neutral_button("Check IP", palette),
                    )
                    .clicked()
                {
                    self.start_ip_check();
                }
                if ui
                    .add(neutral_button("Use connect as scan target", palette))
                    .clicked()
                {
                    self.scan_target = self.form.connect.clone();
                    self.save_state();
                }
            });
        });
    }

    fn draw_config(&mut self, ui: &mut egui::Ui, palette: Palette) {
        egui::CollapsingHeader::new(
            egui::RichText::new("Proxy Config")
                .color(palette.text)
                .strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            section_frame(palette).show(ui, |ui| {
                egui::Grid::new("config_grid")
                    .num_columns(2)
                    .spacing([18.0, 9.0])
                    .show(ui, |ui| {
                        ui.label("listen");
                        ui.text_edit_singleline(&mut self.form.listen);
                        ui.end_row();

                        ui.label("connect");
                        ui.text_edit_singleline(&mut self.form.connect);
                        ui.end_row();

                        ui.label("fake_sni");
                        ui.text_edit_singleline(&mut self.form.fake_sni);
                        ui.end_row();

                        ui.label("conn_timeout_sec");
                        ui.text_edit_singleline(&mut self.form.conn_timeout_sec);
                        ui.end_row();

                        ui.label("handshake_timeout_sec");
                        ui.text_edit_singleline(&mut self.form.handshake_timeout_sec);
                        ui.end_row();

                        ui.label("keepalive_time_sec");
                        ui.text_edit_singleline(&mut self.form.keepalive_time_sec);
                        ui.end_row();

                        ui.label("keepalive_interval_sec");
                        ui.text_edit_singleline(&mut self.form.keepalive_interval_sec);
                        ui.end_row();

                        ui.label("idle_timeout");
                        ui.text_edit_singleline(&mut self.form.idle_timeout);
                        ui.end_row();

                        ui.label("buffer_size_kib");
                        ui.text_edit_singleline(&mut self.form.buffer_size);
                        ui.end_row();

                        ui.label("graceful_shutdown_sec");
                        ui.text_edit_singleline(&mut self.form.graceful_shutdown_sec);
                        ui.end_row();
                    });
            });
        });
    }

    fn draw_import(&mut self, ui: &mut egui::Ui, palette: Palette) {
        egui::CollapsingHeader::new(
            egui::RichText::new("Xray Import")
                .color(palette.text)
                .strong(),
        )
        .default_open(true)
        .show(ui, |ui| {
            section_frame(palette).show(ui, |ui| {
                egui::Grid::new("xray_runtime_grid")
                    .num_columns(2)
                    .spacing([18.0, 9.0])
                    .show(ui, |ui| {
                        ui.label("xray_binary");
                        ui.text_edit_singleline(&mut self.xray_path);
                        ui.end_row();

                        ui.label("http_https_proxy");
                        ui.text_edit_singleline(&mut self.xray_http_listen);
                        ui.end_row();

                        ui.label("socks5_proxy");
                        ui.text_edit_singleline(&mut self.xray_socks_listen);
                        ui.end_row();

                        ui.label("xray_log");
                        ui.text_edit_singleline(&mut self.xray_log_level);
                        ui.end_row();
                    });

                ui.horizontal_wrapped(|ui| {
                    if ui.add(neutral_button("Local only", palette)).clicked() {
                        self.bind_xray_local();
                    }
                    if ui
                        .add(filled_button("Share on LAN", palette.primary_fill))
                        .clicked()
                    {
                        self.bind_xray_lan();
                    }
                    if ui
                        .checkbox(&mut self.xray_tun_enabled, "Xray TUN mode")
                        .changed()
                    {
                        self.status = if self.xray_tun_enabled {
                            "Xray TUN mode enabled. Run elevated and avoid routing loops.".into()
                        } else {
                            "Xray TUN mode disabled".into()
                        };
                        self.save_state();
                    }
                });

                let import_labels = share_lines(&self.import_text)
                    .iter()
                    .enumerate()
                    .map(|(idx, line)| share_label(idx, line))
                    .collect::<Vec<_>>();
                ui.horizontal_wrapped(|ui| {
                    ui.label("active_config");
                    let selected_label = import_labels
                        .get(self.selected_import)
                        .cloned()
                        .unwrap_or_else(|| "No config selected".into());
                    egui::ComboBox::from_id_source("active_import")
                        .selected_text(selected_label)
                        .width(360.0)
                        .show_ui(ui, |ui| {
                            for (idx, label) in import_labels.iter().enumerate() {
                                ui.selectable_value(&mut self.selected_import, idx, label);
                            }
                        });
                    ui.label(format!("{} saved line(s)", import_labels.len()));
                });

                ui.add(
                    egui::TextEdit::multiline(&mut self.import_text)
                        .desired_rows(6)
                        .desired_width(f32::INFINITY)
                        .hint_text("vless://...\ntrojan://...\none config per line"),
                );
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add(filled_button("Parse selected", palette.success_fill))
                        .clicked()
                    {
                        self.import_xray();
                    }
                    if ui.add(neutral_button("Download Xray", palette)).clicked() {
                        self.download_xray();
                    }
                    if ui
                        .add_enabled(
                            self.xray.is_some() && self.ip_check_rx.is_none(),
                            neutral_button("Fetch my IP", palette),
                        )
                        .clicked()
                    {
                        self.start_ip_check();
                    }
                    if ui
                        .add_enabled(
                            self.xray.is_none(),
                            filled_button("Start Xray", palette.primary_fill),
                        )
                        .clicked()
                    {
                        self.start_xray();
                    }
                    if ui.add(neutral_button("Clear", palette)).clicked() {
                        self.import_text.clear();
                        self.selected_import = 0;
                        self.save_state();
                    }
                });
                ui.label(format!(
                    "HTTP/HTTPS: {}    SOCKS5: {}    TUN: {}    {}",
                    self.xray_http_listen,
                    self.xray_socks_listen,
                    if self.xray_tun_enabled { "on" } else { "off" },
                    self.connection_status.detail()
                ));
            });
        });
    }

    fn draw_scanner(&mut self, ui: &mut egui::Ui, palette: Palette) {
        egui::CollapsingHeader::new(
            egui::RichText::new("SNI Scanner")
                .color(palette.text)
                .strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            section_frame(palette).show(ui, |ui| {
                egui::Grid::new("scan_grid")
                    .num_columns(2)
                    .spacing([18.0, 9.0])
                    .show(ui, |ui| {
                        ui.label("target");
                        ui.text_edit_singleline(&mut self.scan_target);
                        ui.end_row();

                        ui.label("timeout_sec");
                        ui.text_edit_singleline(&mut self.scan_timeout_secs);
                        ui.end_row();

                        ui.label("concurrency");
                        ui.text_edit_singleline(&mut self.scan_concurrency);
                        ui.end_row();
                    });

                ui.horizontal_wrapped(|ui| {
                    let scanning = self.scan_rx.is_some();
                    if ui
                        .add_enabled(
                            !scanning,
                            filled_button("Test fake_sni", palette.success_fill),
                        )
                        .clicked()
                    {
                        self.start_scan(vec![self.form.fake_sni.clone()]);
                    }
                    if ui
                        .add_enabled(
                            !scanning,
                            filled_button("Scan built-in list", palette.primary_fill),
                        )
                        .clicked()
                    {
                        self.start_scan(scan::default_snis());
                    }
                    if scanning {
                        ui.label(format!(
                            "{} / {} complete, {} ok",
                            self.scan_done, self.scan_total, self.scan_ok
                        ));
                    }
                });

                if let Some(started) = self.scan_started {
                    if self.scan_done > 0 {
                        ui.label(format!("elapsed: {:.1}s", started.elapsed().as_secs_f32()));
                    }
                }

                egui::ScrollArea::vertical()
                    .id_source("scan_results")
                    .max_height(220.0)
                    .show(ui, |ui| {
                        egui::Grid::new("scan_result_grid")
                            .striped(true)
                            .num_columns(2)
                            .spacing([20.0, 4.0])
                            .show(ui, |ui| {
                                ui.strong("SNI");
                                ui.strong("Result");
                                ui.end_row();
                                for result in self.scan_results.iter().rev().take(120) {
                                    ui.label(&result.sni);
                                    match &result.outcome {
                                        ProbeOutcome::Ok => {
                                            ui.colored_label(palette.success_fill, "ok");
                                        }
                                        other => {
                                            ui.colored_label(
                                                palette.danger_fill,
                                                other.to_string(),
                                            );
                                        }
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            });
        });
    }

    fn draw_logs(&mut self, ui: &mut egui::Ui, palette: Palette) {
        section_frame(palette).show(ui, |ui| {
            ui.horizontal(|ui| {
                section_header(ui, "Logs", egui::Color32::from_rgb(108, 117, 125), palette);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.checkbox(&mut self.logging_enabled, "Logging").changed() {
                        self.log.set_enabled(self.logging_enabled);
                        self.status = if self.logging_enabled {
                            "Logging enabled".into()
                        } else {
                            "Logging disabled".into()
                        };
                        self.save_state();
                    }
                    if ui.add(neutral_button("Clear", palette)).clicked() {
                        self.log.clear();
                        self.status = "Logs cleared".into();
                        self.save_state();
                    }
                    if ui.add(neutral_button("Export logs", palette)).clicked() {
                        self.export_logs();
                    }
                });
            });
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .id_source("logs")
                .stick_to_bottom(true)
                .max_height((ui.available_height() - 4.0).max(80.0))
                .show(ui, |ui| {
                    if self.logging_enabled {
                        for line in self.log.snapshot() {
                            ui.monospace(line);
                        }
                    } else {
                        ui.label(egui::RichText::new("Logging is disabled").color(palette.muted));
                    }
                });
        });
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct UiState {
    form: FormState,
    import_text: String,
    selected_import: usize,
    xray_path: String,
    xray_http_listen: String,
    #[serde(default)]
    xray_socks_listen: Option<String>,
    #[serde(default)]
    xray_tun_enabled: bool,
    xray_log_level: String,
    #[serde(default = "default_true")]
    logging_enabled: bool,
    light_mode: bool,
    scan_target: String,
    scan_timeout_secs: String,
    scan_concurrency: String,
    #[serde(default)]
    log_lines: Vec<String>,
}

fn load_ui_state() -> Option<UiState> {
    let path = ui_state_path();
    let body = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

fn default_true() -> bool {
    true
}

fn ui_state_path() -> PathBuf {
    if let Ok(path) = std::env::var("SNI_SPOOF_UI_STATE") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }

    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join(STATE_FILE)))
        .unwrap_or_else(|| PathBuf::from(STATE_FILE))
}

fn log_export_path() -> PathBuf {
    let file_name = format!("sni-spoof-rs-ui-logs-{}.txt", unix_timestamp_secs());
    ui_state_path()
        .parent()
        .map(|dir| dir.join(&file_name))
        .unwrap_or_else(|| PathBuf::from(file_name))
}

fn app_data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("SNI_SPOOF_UI_DATA_DIR") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home_dir() {
            return home
                .join("Library")
                .join("Application Support")
                .join("sni-spoof-rs");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.trim().is_empty() {
                return PathBuf::from(appdata).join("sni-spoof-rs");
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
            if !xdg_data.trim().is_empty() {
                return PathBuf::from(xdg_data).join("sni-spoof-rs");
            }
        }
        if let Some(home) = home_dir() {
            return home.join(".local").join("share").join("sni-spoof-rs");
        }
    }

    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join(".sni-spoof-rs")))
        .unwrap_or_else(|| PathBuf::from(".sni-spoof-rs"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

fn xray_data_dir() -> PathBuf {
    app_data_dir().join("xray").join(format!(
        "{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

struct XrayRuntime {
    child: Child,
    config_path: PathBuf,
}

impl XrayRuntime {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config_path);
    }
}

impl Drop for XrayRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

enum XrayMsg {
    Downloaded(Result<String, String>),
}

enum IpCheckMsg {
    Checked(Result<String, String>),
}

#[derive(Clone)]
enum ConnectionStatus {
    Idle,
    Checking,
    Connected(String),
    Failed(String),
}

impl ConnectionStatus {
    fn pill(&self, palette: Palette) -> (String, egui::Color32) {
        match self {
            Self::Idle => ("IP unchecked".into(), palette.stopped_fill),
            Self::Checking => ("Checking IP".into(), palette.primary_fill),
            Self::Connected(ip) => (format!("IP {}", ip), palette.success_fill),
            Self::Failed(_) => ("IP check failed".into(), palette.danger_fill),
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Idle => "IP: unchecked".into(),
            Self::Checking => "IP: checking".into(),
            Self::Connected(ip) => format!("IP: {}", ip),
            Self::Failed(e) => format!("IP check failed: {}", e),
        }
    }
}

fn share_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

fn share_line_count(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .count()
}

fn selected_share_line(text: &str, selected: usize) -> Option<&str> {
    share_lines(text).get(selected).copied()
}

fn share_label(index: usize, line: &str) -> String {
    match xray::parse_share_link(line) {
        Ok(share) => format!(
            "{}. {} {}",
            index + 1,
            share.protocol.to_uppercase(),
            share.label()
        ),
        Err(_) => format!("{}. {}", index + 1, truncate_middle(line, 44)),
    }
}

fn truncate_middle(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let keep = max.saturating_sub(3) / 2;
    let start: String = value.chars().take(keep).collect();
    let end: String = value
        .chars()
        .rev()
        .take(keep)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{}...{}", start, end)
}

fn is_proxy_loop(listen: SocketAddr, connect: SocketAddr) -> bool {
    if listen == connect {
        return true;
    }

    connect.port() == listen.port()
        && connect.ip().is_loopback()
        && (listen.ip().is_loopback() || listen.ip().is_unspecified())
}

fn replace_socket_host(value: &str, host: &str) -> String {
    value
        .trim()
        .parse::<SocketAddr>()
        .map(|addr| format!("{}:{}", host, addr.port()))
        .unwrap_or_else(|_| format!("{}:40443", host))
}

fn default_xray_path() -> String {
    if let Ok(path) = std::env::var("XRAY_PATH") {
        if !path.trim().is_empty() {
            return path;
        }
    }

    let binary_name = if cfg!(windows) { "xray.exe" } else { "xray" };
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(binary_name));
        }
    }
    candidates.push(xray_data_dir().join(binary_name));
    candidates.push(
        std::env::temp_dir()
            .join("sni-spoof-rs-xray")
            .join(binary_name),
    );
    candidates.push(PathBuf::from("/opt/homebrew/bin/xray"));
    candidates.push(PathBuf::from("/usr/local/bin/xray"));

    for candidate in candidates {
        if candidate.exists() {
            return candidate.to_string_lossy().to_string();
        }
    }

    "xray".into()
}

fn xray_download_url() -> Option<String> {
    let file = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "Xray-macos-arm64-v8a.zip",
        ("macos", "x86_64") => "Xray-macos-64.zip",
        ("linux", "aarch64") => "Xray-linux-arm64-v8a.zip",
        ("linux", "x86_64") => "Xray-linux-64.zip",
        ("windows", "x86_64") => "Xray-windows-64.zip",
        _ => return None,
    };
    Some(format!(
        "https://github.com/XTLS/Xray-core/releases/latest/download/{}",
        file
    ))
}

fn download_xray_to(url: &str, dest_dir: &Path) -> Result<String, String> {
    std::fs::create_dir_all(dest_dir).map_err(|e| e.to_string())?;
    let zip_path = dest_dir.join("xray.zip");

    let curl_status = Command::new("curl")
        .arg("-L")
        .arg("--fail")
        .arg("--max-time")
        .arg("180")
        .arg("-o")
        .arg(&zip_path)
        .arg(url)
        .status()
        .map_err(|e| format!("failed to run curl: {}", e))?;
    if !curl_status.success() {
        return Err(format!("curl exited with {}", curl_status));
    }

    let binary_name = if cfg!(windows) { "xray.exe" } else { "xray" };
    let binary = dest_dir.join(binary_name);
    let _ = std::fs::remove_file(&binary);
    extract_xray_zip(&zip_path, binary_name, dest_dir)?;
    let _ = std::fs::remove_file(&zip_path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&binary)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&binary, perms).map_err(|e| e.to_string())?;
    }

    #[cfg(windows)]
    install_wintun_to(dest_dir)?;

    Ok(binary.to_string_lossy().to_string())
}

#[cfg(windows)]
fn install_wintun_to(dest_dir: &Path) -> Result<(), String> {
    let zip_path = dest_dir.join("wintun.zip");
    let extract_dir = dest_dir.join("wintun-extracted");
    let _ = std::fs::remove_dir_all(&extract_dir);

    let curl_status = Command::new("curl")
        .arg("-L")
        .arg("--fail")
        .arg("--max-time")
        .arg("180")
        .arg("-o")
        .arg(&zip_path)
        .arg(WINTUN_URL)
        .status()
        .map_err(|e| format!("failed to run curl for Wintun: {}", e))?;
    if !curl_status.success() {
        return Err(format!("Wintun download exited with {}", curl_status));
    }

    let status = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg("Expand-Archive -Force -LiteralPath $args[0] -DestinationPath $args[1]")
        .arg(&zip_path)
        .arg(&extract_dir)
        .status()
        .map_err(|e| format!("failed to run powershell Expand-Archive for Wintun: {}", e))?;
    if !status.success() {
        return Err(format!("Wintun Expand-Archive exited with {}", status));
    }

    let arch_dir = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "x86",
        "aarch64" => "arm64",
        other => return Err(format!("unsupported Wintun architecture: {}", other)),
    };
    let source = extract_dir
        .join("wintun")
        .join("bin")
        .join(arch_dir)
        .join("wintun.dll");
    let dest = dest_dir.join("wintun.dll");
    std::fs::copy(&source, &dest)
        .map_err(|e| format!("failed to install Wintun from {}: {}", source.display(), e))?;
    let _ = std::fs::remove_file(&zip_path);
    let _ = std::fs::remove_dir_all(&extract_dir);
    Ok(())
}

#[cfg(not(windows))]
fn extract_xray_zip(zip_path: &Path, binary_name: &str, dest_dir: &Path) -> Result<(), String> {
    let unzip_status = Command::new("unzip")
        .arg("-o")
        .arg(zip_path)
        .arg(binary_name)
        .arg("-d")
        .arg(dest_dir)
        .status()
        .map_err(|e| format!("failed to run unzip: {}", e))?;
    if !unzip_status.success() {
        return Err(format!("unzip exited with {}", unzip_status));
    }
    Ok(())
}

#[cfg(windows)]
fn extract_xray_zip(zip_path: &Path, binary_name: &str, dest_dir: &Path) -> Result<(), String> {
    let status = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg("Expand-Archive -Force -LiteralPath $args[0] -DestinationPath $args[1]")
        .arg(zip_path)
        .arg(dest_dir)
        .status()
        .map_err(|e| format!("failed to run powershell Expand-Archive: {}", e))?;
    if !status.success() {
        return Err(format!("Expand-Archive exited with {}", status));
    }
    if !dest_dir.join(binary_name).exists() {
        return Err(format!("{} was not found in Xray archive", binary_name));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_tun_runtime(tun_enabled: bool, xray_path: &str) -> Result<(), String> {
    if !tun_enabled {
        return Ok(());
    }

    let path = Path::new(xray_path.trim());
    let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) else {
        return Ok(());
    };
    if dir.join("wintun.dll").exists() {
        Ok(())
    } else {
        Err(format!(
            "Xray TUN on Windows needs wintun.dll next to xray.exe. Use Download Xray or copy it to {}",
            dir.display()
        ))
    }
}

#[cfg(not(windows))]
fn validate_tun_runtime(_tun_enabled: bool, _xray_path: &str) -> Result<(), String> {
    Ok(())
}

fn connection_check_proxy_url(http_listen: &str, socks_listen: &str) -> Result<String, String> {
    if let Some(addr) = parse_optional_socket("Xray HTTP/HTTPS proxy", http_listen)? {
        return Ok(format!("http://{}", local_check_addr(addr)));
    }
    if let Some(addr) = parse_optional_socket("Xray SOCKS5 proxy", socks_listen)? {
        return Ok(format!("socks5h://{}", local_check_addr(addr)));
    }
    Err("enable an Xray HTTP/HTTPS or SOCKS5 proxy before checking IP".into())
}

fn local_check_addr(addr: SocketAddr) -> String {
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    match ip {
        IpAddr::V4(ip) => format!("{}:{}", ip, addr.port()),
        IpAddr::V6(ip) => format!("[{}]:{}", ip, addr.port()),
    }
}

fn fetch_public_ip_through_proxy(proxy_url: &str) -> Result<String, String> {
    let endpoints = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ];
    let mut last_error = String::new();
    for endpoint in endpoints {
        match fetch_public_ip_once(proxy_url, endpoint) {
            Ok(ip) => return Ok(ip),
            Err(e) => last_error = e,
        }
    }
    if last_error.is_empty() {
        last_error = "no IP endpoints were configured".into();
    }
    Err(last_error)
}

fn fetch_public_ip_once(proxy_url: &str, endpoint: &str) -> Result<String, String> {
    let output = Command::new("curl")
        .arg("-fsSL")
        .arg("--max-time")
        .arg("12")
        .arg("--connect-timeout")
        .arg("6")
        .arg("--proxy")
        .arg(proxy_url)
        .arg(endpoint)
        .output()
        .map_err(|e| format!("failed to run curl: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("curl exited with {}", output.status)
        } else {
            stderr
        });
    }

    let body = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let first = body.split_whitespace().next().unwrap_or_default();
    first
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| format!("{} returned unexpected response: {}", endpoint, body))
}

fn spawn_output_reader<R>(reader: R, log: UiLog, prefix: &'static str)
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if !line.is_empty() {
                log.push(format!("{}: {}", prefix, line));
            }
        }
    });
}

fn build_xray_config(
    share: &xray::XrayShare,
    sni_listener: &str,
    http_listen: &str,
    socks_listen: &str,
    tun_enabled: bool,
    log_level: &str,
) -> Result<String, String> {
    if !matches!(share.protocol.as_str(), "vless" | "trojan") {
        return Err("all-in-one runtime currently supports VLESS and Trojan links".into());
    }

    let user_id = share
        .user_id
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or("share link is missing UUID/password user info")?;
    let sni_addr: SocketAddr = sni_listener
        .trim()
        .parse()
        .map_err(|e| format!("invalid SNI listener address: {}", e))?;
    let http_addr = parse_optional_socket("Xray HTTP/HTTPS proxy", http_listen)?;
    let socks_addr = parse_optional_socket("Xray SOCKS5 proxy", socks_listen)?;
    if http_addr.is_none() && socks_addr.is_none() && !tun_enabled {
        return Err("enable at least one Xray inbound proxy address".into());
    }

    let network = share.network.as_deref().unwrap_or("tcp");
    let security = share
        .security
        .as_deref()
        .unwrap_or(if share.tls { "tls" } else { "none" });
    let mut stream = Map::new();
    stream.insert("network".into(), json!(network));
    stream.insert("security".into(), json!(security));

    if security.eq_ignore_ascii_case("tls") {
        stream.insert(
            "tlsSettings".into(),
            json!({
                "serverName": share
                    .sni
                    .as_deref()
                    .or(share.http_host.as_deref())
                    .unwrap_or(&share.host),
                "fingerprint": share.fingerprint.as_deref().unwrap_or("chrome"),
                "allowInsecure": share.allow_insecure
            }),
        );
    }

    match network {
        "ws" => {
            let mut headers = Map::new();
            if let Some(host) = share.http_host.as_deref().filter(|v| !v.is_empty()) {
                headers.insert("Host".into(), json!(host));
            }
            stream.insert(
                "wsSettings".into(),
                json!({
                    "path": share.path.as_deref().unwrap_or("/"),
                    "headers": Value::Object(headers)
                }),
            );
        }
        "grpc" => {
            stream.insert(
                "grpcSettings".into(),
                json!({
                    "serviceName": share.path.as_deref().unwrap_or("")
                }),
            );
        }
        "xhttp" => {
            stream.insert(
                "xhttpSettings".into(),
                json!({
                    "path": share.path.as_deref().unwrap_or("/"),
                    "host": share.http_host.as_deref().unwrap_or(""),
                    "mode": share.mode.as_deref().unwrap_or("auto")
                }),
            );
        }
        _ => {}
    }

    let outbound_settings = match share.protocol.as_str() {
        "vless" => json!({
            "vnext": [
                {
                    "address": "127.0.0.1",
                    "port": sni_addr.port(),
                    "users": [
                        {
                            "id": user_id,
                            "encryption": share.encryption.as_deref().unwrap_or("none")
                        }
                    ]
                }
            ]
        }),
        "trojan" => json!({
            "servers": [
                {
                    "address": "127.0.0.1",
                    "port": sni_addr.port(),
                    "password": user_id
                }
            ]
        }),
        _ => unreachable!(),
    };

    let mut inbounds = Vec::new();
    if let Some(addr) = http_addr {
        inbounds.push(json!({
            "port": addr.port(),
            "listen": addr.ip().to_string(),
            "protocol": "http",
            "settings": {}
        }));
    }
    if let Some(addr) = socks_addr {
        inbounds.push(json!({
            "port": addr.port(),
            "listen": addr.ip().to_string(),
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": false
            }
        }));
    }
    if tun_enabled {
        inbounds.push(json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": "sni-spoof-rs-tun",
                "mtu": 1500,
                "gateway": ["10.250.0.1/16", "fc00:250::1/64"],
                "dns": ["1.1.1.1", "8.8.8.8"],
                "userLevel": 0,
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                "autoOutboundsInterface": "auto"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        }));
    }

    let config = json!({
        "log": {
            "loglevel": log_level.trim().if_empty("warning")
        },
        "inbounds": inbounds,
        "outbounds": [
            {
                "protocol": share.protocol.as_str(),
                "settings": outbound_settings,
                "streamSettings": Value::Object(stream)
            }
        ]
    });

    serde_json::to_string_pretty(&config).map_err(|e| e.to_string())
}

fn parse_optional_socket(label: &str, value: &str) -> Result<Option<SocketAddr>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse()
        .map(Some)
        .map_err(|e| format!("invalid {} address: {}", label, e))
}

trait IfEmpty {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str;
}

impl IfEmpty for str {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str {
        let trimmed = self.trim();
        if trimmed.is_empty() {
            fallback
        } else {
            trimmed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_xray_config_for_local_rewritten_vless_xhttp() {
        let share = xray::parse_share_link("vless://uuid@127.0.0.1:40443?mode=auto&path=%2FGoOgLe&security=tls&encryption=none&host=tom.dnstt.space&fp=chrome&type=xhttp&sni=tom.dnstt.space#NET_SPOOF").unwrap();
        let body = build_xray_config(
            &share,
            "127.0.0.1:40443",
            "127.0.0.1:1080",
            "127.0.0.1:1081",
            false,
            "warning",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["outbounds"][0]["protocol"], "vless");
        assert_eq!(value["inbounds"][0]["protocol"], "http");
        assert_eq!(value["inbounds"][1]["protocol"], "socks");
        assert_eq!(
            value["outbounds"][0]["settings"]["vnext"][0]["address"],
            "127.0.0.1"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["xhttpSettings"]["host"],
            "tom.dnstt.space"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"],
            "/GoOgLe"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["xhttpSettings"]["mode"],
            "auto"
        );
    }

    #[test]
    fn builds_xray_config_for_trojan_ws() {
        let share = xray::parse_share_link("trojan://humanity@127.0.0.1:40443?path=%2Fassignment&security=tls&host=www.ignitelimit.com&type=ws&sni=www.ignitelimit.com#NET_SPOOF").unwrap();
        let body = build_xray_config(
            &share,
            "127.0.0.1:40443",
            "0.0.0.0:1080",
            "0.0.0.0:1081",
            false,
            "warning",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["outbounds"][0]["protocol"], "trojan");
        assert_eq!(value["inbounds"][0]["listen"], "0.0.0.0");
        assert_eq!(value["inbounds"][1]["listen"], "0.0.0.0");
        assert_eq!(
            value["outbounds"][0]["settings"]["servers"][0]["password"],
            "humanity"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"],
            "www.ignitelimit.com"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["wsSettings"]["path"],
            "/assignment"
        );
    }

    #[test]
    fn rejects_xray_config_without_any_inbound_proxy() {
        let share = xray::parse_share_link("trojan://humanity@example.com:443?security=tls")
            .expect("parse share");
        let err = build_xray_config(&share, "127.0.0.1:40443", "", "", false, "warning")
            .expect_err("missing inbounds should fail");
        assert!(err.contains("enable at least one Xray inbound"));
    }

    #[test]
    fn builds_xray_config_with_tun_inbound() {
        let share = xray::parse_share_link("trojan://humanity@example.com:443?security=tls")
            .expect("parse share");
        let body = build_xray_config(&share, "127.0.0.1:40443", "", "", true, "warning")
            .expect("tun-only config should be valid");
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["inbounds"][0]["protocol"], "tun");
        assert_eq!(
            value["inbounds"][0]["settings"]["autoOutboundsInterface"],
            "auto"
        );
    }

    #[test]
    fn rewrites_unspecified_proxy_for_local_ip_check() {
        assert_eq!(
            connection_check_proxy_url("0.0.0.0:1080", "0.0.0.0:1081").unwrap(),
            "http://127.0.0.1:1080"
        );
        assert_eq!(
            connection_check_proxy_url("", "0.0.0.0:1081").unwrap(),
            "socks5h://127.0.0.1:1081"
        );
    }

    #[test]
    fn selects_share_links_from_multiline_import_text() {
        let text = "\n  vless://one@example.com:443?security=tls\n\n  trojan://two@example.com:443?security=tls\n";
        assert_eq!(share_line_count(text), 2);
        assert_eq!(
            selected_share_line(text, 1),
            Some("trojan://two@example.com:443?security=tls")
        );
    }

    #[test]
    fn rewrites_socket_host_for_lan_binding() {
        assert_eq!(
            replace_socket_host("127.0.0.1:40443", "0.0.0.0"),
            "0.0.0.0:40443"
        );
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct FormState {
    listen: String,
    connect: String,
    fake_sni: String,
    conn_timeout_sec: String,
    handshake_timeout_sec: String,
    keepalive_time_sec: String,
    keepalive_interval_sec: String,
    idle_timeout: String,
    buffer_size: String,
    graceful_shutdown_sec: String,
}

impl FormState {
    fn from_config(cfg: &Config) -> Self {
        let listener = cfg
            .listeners
            .first()
            .cloned()
            .unwrap_or_else(ListenerConfig::default);
        Self {
            listen: listener.listen.to_string(),
            connect: listener.connect.to_string(),
            fake_sni: listener.fake_sni,
            conn_timeout_sec: listener.conn_timeout_sec.to_string(),
            handshake_timeout_sec: listener.handshake_timeout_sec.to_string(),
            keepalive_time_sec: listener.keepalive_time_sec.to_string(),
            keepalive_interval_sec: listener.keepalive_interval_sec.to_string(),
            idle_timeout: cfg.idle_timeout.map(|v| v.to_string()).unwrap_or_default(),
            buffer_size: cfg.buffer_size.to_string(),
            graceful_shutdown_sec: cfg.graceful_shutdown_sec.to_string(),
        }
    }

    fn to_config(&self) -> Result<Config, String> {
        let listener = ListenerConfig {
            listen: self
                .listen
                .trim()
                .parse()
                .map_err(|e| format!("invalid listen address: {}", e))?,
            connect: self
                .connect
                .trim()
                .parse()
                .map_err(|e| format!("invalid connect address: {}", e))?,
            fake_sni: self.fake_sni.trim().to_string(),
            conn_timeout_sec: parse_u64("conn_timeout_sec", &self.conn_timeout_sec)?,
            handshake_timeout_sec: parse_u64("handshake_timeout_sec", &self.handshake_timeout_sec)?,
            keepalive_time_sec: parse_u64("keepalive_time_sec", &self.keepalive_time_sec)?,
            keepalive_interval_sec: parse_u64(
                "keepalive_interval_sec",
                &self.keepalive_interval_sec,
            )?,
        };
        let cfg = Config {
            idle_timeout: parse_optional_u64("idle_timeout", &self.idle_timeout)?,
            buffer_size: parse_usize("buffer_size", &self.buffer_size)?,
            listeners: vec![listener],
            graceful_shutdown_sec: parse_u64("graceful_shutdown_sec", &self.graceful_shutdown_sec)?,
        };
        config::validate(&cfg).map_err(|e| e.to_string())?;
        Ok(cfg)
    }
}

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("invalid {}: {}", name, e))
}

fn parse_optional_u64(name: &str, value: &str) -> Result<Option<u64>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        parse_u64(name, trimmed).map(Some)
    }
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|e| format!("invalid {}: {}", name, e))
}

enum ScanMsg {
    Started(usize),
    Result(ProbeResult),
    Finished,
    Failed(String),
}

fn spawn_scan(
    tx: Sender<ScanMsg>,
    target: SocketAddr,
    timeout: Duration,
    concurrency: usize,
    snis: Vec<String>,
) {
    std::thread::Builder::new()
        .name("sni-scan".into())
        .spawn(move || {
            if tx.send(ScanMsg::Started(snis.len())).is_err() {
                return;
            }
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(ScanMsg::Failed(e.to_string()));
                    return;
                }
            };
            rt.block_on(async move {
                let sem = Arc::new(Semaphore::new(concurrency));
                let mut handles = Vec::with_capacity(snis.len());
                for sni in snis {
                    let sem = sem.clone();
                    handles.push(tokio::spawn(async move {
                        let _permit = sem.acquire_owned().await.ok();
                        scan::probe_sni(target, sni, timeout).await
                    }));
                }

                for handle in handles {
                    match handle.await {
                        Ok(result) => {
                            if tx.send(ScanMsg::Result(result)).is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(ScanMsg::Failed(e.to_string()));
                            return;
                        }
                    }
                }
                let _ = tx.send(ScanMsg::Finished);
            });
        })
        .expect("failed to spawn scan thread");
}
