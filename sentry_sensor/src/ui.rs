use crossbeam_channel::{Receiver, Sender};
use eframe::egui;
use std::collections::VecDeque;

// ─── Theme Constants ────────────────────────────────────────────────────────

const BG_DARK: egui::Color32 = egui::Color32::from_rgb(18, 18, 24);
const CARD_BG: egui::Color32 = egui::Color32::from_rgb(28, 28, 38);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(80, 140, 255);
const GREEN: egui::Color32 = egui::Color32::from_rgb(60, 210, 120);
const RED: egui::Color32 = egui::Color32::from_rgb(240, 80, 80);
const YELLOW: egui::Color32 = egui::Color32::from_rgb(240, 200, 60);
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(140, 140, 160);
const TEXT_BRIGHT: egui::Color32 = egui::Color32::from_rgb(230, 230, 240);
const LOG_BG: egui::Color32 = egui::Color32::from_rgb(12, 12, 16);

// ─── State & Messages ───────────────────────────────────────────────────────

pub enum UiState {
    Login,
    Dashboard,
}

pub enum BackendCommand {
    Login { username: String, password: String },
    Logout,
    ToggleKillSwitch(bool),
}

pub enum BackendEvent {
    Log(String),
    AuthResult(bool),
    KillSwitchState(bool),
    SensorState(bool),
    ConnectionState(bool),
    FlowCaptured(crate::schema::FlowRecord),
}

pub struct SentryApp {
    state: UiState,

    // Login
    username: String,
    password: String,
    service_url: String,
    login_error: Option<String>,

    // Dashboard
    kill_switch_enabled: bool,
    sensor_running: bool,
    connected_to_service: bool,
    network_blocked: bool,
    flow_count: u64,
    logs: VecDeque<String>,
    recent_flows: VecDeque<crate::schema::FlowRecord>,

    // Channels
    tx: Sender<BackendCommand>,
    rx: Receiver<BackendEvent>,
    tray_rx: Option<Receiver<bool>>,
}

impl SentryApp {
    pub fn new(tx: Sender<BackendCommand>, rx: Receiver<BackendEvent>) -> Self {
        let config = crate::config::SentryConfig::load();
        Self {
            state: UiState::Login,
            username: config.nats_username,
            password: String::new(),
            service_url: config.nats_url,
            login_error: None,
            kill_switch_enabled: false,
            sensor_running: false,
            connected_to_service: false,
            network_blocked: false,
            flow_count: 0,
            logs: VecDeque::new(),
            recent_flows: VecDeque::new(),
            tx,
            rx,
            tray_rx: None,
        }
    }

    pub fn new_with_tray(
        tx: Sender<BackendCommand>,
        rx: Receiver<BackendEvent>,
        tray_rx: Receiver<bool>,
    ) -> Self {
        let mut app = Self::new(tx, rx);
        app.tray_rx = Some(tray_rx);
        app
    }

    fn process_events(&mut self, ctx: &egui::Context) {
        if let Some(tray_rx) = &self.tray_rx {
            while let Ok(show) = tray_rx.try_recv() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(show));
            }
        }

        while let Ok(event) = self.rx.try_recv() {
            match event {
                BackendEvent::Log(msg) => {
                    self.logs.push_back(msg);
                    if self.logs.len() > 200 {
                        self.logs.pop_front();
                    }
                }
                BackendEvent::AuthResult(success) => {
                    if success {
                        self.state = UiState::Dashboard;
                        self.login_error = None;
                    } else {
                        self.state = UiState::Login;
                        self.login_error =
                            Some("Authentication failed. Check credentials.".to_string());
                    }
                }
                BackendEvent::KillSwitchState(active) => {
                    self.kill_switch_enabled = active;
                }
                BackendEvent::SensorState(running) => {
                    self.sensor_running = running;
                }
                BackendEvent::ConnectionState(connected) => {
                    self.connected_to_service = connected;
                    self.network_blocked = self.kill_switch_enabled;
                }
                BackendEvent::FlowCaptured(record) => {
                    self.flow_count += 1;
                    self.recent_flows.push_back(record);
                    if self.recent_flows.len() > 50 {
                        self.recent_flows.pop_front();
                    }
                }
            }
        }

        // Recompute network_blocked state each frame
        self.network_blocked = self.kill_switch_enabled;
    }

    // ─── Login Screen ───────────────────────────────────────────────────────

    fn render_login(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.label(egui::RichText::new("🛡").size(48.0));
            ui.add_space(12.0);
            ui.label(
                egui::RichText::new("AttackSentry")
                    .size(28.0)
                    .strong()
                    .color(TEXT_BRIGHT),
            );
            ui.label(
                egui::RichText::new("Network Detection & Response Sensor")
                    .size(13.0)
                    .color(TEXT_DIM),
            );
            ui.add_space(40.0);

            // Login card
            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(32.0, 28.0))
                .rounding(14.0)
                .fill(CARD_BG)
                .show(ui, |ui| {
                    ui.set_max_width(320.0);

                    ui.label(
                        egui::RichText::new("Sign In")
                            .size(18.0)
                            .strong()
                            .color(TEXT_BRIGHT),
                    );
                    ui.add_space(20.0);

                    ui.label(egui::RichText::new("Username").size(12.0).color(TEXT_DIM));
                    ui.add_space(4.0);
                    let username_edit = egui::TextEdit::singleline(&mut self.username)
                        .desired_width(f32::INFINITY)
                        .margin(egui::Margin::symmetric(10.0, 8.0));
                    ui.add(username_edit);

                    ui.add_space(14.0);

                    ui.label(egui::RichText::new("Password").size(12.0).color(TEXT_DIM));
                    ui.add_space(4.0);
                    let password_edit = egui::TextEdit::singleline(&mut self.password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .margin(egui::Margin::symmetric(10.0, 8.0));
                    ui.add(password_edit);

                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(format!("Service: {}", self.service_url))
                            .size(10.0)
                            .color(TEXT_DIM),
                    );

                    ui.add_space(14.0);

                    let connect_btn = ui.add_sized(
                        [ui.available_width(), 38.0],
                        egui::Button::new(
                            egui::RichText::new("Connect to Sentry Service")
                                .strong()
                                .color(egui::Color32::WHITE),
                        )
                        .fill(ACCENT)
                        .rounding(8.0),
                    );
                    if connect_btn.clicked() {
                        let _ = self.tx.send(BackendCommand::Login {
                            username: self.username.clone(),
                            password: self.password.clone(),
                        });
                        self.login_error = None;
                    }

                    if let Some(err) = &self.login_error {
                        ui.add_space(12.0);
                        ui.label(egui::RichText::new(err).size(12.0).color(RED));
                    }
                });
        });
    }

    // ─── Dashboard ──────────────────────────────────────────────────────────

    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(8.0);

            // ── Header row ──
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Dashboard")
                        .size(20.0)
                        .strong()
                        .color(TEXT_BRIGHT),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Disconnect & quit")
                                    .size(12.0)
                                    .color(TEXT_DIM),
                            )
                            .rounding(6.0),
                        )
                        .clicked()
                    {
                        let _ = self.tx.send(BackendCommand::Logout);
                        self.state = UiState::Login;
                        self.username.clear();
                        self.password.clear();
                    }
                });
            });
            ui.add_space(12.0);

            // ── Status Cards Row ──
            ui.columns(3, |cols| {
                // Card 1: Connection
                Self::render_status_card(
                    &mut cols[0],
                    "Service Connection",
                    if self.connected_to_service {
                        "CONNECTED"
                    } else {
                        "DISCONNECTED"
                    },
                    if self.connected_to_service {
                        GREEN
                    } else {
                        RED
                    },
                    if self.connected_to_service {
                        "●"
                    } else {
                        "○"
                    },
                );

                // Card 2: Sensor
                Self::render_status_card(
                    &mut cols[1],
                    "Capture Engine",
                    if self.sensor_running {
                        "RUNNING"
                    } else {
                        "STOPPED"
                    },
                    if self.sensor_running { GREEN } else { YELLOW },
                    if self.sensor_running { "●" } else { "○" },
                );

                // Card 3: Flows
                Self::render_status_card(
                    &mut cols[2],
                    "Flows Captured",
                    &self.flow_count.to_string(),
                    ACCENT,
                    "⬡",
                );
            });

            ui.add_space(16.0);

            // ── Controls Card ──
            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(16.0, 14.0))
                .rounding(12.0)
                .fill(CARD_BG)
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("Controls")
                            .size(14.0)
                            .strong()
                            .color(TEXT_BRIGHT),
                    );
                    ui.add_space(12.0);

                    // Explicit local emergency isolation
                    ui.horizontal(|ui| {
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Emergency isolation").color(TEXT_BRIGHT));
                        ui.add_space(8.0);

                        let toggle_text = if self.kill_switch_enabled {
                            "Enabled"
                        } else {
                            "Disabled"
                        };
                        let toggle_color = if self.kill_switch_enabled {
                            GREEN
                        } else {
                            TEXT_DIM
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new(toggle_text)
                                        .size(12.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(toggle_color.linear_multiply(0.6))
                                .rounding(10.0),
                            )
                            .clicked()
                        {
                            self.kill_switch_enabled = !self.kill_switch_enabled;
                            let _ = self
                                .tx
                                .send(BackendCommand::ToggleKillSwitch(self.kill_switch_enabled));
                        }

                        ui.add_space(12.0);

                        // Network status indicator
                        if self.network_blocked {
                            ui.label(
                                egui::RichText::new("⛔ Outbound traffic isolated locally")
                                    .size(11.0)
                                    .color(RED),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new("— Isolation disabled (safe default)")
                                    .size(11.0)
                                    .color(TEXT_DIM),
                            );
                        }
                    });
                });

            ui.add_space(16.0);

            // ── Live Telemetry ──
            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(16.0, 14.0))
                .rounding(12.0)
                .fill(CARD_BG)
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("Live Network Telemetry")
                            .size(14.0)
                            .strong()
                            .color(TEXT_BRIGHT),
                    );
                    ui.add_space(8.0);

                    egui::ScrollArea::vertical()
                        .id_source("flows_scroll")
                        .max_height(160.0)
                        .show(ui, |ui| {
                            egui::Grid::new("flow_grid")
                                .striped(true)
                                .min_col_width(55.0)
                                .spacing([8.0, 4.0])
                                .show(ui, |ui| {
                                    for label in
                                        ["Time", "Source", "Destination", "Proto", "Bytes", "Pkts"]
                                    {
                                        ui.label(
                                            egui::RichText::new(label)
                                                .size(11.0)
                                                .strong()
                                                .color(ACCENT),
                                        );
                                    }
                                    ui.end_row();

                                    for flow in self.recent_flows.iter().rev().take(25) {
                                        let t = if flow.timestamp.len() >= 19 {
                                            &flow.timestamp[11..19]
                                        } else {
                                            &flow.timestamp
                                        };
                                        ui.label(
                                            egui::RichText::new(t)
                                                .size(11.0)
                                                .family(egui::FontFamily::Monospace)
                                                .color(TEXT_DIM),
                                        );
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}:{}",
                                                flow.src_ip, flow.src_port
                                            ))
                                            .size(11.0)
                                            .color(TEXT_BRIGHT),
                                        );
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}:{}",
                                                flow.dst_ip, flow.dst_port
                                            ))
                                            .size(11.0)
                                            .color(TEXT_BRIGHT),
                                        );
                                        ui.label(
                                            egui::RichText::new(flow.protocol.to_string())
                                                .size(11.0)
                                                .color(TEXT_DIM),
                                        );
                                        ui.label(
                                            egui::RichText::new(
                                                (flow.total_fwd_bytes + flow.total_bwd_bytes)
                                                    .to_string(),
                                            )
                                            .size(11.0)
                                            .color(TEXT_BRIGHT),
                                        );
                                        ui.label(
                                            egui::RichText::new(
                                                (flow.total_fwd_packets + flow.total_bwd_packets)
                                                    .to_string(),
                                            )
                                            .size(11.0)
                                            .color(TEXT_BRIGHT),
                                        );
                                        ui.end_row();
                                    }
                                });
                        });
                });

            ui.add_space(16.0);

            // ── System Logs ──
            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(16.0, 14.0))
                .rounding(12.0)
                .fill(CARD_BG)
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("System Logs")
                            .size(14.0)
                            .strong()
                            .color(TEXT_BRIGHT),
                    );
                    ui.add_space(8.0);

                    egui::Frame::none()
                        .inner_margin(8.0)
                        .rounding(8.0)
                        .fill(LOG_BG)
                        .show(ui, |ui| {
                            egui::ScrollArea::vertical()
                                .id_source("logs_scroll")
                                .max_height(120.0)
                                .stick_to_bottom(true)
                                .show(ui, |ui| {
                                    for log_line in &self.logs {
                                        ui.label(
                                            egui::RichText::new(log_line)
                                                .family(egui::FontFamily::Monospace)
                                                .size(11.0)
                                                .color(TEXT_DIM),
                                        );
                                    }
                                });
                        });
                });

            ui.add_space(12.0);
        });
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    fn render_status_card(
        ui: &mut egui::Ui,
        title: &str,
        value: &str,
        color: egui::Color32,
        icon: &str,
    ) {
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(14.0, 14.0))
            .rounding(12.0)
            .fill(CARD_BG)
            .show(ui, |ui| {
                ui.label(egui::RichText::new(title).size(11.0).color(TEXT_DIM));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(icon).size(16.0).color(color));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(value).size(16.0).strong().color(color));
                });
            });
    }
}

// ─── eframe::App ─────────────────────────────────────────────────────────────

impl eframe::App for SentryApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_events(ctx);

        // ── Global visuals ──
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG_DARK;
        visuals.window_rounding = egui::Rounding::same(14.0);
        visuals.widgets.noninteractive.rounding = egui::Rounding::same(8.0);
        visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
        visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
        visuals.widgets.active.rounding = egui::Rounding::same(8.0);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(38, 38, 50);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(50, 50, 65);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(60, 60, 78);
        ctx.set_visuals(visuals);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(14.0, 6.0);
        ctx.set_style(style);

        // ── Main Content ──
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG_DARK)
                    .inner_margin(egui::Margin::symmetric(20.0, 12.0)),
            )
            .show(ctx, |ui| match self.state {
                UiState::Login => self.render_login(ui),
                UiState::Dashboard => self.render_dashboard(ui),
            });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
