#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

mod capture;
mod config;
mod exporter;
mod kill_switch;
mod schema;
mod ui;

use crate::capture::CaptureEngine;
use crate::config::SentryConfig;
use crate::kill_switch::KillSwitch;
use crate::ui::{BackendCommand, BackendEvent};
use crossbeam_channel::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

fn main() -> eframe::Result<()> {
    // CLI health check used by installers and support:
    //   SENTRY_TEST_CONNECTION=1 ./attacksentry-sensor
    if std::env::var("SENTRY_TEST_CONNECTION").is_ok() {
        run_connection_test();
        return Ok(());
    }

    // Headless mode: run the capture+export agent without a GUI.
    let headless = std::env::var("SENTRY_HEADLESS")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
        || SentryConfig::load().headless;
    if headless {
        run_headless();
        return Ok(());
    }

    let (tray_tx, tray_rx) = crossbeam_channel::unbounded();

    // Spawn tray event handler thread (non-critical — may fail on some desktops)
    let tray_tx_clone = tray_tx.clone();
    std::thread::spawn(move || {
        // Catch panics from GTK initialization issues
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let show_i = tray_icon::menu::MenuItem::new("Show UI", true, None);
            let hide_i = tray_icon::menu::MenuItem::new("Hide UI", true, None);
            let quit_i = tray_icon::menu::MenuItem::new("Quit", true, None);
            let menu = tray_icon::menu::Menu::new();
            let _ = menu.append_items(&[
                &show_i,
                &hide_i,
                &tray_icon::menu::PredefinedMenuItem::separator(),
                &quit_i,
            ]);

            let _tray_icon = match tray_icon::TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("AttackSentry Sensor")
                .build()
            {
                Ok(icon) => Some(icon),
                Err(e) => {
                    println!("Tray icon unavailable: {:?}", e);
                    return;
                }
            };

            let menu_channel = tray_icon::menu::MenuEvent::receiver();
            loop {
                if let Ok(event) = menu_channel.recv() {
                    if event.id == show_i.id() {
                        let _ = tray_tx_clone.send(true);
                    } else if event.id == hide_i.id() {
                        let _ = tray_tx_clone.send(false);
                    } else if event.id == quit_i.id() {
                        std::process::exit(0);
                    }
                }
            }
        }));

        if result.is_err() {
            eprintln!("Tray icon is not available on this desktop environment.");
        }
    });

    let (ui_tx, ui_rx) = crossbeam_channel::unbounded();
    let (backend_tx, backend_rx) = crossbeam_channel::unbounded();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            backend_loop(ui_tx, backend_rx).await;
        });
    });

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([860.0, 640.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title("AttackSentry Sensor"),
        ..Default::default()
    };

    eframe::run_native(
        "AttackSentry Sensor",
        options,
        Box::new(|_cc| Box::new(ui::SentryApp::new_with_tray(backend_tx, ui_rx, tray_rx))),
    )
}

fn run_connection_test() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let config = SentryConfig::load();
        println!("Service: {}", config.nats_url);
        println!("Username: {}", config.nats_username);
        match exporter::test_connection(
            &config.nats_url,
            &config.nats_username,
            config.nats_password.as_deref(),
        )
        .await
        {
            Ok(()) => println!("CONNECTED"),
            Err(error) => {
                eprintln!("FAILED: {error}");
                std::process::exit(2);
            }
        }
    });
}

fn run_headless() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let config = SentryConfig::load();
        println!(
            "AttackSentry Sensor — headless mode (device={}, nats={})",
            config.device, config.nats_url
        );

        let (tx_capture, mut rx_capture) = mpsc::channel::<crate::schema::FlowRecord>(10000);
        let (tx_exporter, rx_exporter) = mpsc::channel::<crate::schema::FlowRecord>(10000);

        // Broadcast: stamp subnet group + null defaults, then forward to exporter.
        let tx_exporter_clone = tx_exporter.clone();
        let sensor_id = config.sensor_id.clone();
        tokio::spawn(async move {
            while let Some(mut record) = rx_capture.recv().await {
                record.sensor_id = sensor_id.clone();
                record.user_id = None;
                record.identity_type = Some("sensor_user".to_string());
                let parts: Vec<&str> = record.src_ip.split('.').collect();
                if parts.len() == 4 {
                    let subnet = format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
                    record.source_subnet = Some(subnet.clone());
                    record.subnet_group = Some(classify_subnet(&record.src_ip));
                }
                if record.flow_iat_max.is_none() {
                    record.flow_iat_max = Some(0.0);
                }
                if record.flow_iat_min.is_none() {
                    record.flow_iat_min = Some(0.0);
                }
                if record.flow_iat_std.is_none() {
                    record.flow_iat_std = Some(0.0);
                }
                if tx_exporter_clone.send(record).await.is_err() {
                    break;
                }
            }
        });

        // Exporter.
        let nats_url = config.nats_url.clone();
        let subject = config.subject.clone();
        let username = config.nats_username.clone();
        let password = config.nats_password.clone();
        tokio::spawn(async move {
            exporter::start_exporter(rx_exporter, nats_url, subject, username, password).await;
        });

        // Capture engine.
        let engine = capture::CaptureEngine::new(tx_capture);
        if let Err(e) = engine.start_capture(&config.device).await {
            eprintln!("Capture error: {e}");
        }
    });
}

async fn backend_loop(ui_tx: Sender<BackendEvent>, backend_rx: Receiver<BackendCommand>) {
    let log = |msg: String| {
        println!("{}", msg);
        let _ = ui_tx.send(BackendEvent::Log(msg));
    };

    log("Starting Sentry Sensor...".to_string());

    let mut config = SentryConfig::load();
    let mut ks = KillSwitch::new();
    let mut authenticated = false;
    let mut sensor_started = false;
    let auth_username: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Emergency isolation is an explicit local control. It is never enabled
    // automatically by connectivity loss or by a backend command.
    let update_kill_switch = |ks: &mut KillSwitch, enabled: bool, ui_tx: &Sender<BackendEvent>| {
        if enabled && !ks.is_engaged() {
            ks.engage();
            let _ = ui_tx.send(BackendEvent::Log("Emergency isolation requested: outbound network control applied if privileges permit.".to_string()));
        } else if !enabled && ks.is_engaged() {
            ks.disengage();
            let _ = ui_tx.send(BackendEvent::Log(
                "Emergency isolation released.".to_string(),
            ));
        }
        let _ = ui_tx.send(BackendEvent::KillSwitchState(ks.is_engaged()));
    };

    // Initial state
    update_kill_switch(&mut ks, config.kill_switch_active, &ui_tx);

    // Check saved token for auto-login
    if config.nats_password.is_some() && !config.nats_username.is_empty() {
        match exporter::test_connection(
            &config.nats_url,
            &config.nats_username,
            config.nats_password.as_deref(),
        )
        .await
        {
            Ok(()) => {
                authenticated = true;
                *auth_username.lock().unwrap() = Some(config.nats_username.clone());
                log("Authenticated to the telemetry service using saved credentials.".to_string());
                let _ = ui_tx.send(BackendEvent::AuthResult(true));
                update_kill_switch(&mut ks, config.kill_switch_active, &ui_tx);
                let _ = ui_tx.send(BackendEvent::ConnectionState(true));
            }
            Err(error) => log(format!(
                "Saved telemetry credentials were rejected: {error}"
            )),
        }
    }

    loop {
        if let Ok(cmd) = backend_rx.try_recv() {
            match cmd {
                BackendCommand::Login { username, password } => {
                    log("Connecting to Sentry Service...".to_string());
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

                    if username.trim().is_empty() || password.is_empty() {
                        log("Authentication failed: username and password are required."
                            .to_string());
                        let _ = ui_tx.send(BackendEvent::AuthResult(false));
                        continue;
                    }
                    match exporter::test_connection(&config.nats_url, &username, Some(&password))
                        .await
                    {
                        Ok(()) => {
                            log("Authenticated to the telemetry service.".to_string());
                            config.nats_username = username.clone();
                            config.nats_password = Some(password);
                            config.save();
                            *auth_username.lock().unwrap() = Some(username);
                            authenticated = true;
                            let _ = ui_tx.send(BackendEvent::AuthResult(true));
                            update_kill_switch(&mut ks, config.kill_switch_active, &ui_tx);
                            let _ = ui_tx.send(BackendEvent::ConnectionState(true));
                        }
                        Err(error) => {
                            log(format!("Authentication failed: {error}"));
                            let _ = ui_tx.send(BackendEvent::AuthResult(false));
                        }
                    }
                }
                BackendCommand::Logout => {
                    log("Credentials cleared. Shutting down capture safely...".to_string());
                    config.nats_password = None;
                    config.save();
                    std::process::exit(0);
                }
                BackendCommand::ToggleKillSwitch(active) => {
                    config.kill_switch_active = active;
                    config.save();
                    log(format!(
                        "Emergency isolation {}",
                        if active { "enabled" } else { "disabled" }
                    ));
                    update_kill_switch(&mut ks, active, &ui_tx);
                }
            }
        }

        if authenticated && !sensor_started {
            sensor_started = true;
            let _ = ui_tx.send(BackendEvent::SensorState(true));

            let (tx_capture, mut rx_capture) = mpsc::channel::<crate::schema::FlowRecord>(10000);
            let (tx_exporter, rx_exporter) = mpsc::channel::<crate::schema::FlowRecord>(10000);

            // Broadcast flows to exporter + UI, enriching each record
            let ui_tx_clone_broadcast = ui_tx.clone();
            let username_ref = auth_username.clone();
            let sensor_id = config.sensor_id.clone();
            tokio::spawn(async move {
                while let Some(mut record) = rx_capture.recv().await {
                    record.sensor_id = sensor_id.clone();
                    // Stamp user identity
                    record.user_id = username_ref.lock().unwrap().clone();
                    record.identity_type = Some("sensor_user".to_string());

                    // Compute subnet from source IP (e.g. 10.223.66.238 → 10.223.66.0/24)
                    let parts: Vec<&str> = record.src_ip.split('.').collect();
                    if parts.len() == 4 {
                        let subnet = format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
                        record.source_subnet = Some(subnet.clone());
                        // Classify subnet group
                        record.subnet_group = Some(classify_subnet(&record.src_ip));
                    }

                    // Fill null defaults for IAT/rate fields (0.0 instead of null)
                    if record.flow_iat_max.is_none() {
                        record.flow_iat_max = Some(0.0);
                    }
                    if record.flow_iat_min.is_none() {
                        record.flow_iat_min = Some(0.0);
                    }
                    if record.flow_iat_std.is_none() {
                        record.flow_iat_std = Some(0.0);
                    }
                    if record.pkt_len_mean.is_none() {
                        record.pkt_len_mean = Some(0.0);
                    }
                    if record.pkt_len_std.is_none() {
                        record.pkt_len_std = Some(0.0);
                    }
                    if record.max_pkt_len.is_none() {
                        record.max_pkt_len = Some(0.0);
                    }
                    if record.flow_bytes_sec.is_none() {
                        record.flow_bytes_sec = Some(0.0);
                    }
                    if record.flow_packets_sec.is_none() {
                        record.flow_packets_sec = Some(0.0);
                    }

                    // Try to get process info from /proc (Linux only)
                    #[cfg(target_os = "linux")]
                    {
                        if record.process_name.is_none() {
                            if let Some((pid, name)) =
                                lookup_process(record.src_port, record.protocol)
                            {
                                record.process_id = Some(pid);
                                record.process_name = Some(name);
                            }
                        }
                    }

                    if tx_exporter.send(record.clone()).await.is_err() {
                        break;
                    }
                    let _ = ui_tx_clone_broadcast.send(BackendEvent::FlowCaptured(record));
                }
            });

            // Start Exporter
            let ui_tx_clone = ui_tx.clone();
            let nats_url = config.nats_url.clone();
            let subject = config.subject.clone();
            let username = config.nats_username.clone();
            let password = config.nats_password.clone();
            tokio::spawn(async move {
                let _ = ui_tx_clone.send(BackendEvent::Log("Exporter started.".to_string()));
                exporter::start_exporter(rx_exporter, nats_url, subject, username, password).await;
            });

            // Start Capture Engine
            let ui_tx_clone2 = ui_tx.clone();
            let configured_device = config.device.clone();
            tokio::spawn(async move {
                let device_name = if cfg!(target_os = "linux") {
                    if configured_device.is_empty() {
                        "any".to_string()
                    } else {
                        configured_device.clone()
                    }
                } else {
                    let device = match pcap::Device::list() {
                        Ok(devices) => {
                            let mut best_dev = None;
                            let mut fallback_dev = None;
                            for d in devices.clone() {
                                for addr in &d.addresses {
                                    if let std::net::IpAddr::V4(ipv4) = addr.addr {
                                        if !ipv4.is_loopback() && !ipv4.is_link_local() {
                                            best_dev = Some(d.clone());
                                            break;
                                        } else if ipv4.is_loopback() {
                                            fallback_dev = Some(d.clone());
                                        }
                                    }
                                }
                                if best_dev.is_some() {
                                    break;
                                }
                            }
                            best_dev
                                .or(fallback_dev)
                                .or_else(|| pcap::Device::lookup().ok().flatten())
                        }
                        Err(_) => pcap::Device::lookup().ok().flatten(),
                    };
                    device.map(|d| d.name).unwrap_or_else(|| "any".to_string())
                };

                let msg = format!("Capturing on: {}", device_name);
                let _ = ui_tx_clone2.send(BackendEvent::Log(msg));

                let engine = CaptureEngine::new(tx_capture);
                if let Err(e) = engine.start_capture(&device_name).await {
                    let _ = ui_tx_clone2.send(BackendEvent::Log(format!("Capture error: {:?}", e)));
                }
            });
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Classify an IP into a subnet group (RFC1918 private, loopback, or public).
fn classify_subnet(ip: &str) -> String {
    if ip.starts_with("10.") {
        "private_10".to_string()
    } else if ip.starts_with("172.") {
        // Check 172.16-31.x.x
        if let Some(second) = ip.split('.').nth(1).and_then(|s| s.parse::<u8>().ok()) {
            if (16..=31).contains(&second) {
                return "private_172".to_string();
            }
        }
        "public".to_string()
    } else if ip.starts_with("192.168.") {
        "private_192".to_string()
    } else if ip.starts_with("127.") {
        "loopback".to_string()
    } else {
        "public".to_string()
    }
}

/// Look up the process that owns a local port by reading /proc/net/{tcp,udp}.
/// Returns (pid, process_name) if found.
#[cfg(target_os = "linux")]
fn lookup_process(local_port: u16, protocol: u8) -> Option<(u32, String)> {
    // protocol 6 = TCP, 17 = UDP
    let proc_file = match protocol {
        6 => "/proc/net/tcp",
        17 => "/proc/net/udp",
        _ => return None,
    };

    let contents = std::fs::read_to_string(proc_file).ok()?;

    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        // Field 1 is local_address:port in hex (e.g., "0100007F:0035")
        let local_addr = fields[1];
        if let Some(hex_port) = local_addr.split(':').nth(1) {
            if let Ok(port) = u16::from_str_radix(hex_port, 16) {
                if port == local_port {
                    // Field 9 is the inode
                    if let Ok(inode) = fields[9].parse::<u64>() {
                        if inode == 0 {
                            continue;
                        }
                        // Search /proc/*/fd/ for this inode
                        return find_pid_for_inode(inode);
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn find_pid_for_inode(target_inode: u64) -> Option<(u32, String)> {
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    let socket_pattern = format!("socket:[{}]", target_inode);

    for entry in proc_dir.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_str()?;
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_path = format!("/proc/{}/fd", pid);
        let fd_dir = match std::fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_dir.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                if link.to_string_lossy() == socket_pattern {
                    // Read the process name
                    let comm_path = format!("/proc/{}/comm", pid);
                    let name = std::fs::read_to_string(comm_path)
                        .unwrap_or_else(|_| "unknown".to_string())
                        .trim()
                        .to_string();
                    return Some((pid, name));
                }
            }
        }
    }

    None
}
