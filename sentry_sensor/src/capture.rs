use crate::schema::FlowRecord;
use chrono::{DateTime, Utc};
use etherparse::{PacketHeaders, TransportHeader};
use pcap::Capture;
use std::collections::HashMap;
use tokio::sync::mpsc::Sender;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

struct TcpFlags {
    fin: u32,
    syn: u32,
    rst: u32,
    psh: u32,
    ack: u32,
    urg: u32,
}

struct FlowState {
    record: FlowRecord,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    iat_total: f64,
    iat_count: u32,
    iat_sq_sum: f64,
    iat_max: f64,
    iat_min: f64,
    pkt_count: u32,
    pkt_len_sum: f64,
    pkt_len_sq_sum: f64,
    max_pkt_len: f64,
    fwd_pkt_count: u32,
    fwd_len_sum: f64,
    fwd_len_sq_sum: f64,
    fwd_len_min: f64,
    fwd_len_max: f64,
    bwd_pkt_count: u32,
    bwd_len_sum: f64,
    bwd_len_sq_sum: f64,
    bwd_len_min: f64,
    bwd_len_max: f64,
}

pub struct CaptureEngine {
    tx: Sender<FlowRecord>,
}

impl CaptureEngine {
    pub fn new(tx: Sender<FlowRecord>) -> Self {
        Self { tx }
    }

    pub async fn start_capture(&self, device_name: &str) -> Result<(), String> {
        let is_any = device_name == "any";
        let mut cap = Capture::from_device(device_name)
            .map_err(|e| format!("Error parsing device name: {:?}", e))?
            .promisc(!is_any)
            .snaplen(65535)
            .timeout(100)
            .open()
            .map_err(|e| {
                format!(
                    "Failed to open capture device. Ensure you have admin privileges: {:?}",
                    e
                )
            })?;

        let tx = self.tx.clone();

        // Run the blocking pcap capture loop in a separate thread
        tokio::task::spawn_blocking(move || {
            let mut flow_table: HashMap<FlowKey, FlowState> = HashMap::new();
            let flow_timeout = chrono::Duration::seconds(5); // Export inactive flows after 5s
            let mut last_cleanup = Utc::now();

            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        let bytes = packet.header.len as usize;
                        let now = Utc::now();

                        // Try parsing packet safely with fallbacks (Ethernet -> IP -> Loopback)
                        let headers_opt = PacketHeaders::from_ethernet_slice(packet.data)
                            .ok()
                            .or_else(|| PacketHeaders::from_ip_slice(packet.data).ok())
                            .or_else(|| {
                                if packet.data.len() > 16 {
                                    PacketHeaders::from_ip_slice(&packet.data[16..]).ok()
                                } else {
                                    None
                                }
                            })
                            .or_else(|| {
                                if packet.data.len() > 4 {
                                    PacketHeaders::from_ip_slice(&packet.data[4..]).ok()
                                } else {
                                    None
                                }
                            });

                        if let Some(headers) = headers_opt {
                            if let Some((fwd_key, bwd_key, flags, ttl)) =
                                extract_packet_info(&headers)
                            {
                                // Determine direction and which key to use
                                let (key, is_forward) = if flow_table.contains_key(&bwd_key) {
                                    (bwd_key, false)
                                } else {
                                    (fwd_key, true)
                                };

                                let state =
                                    flow_table.entry(key.clone()).or_insert_with(|| FlowState {
                                        record: FlowRecord {
                                            src_ip: key.src_ip.clone(),
                                            dst_ip: key.dst_ip.clone(),
                                            src_port: key.src_port,
                                            dst_port: key.dst_port,
                                            protocol: key.protocol,
                                            flow_duration: 0.0,
                                            total_fwd_packets: 0,
                                            total_bwd_packets: 0,
                                            total_fwd_bytes: 0,
                                            total_bwd_bytes: 0,
                                            flow_iat_mean: 0.0,
                                            fin_flag_count: 0,
                                            syn_flag_count: 0,
                                            rst_flag_count: 0,
                                            psh_flag_count: 0,
                                            ack_flag_count: 0,
                                            urg_flag_count: 0,
                                            ttl,
                                            timestamp: now.to_rfc3339(),
                                            ..Default::default()
                                        },
                                        first_seen: now,
                                        last_seen: now,
                                        iat_total: 0.0,
                                        iat_count: 0,
                                        iat_sq_sum: 0.0,
                                        iat_max: 0.0,
                                        iat_min: f64::MAX,
                                        pkt_count: 0,
                                        pkt_len_sum: 0.0,
                                        pkt_len_sq_sum: 0.0,
                                        max_pkt_len: 0.0,
                                        fwd_pkt_count: 0,
                                        fwd_len_sum: 0.0,
                                        fwd_len_sq_sum: 0.0,
                                        fwd_len_min: f64::MAX,
                                        fwd_len_max: 0.0,
                                        bwd_pkt_count: 0,
                                        bwd_len_sum: 0.0,
                                        bwd_len_sq_sum: 0.0,
                                        bwd_len_min: f64::MAX,
                                        bwd_len_max: 0.0,
                                    });

                                // Update packet length metrics
                                state.pkt_count += 1;
                                let pkt_len = bytes as f64;
                                state.pkt_len_sum += pkt_len;
                                state.pkt_len_sq_sum += pkt_len * pkt_len;
                                if pkt_len > state.max_pkt_len {
                                    state.max_pkt_len = pkt_len;
                                }

                                // Update flow metrics
                                let iat =
                                    (now - state.last_seen).num_milliseconds() as f64 / 1000.0;
                                if iat > 0.0 {
                                    state.iat_total += iat;
                                    state.iat_count += 1;
                                    state.record.flow_iat_mean =
                                        state.iat_total / (state.iat_count as f64);

                                    state.iat_sq_sum += iat * iat;
                                    if iat > state.iat_max {
                                        state.iat_max = iat;
                                    }
                                    if iat < state.iat_min {
                                        state.iat_min = iat;
                                    }
                                }

                                state.last_seen = now;
                                let duration =
                                    (now - state.first_seen).num_milliseconds() as f64 / 1000.0;
                                state.record.flow_duration = duration;

                                if is_forward {
                                    state.record.total_fwd_packets += 1;
                                    state.record.total_fwd_bytes += bytes as u64;
                                    state.fwd_pkt_count += 1;
                                    state.fwd_len_sum += pkt_len;
                                    state.fwd_len_sq_sum += pkt_len * pkt_len;
                                    if pkt_len < state.fwd_len_min {
                                        state.fwd_len_min = pkt_len;
                                    }
                                    if pkt_len > state.fwd_len_max {
                                        state.fwd_len_max = pkt_len;
                                    }
                                } else {
                                    state.record.total_bwd_packets += 1;
                                    state.record.total_bwd_bytes += bytes as u64;
                                    state.bwd_pkt_count += 1;
                                    state.bwd_len_sum += pkt_len;
                                    state.bwd_len_sq_sum += pkt_len * pkt_len;
                                    if pkt_len < state.bwd_len_min {
                                        state.bwd_len_min = pkt_len;
                                    }
                                    if pkt_len > state.bwd_len_max {
                                        state.bwd_len_max = pkt_len;
                                    }
                                }

                                state.record.fin_flag_count += flags.fin;
                                state.record.syn_flag_count += flags.syn;
                                state.record.rst_flag_count += flags.rst;
                                state.record.psh_flag_count += flags.psh;
                                state.record.ack_flag_count += flags.ack;
                                state.record.urg_flag_count += flags.urg;

                                // Update T2 metrics in record
                                if state.pkt_count > 0 {
                                    let mean = state.pkt_len_sum / state.pkt_count as f64;
                                    state.record.pkt_len_mean = Some(mean);
                                    let variance = (state.pkt_len_sq_sum / state.pkt_count as f64)
                                        - (mean * mean);
                                    state.record.pkt_len_std =
                                        Some(if variance > 0.0 { variance.sqrt() } else { 0.0 });
                                    state.record.max_pkt_len = Some(state.max_pkt_len);
                                }

                                if state.fwd_pkt_count > 0 {
                                    let m = state.fwd_len_sum / state.fwd_pkt_count as f64;
                                    let v = (state.fwd_len_sq_sum / state.fwd_pkt_count as f64)
                                        - (m * m);
                                    state.record.fwd_pkt_len_mean = Some(m);
                                    state.record.fwd_pkt_len_std =
                                        Some(if v > 0.0 { v.sqrt() } else { 0.0 });
                                    state.record.fwd_pkt_len_min = Some(state.fwd_len_min);
                                    state.record.fwd_pkt_len_max = Some(state.fwd_len_max);
                                }

                                if state.bwd_pkt_count > 0 {
                                    let m = state.bwd_len_sum / state.bwd_pkt_count as f64;
                                    let v = (state.bwd_len_sq_sum / state.bwd_pkt_count as f64)
                                        - (m * m);
                                    state.record.bwd_pkt_len_mean = Some(m);
                                    state.record.bwd_pkt_len_std =
                                        Some(if v > 0.0 { v.sqrt() } else { 0.0 });
                                    state.record.bwd_pkt_len_min = Some(state.bwd_len_min);
                                    state.record.bwd_pkt_len_max = Some(state.bwd_len_max);
                                }

                                if state.iat_count > 0 {
                                    state.record.flow_iat_max = Some(state.iat_max);
                                    state.record.flow_iat_min = Some(state.iat_min);
                                    let iat_mean = state.record.flow_iat_mean;
                                    let variance = (state.iat_sq_sum / state.iat_count as f64)
                                        - (iat_mean * iat_mean);
                                    state.record.flow_iat_std =
                                        Some(if variance > 0.0 { variance.sqrt() } else { 0.0 });
                                }

                                if duration > 0.0 {
                                    state.record.flow_bytes_sec = Some(
                                        (state.record.total_fwd_bytes
                                            + state.record.total_bwd_bytes)
                                            as f64
                                            / duration,
                                    );
                                    state.record.flow_packets_sec = Some(
                                        (state.record.total_fwd_packets
                                            + state.record.total_bwd_packets)
                                            as f64
                                            / duration,
                                    );
                                }
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Ignore timeouts, just keep listening
                    }
                    Err(e) => {
                        println!("DEBUG: Capture loop encountered an error: {:?}", e);
                        break;
                    }
                }

                // Cleanup and export expired/completed flows periodically
                let now = Utc::now();
                if (now - last_cleanup).num_milliseconds() > 1000 {
                    last_cleanup = now;
                    let mut expired_keys = Vec::new();

                    for (key, state) in flow_table.iter() {
                        let inactive_time = now - state.last_seen;

                        // Export if inactive for 5s OR if the flow represents a closed TCP connection (FIN or RST)
                        if inactive_time > flow_timeout
                            || state.record.fin_flag_count > 0
                            || state.record.rst_flag_count > 0
                        {
                            let _ = tx.blocking_send(state.record.clone());
                            expired_keys.push(key.clone());
                        }
                    }

                    for key in expired_keys {
                        flow_table.remove(&key);
                    }
                }
            }
        });

        Ok(())
    }
}

fn extract_packet_info(headers: &PacketHeaders) -> Option<(FlowKey, FlowKey, TcpFlags, u8)> {
    // Extract IP addresses and TTL/Protocol
    let (src_ip, dst_ip, ttl, protocol_num) = match headers.net {
        Some(etherparse::NetHeaders::Ipv4(ref h, _)) => (
            std::net::IpAddr::V4(h.source.into()),
            std::net::IpAddr::V4(h.destination.into()),
            h.time_to_live,
            h.protocol,
        ),
        Some(etherparse::NetHeaders::Ipv6(ref h, _)) => (
            std::net::IpAddr::V6(h.source.into()),
            std::net::IpAddr::V6(h.destination.into()),
            h.hop_limit,
            h.next_header,
        ),
        _ => return None, // Skip non-IP packets
    };

    // Extract Ports and TCP flags
    let mut src_port = 0;
    let mut dst_port = 0;
    let mut flags = TcpFlags {
        fin: 0,
        syn: 0,
        rst: 0,
        psh: 0,
        ack: 0,
        urg: 0,
    };

    if let Some(transport) = &headers.transport {
        match transport {
            TransportHeader::Tcp(h) => {
                src_port = h.source_port;
                dst_port = h.destination_port;
                if h.fin {
                    flags.fin = 1;
                }
                if h.syn {
                    flags.syn = 1;
                }
                if h.rst {
                    flags.rst = 1;
                }
                if h.psh {
                    flags.psh = 1;
                }
                if h.ack {
                    flags.ack = 1;
                }
                if h.urg {
                    flags.urg = 1;
                }
            }
            TransportHeader::Udp(h) => {
                src_port = h.source_port;
                dst_port = h.destination_port;
            }
            _ => {
                // Not TCP or UDP, keep ports as 0
            }
        }
    }

    let fwd_key = FlowKey {
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port,
        dst_port,
        protocol: protocol_num.into(),
    };

    let bwd_key = FlowKey {
        src_ip: dst_ip.to_string(),
        dst_ip: src_ip.to_string(),
        src_port: dst_port,
        dst_port: src_port,
        protocol: protocol_num.into(),
    };

    Some((fwd_key, bwd_key, flags, ttl))
}
