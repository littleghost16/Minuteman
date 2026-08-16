use crate::logger::Database;
use crate::types::{ArpEntry, DhcpOption, LeaseSourceType, NetworkLease, OuiEntry};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

pub struct NetworkStack {
    leases_path: PathBuf,
    db: Database,
    stealth: bool,
    running: Arc<AtomicBool>,
}

impl NetworkStack {
    pub fn new(
        leases_path: impl AsRef<Path>,
        db: Database,
        stealth: bool,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            leases_path: leases_path.as_ref().to_path_buf(),
            db,
            stealth,
            running,
        }
    }

    pub async fn start(&self) -> Result<()> {
        if self.stealth {
            info!("Stealth mode active: L2/L3 active DHCP/ARP interrogation suppressed.");
            return Ok(());
        }

        info!(
            "Starting L2/L3 Network Stack Engine. Monitoring DHCP Leases at: {:?}",
            self.leases_path
        );

        // 1. Spawn Lease File Watcher (supports dnsmasq, ISC DHCP, Kea, OpenWrt)
        let leases_path = self.leases_path.clone();
        let db_watcher = self.db.clone();
        let running_watcher = self.running.clone();

        tokio::spawn(async move {
            let mut seen_leases: HashSet<String> = HashSet::new();

            while running_watcher.load(Ordering::Relaxed) {
                Self::poll_lease_sources(&leases_path, &db_watcher, &mut seen_leases).await;
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
        });

        // 2. Spawn Live UDP 67/68 DHCP Protocol Sniffer
        let db_sniffer = self.db.clone();
        let running_sniffer = self.running.clone();

        tokio::spawn(async move {
            Self::run_live_dhcp_sniffer(db_sniffer, running_sniffer).await;
        });

        // 3. Spawn ARP & Neighbor Cache Scanner
        let db_arp = self.db.clone();
        let running_arp = self.running.clone();

        tokio::spawn(async move {
            let mut seen_arp: HashSet<String> = HashSet::new();
            while running_arp.load(Ordering::Relaxed) {
                Self::poll_arp_neighbor_table(&db_arp, &mut seen_arp).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });

        Ok(())
    }

    async fn poll_lease_sources(
        leases_path: &Path,
        db: &Database,
        seen_leases: &mut HashSet<String>,
    ) {
        let mut found_file = false;

        // Check user provided path
        if leases_path.exists() {
            found_file = true;
            Self::parse_file_and_record(leases_path, db, seen_leases);
        }

        // Check common Unix/Linux DHCP lease paths
        let standard_paths = [
            "/var/lib/misc/dnsmasq.leases",
            "/var/lib/dhcp/dhcpd.leases",
            "/var/lib/dhcpd/dhcpd.leases",
            "/tmp/dhcp.leases",
            "/var/lib/kea/kea-leases4.csv",
        ];

        for &p_str in &standard_paths {
            let p = Path::new(p_str);
            if p.exists() && p != leases_path {
                found_file = true;
                Self::parse_file_and_record(p, db, seen_leases);
            }
        }

        if !found_file {
            debug!("No DHCP lease files found. Monitoring for live DHCP traffic and ARP table only.");
        }
    }

    fn parse_file_and_record(path: &Path, db: &Database, seen: &mut HashSet<String>) {
        if let Ok(content) = fs::read_to_string(path) {
            let path_str = path.to_string_lossy().to_string();

            if path_str.ends_with("dhcpd.leases") {
                // Parse ISC DHCP format
                for lease in Self::parse_isc_dhcpd_leases(&content) {
                    let key = format!("{}_{}", lease.mac_address, lease.ip_address);
                    if !seen.contains(&key) {
                        seen.insert(key);
                        info!(
                            "ISC DHCP Lease Ingested: MAC={}, IP={}, Hostname={:?}",
                            lease.mac_address, lease.ip_address, lease.hostname
                        );
                        let _ = db.record_lease(&lease);
                    }
                }
            } else if path_str.ends_with(".csv") {
                // Parse Kea CSV format
                for lease in Self::parse_kea_csv_leases(&content) {
                    let key = format!("{}_{}", lease.mac_address, lease.ip_address);
                    if !seen.contains(&key) {
                        seen.insert(key);
                        let _ = db.record_lease(&lease);
                    }
                }
            } else {
                // Parse dnsmasq / OpenWrt format
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    if let Some(lease) = Self::parse_dnsmasq_lease(trimmed) {
                        let key = format!("{}_{}", lease.mac_address, lease.ip_address);
                        if !seen.contains(&key) {
                            seen.insert(key);
                            info!(
                                "dnsmasq Lease Ingested: MAC={}, IP={}, Hostname={:?}",
                                lease.mac_address, lease.ip_address, lease.hostname
                            );
                            let _ = db.record_lease(&lease);
                        }
                    }
                }
            }
        }
    }

    pub fn parse_dnsmasq_lease(line: &str) -> Option<NetworkLease> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        let ts_sec = parts[0].parse::<i64>().unwrap_or_else(|_| Utc::now().timestamp());
        let mac = parts[1].to_lowercase();
        let ip = IpAddr::from_str(parts[2]).ok()?;
        let hostname = if parts[3] == "*" {
            None
        } else {
            Some(parts[3].to_string())
        };
        let client_id = if parts.len() > 4 && parts[4] != "*" {
            Some(parts[4].to_string())
        } else {
            None
        };

        let timestamp = DateTime::from_timestamp(ts_sec, 0).unwrap_or_else(Utc::now);

        Some(NetworkLease {
            timestamp,
            mac_address: mac,
            ip_address: ip,
            hostname,
            client_id,
            vendor_class: None,
            dhcp_fingerprint_opt55: None,
            parameter_request_list: Vec::new(),
            lease_duration_secs: None,
            source_type: LeaseSourceType::Dnsmasq,
        })
    }

    pub fn parse_isc_dhcpd_leases(content: &str) -> Vec<NetworkLease> {
        let mut leases = Vec::new();
        let mut current_ip: Option<IpAddr> = None;
        let mut current_mac: Option<String> = None;
        let mut current_host: Option<String> = None;
        let mut current_client_id: Option<String> = None;
        let mut current_starts: Option<DateTime<Utc>> = None;
        let mut current_ends: Option<DateTime<Utc>> = None;
        let mut in_lease = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("lease ") && trimmed.ends_with('{') {
                in_lease = true;
                let ip_str = trimmed[6..trimmed.len() - 1].trim();
                current_ip = IpAddr::from_str(ip_str).ok();
                current_mac = None;
                current_host = None;
                current_client_id = None;
                current_starts = None;
                current_ends = None;
            } else if trimmed == "}" && in_lease {
                if let (Some(ip), Some(mac)) = (current_ip, current_mac.clone()) {
                    let lease_duration = current_ends.and_then(|e| current_starts.map(|s| (e - s).num_seconds() as u32));
                    leases.push(NetworkLease {
                        timestamp: current_starts.unwrap_or_else(Utc::now),
                        mac_address: mac,
                        ip_address: ip,
                        hostname: current_host.clone(),
                        client_id: current_client_id.clone(),
                        vendor_class: None,
                        dhcp_fingerprint_opt55: None,
                        parameter_request_list: Vec::new(),
                        lease_duration_secs: lease_duration,
                        source_type: LeaseSourceType::IscDhcpd,
                    });
                }
                in_lease = false;
            } else if in_lease {
                if trimmed.starts_with("hardware ethernet ") {
                    let mac_str = trimmed[18..].trim_end_matches(';').trim().to_lowercase();
                    current_mac = Some(mac_str);
                } else if trimmed.starts_with("client-hostname ") {
                    let host_str = trimmed[16..].trim_end_matches(';').trim().replace('"', "");
                    current_host = Some(host_str);
                } else if trimmed.starts_with("uid ") {
                    let uid_str = trimmed[4..].trim_end_matches(';').trim().replace('"', "");
                    current_client_id = Some(uid_str);
                } else if trimmed.starts_with("starts ") {
                    let date_str = trimmed[7..].trim_end_matches(';').trim();
                    current_starts = Self::parse_isc_dhcpd_timestamp(date_str);
                } else if trimmed.starts_with("ends ") {
                    let date_str = trimmed[5..].trim_end_matches(';').trim();
                    current_ends = Self::parse_isc_dhcpd_timestamp(date_str);
                }
            }
        }

        leases
    }

    fn parse_isc_dhcpd_timestamp(date_str: &str) -> Option<DateTime<Utc>> {
        let parts: Vec<&str> = date_str.split_whitespace().collect();
        if parts.len() >= 5 {
            let weekday = parts[0];
            let date_parts: Vec<&str> = parts[1].split('/').collect();
            if date_parts.len() == 3 {
                let year = date_parts[2].parse::<i32>().ok()?;
                let month = date_parts[0].parse::<u32>().ok()?;
                let day = date_parts[1].parse::<u32>().ok()?;
                let time_parts: Vec<&str> = parts[2].split(':').collect();
                if time_parts.len() == 3 {
                    let hour = time_parts[0].parse::<u32>().ok()?;
                    let minute = time_parts[1].parse::<u32>().ok()?;
                    let second = time_parts[2].parse::<u32>().ok()?;
                    return Utc.with_ymd_and_hms(year, month, day, hour, minute, second).single();
                }
            }
        }
        None
    }

    pub fn parse_kea_csv_leases(content: &str) -> Vec<NetworkLease> {
        let mut leases = Vec::new();
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 9 {
                let ip_str = parts[0].trim();
                let mac_str = parts[1].trim().to_lowercase();
                let host_str = parts[8].trim();

                if let Ok(ip) = IpAddr::from_str(ip_str) {
                    leases.push(NetworkLease {
                        timestamp: Utc::now(),
                        mac_address: mac_str,
                        ip_address: ip,
                        hostname: if host_str.is_empty() { None } else { Some(host_str.to_string()) },
                        client_id: Some(parts[2].trim().to_string()),
                        vendor_class: None,
                        dhcp_fingerprint_opt55: None,
                        parameter_request_list: Vec::new(),
                        lease_duration_secs: None,
                        source_type: LeaseSourceType::Kea,
                    });
                }
            }
        }
        leases
    }

    async fn run_live_dhcp_sniffer(db: Database, running: Arc<AtomicBool>) {
        info!("Attempting to bind live UDP 67/68 DHCP packet sniffer...");

        let bind_addrs = ["0.0.0.0:67", "0.0.0.0:68", "0.0.0.0:6767"];
        let mut socket = None;

        for bind_addr in &bind_addrs {
            match UdpSocket::bind(bind_addr).await {
                Ok(s) => {
                    info!("Successfully bound DHCP sniffer to {}", bind_addr);
                    socket = Some(s);
                    break;
                }
                Err(e) => {
                    debug!("Failed to bind to {}: {:?}", bind_addr, e);
                }
            }
        }

        let socket = match socket {
            Some(s) => s,
            None => {
                error!("Failed to bind to any DHCP port. Binding to UDP 67/68 requires root/admin privileges.");
                return;
            }
        };

        let mut buf = [0u8; 2048];
        while running.load(Ordering::Relaxed) {
            match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _src))) => {
                    if let Some(lease) = Self::dissect_dhcp_packet(&buf[..len]) {
                        info!(
                            "Live DHCP Packet Captured: MAC={}, Requested IP={}, Hostname={:?}, Opt55 Fingerprint={:?}",
                            lease.mac_address, lease.ip_address, lease.hostname, lease.dhcp_fingerprint_opt55
                        );
                        let _ = db.record_lease(&lease);
                    }
                }
                _ => continue,
            }
        }
    }

    pub fn dissect_dhcp_packet(packet: &[u8]) -> Option<NetworkLease> {
        if packet.len() < 240 {
            return None;
        }

        let op = packet[0];
        if op != 1 && op != 2 {
            return None;
        }

        let hlen = packet[2] as usize;
        if hlen != 6 {
            return None;
        }
        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            packet[28], packet[29], packet[30], packet[31], packet[32], packet[33]
        );

        let yiaddr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let mut target_ip = IpAddr::V4(yiaddr);

        if packet[236..240] != [0x63, 0x82, 0x53, 0x63] {
            return None;
        }

        let mut pos = 240;
        let mut hostname: Option<String> = None;
        let mut vendor_class: Option<String> = None;
        let mut opt55_fp: Option<String> = None;
        let mut parameter_request_list: Vec<u8> = Vec::new();
        let mut client_id: Option<String> = None;
        let mut lease_duration_secs: Option<u32> = None;

        while pos < packet.len() {
            let opt_code = packet[pos];
            if opt_code == 255 {
                break;
            }
            if opt_code == 0 {
                pos += 1;
                continue;
            }

            if pos + 1 >= packet.len() {
                break;
            }
            let opt_len = packet[pos + 1] as usize;
            pos += 2;

            if pos + opt_len > packet.len() {
                break;
            }

            let opt_data = &packet[pos..pos + opt_len];
            match opt_code {
                12 => {
                    if let Ok(s) = std::str::from_utf8(opt_data) {
                        hostname = Some(s.to_string());
                    }
                }
                50 => {
                    if opt_data.len() == 4 {
                        let req_ip = Ipv4Addr::new(opt_data[0], opt_data[1], opt_data[2], opt_data[3]);
                        target_ip = IpAddr::V4(req_ip);
                    }
                }
                51 => {
                    if opt_data.len() == 4 {
                        let duration = u32::from_be_bytes([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]);
                        lease_duration_secs = Some(duration);
                    }
                }
                55 => {
                    parameter_request_list = opt_data.to_vec();
                    let fp_list: Vec<String> = opt_data.iter().map(|b| b.to_string()).collect();
                    opt55_fp = Some(fp_list.join(","));
                }
                60 => {
                    if let Ok(s) = std::str::from_utf8(opt_data) {
                        vendor_class = Some(s.to_string());
                    }
                }
                61 => {
                    client_id = Some(opt_data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"));
                }
                _ => {}
            }
            pos += opt_len;
        }

        Some(NetworkLease {
            timestamp: Utc::now(),
            mac_address: mac,
            ip_address: target_ip,
            hostname,
            client_id,
            vendor_class,
            dhcp_fingerprint_opt55: opt55_fp,
            parameter_request_list,
            lease_duration_secs,
            source_type: LeaseSourceType::DhcpSniffer,
        })
    }

    async fn poll_arp_neighbor_table(db: &Database, seen: &mut HashSet<String>) {
        let arp_path = Path::new("/proc/net/arp");
        if arp_path.exists() {
            if let Ok(content) = fs::read_to_string(arp_path) {
                for line in content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let ip_str = parts[0];
                        let mac_str = parts[3].to_lowercase();

                        if mac_str != "00:00:00:00:00:00" && !mac_str.is_empty() {
                            let key = format!("{}_{}", mac_str, ip_str);
                            if !seen.contains(&key) {
                                seen.insert(key);
                                if let Ok(ip) = IpAddr::from_str(ip_str) {
                                    let lease = NetworkLease {
                                        timestamp: Utc::now(),
                                        mac_address: mac_str,
                                        ip_address: ip,
                                        hostname: None,
                                        client_id: None,
                                        vendor_class: None,
                                        dhcp_fingerprint_opt55: None,
                                        parameter_request_list: Vec::new(),
                                        lease_duration_secs: None,
                                        source_type: LeaseSourceType::ArpTable,
                                    };
                                    let _ = db.record_lease(&lease);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn lookup_oui(mac: &str) -> Option<String> {
        let mac_bytes: Vec<&str> = mac.split(':').collect();
        if mac_bytes.len() >= 3 {
            let oui = format!("{}:{}:{}", mac_bytes[0], mac_bytes[1], mac_bytes[2]);
            let oui_lower = oui.to_lowercase();
            return match oui_lower.as_str() {
                "00:00:0c" => Some("Cisco Systems".to_string()),
                "00:00:0f" => Some("Netgear".to_string()),
                "00:00:24" => Some("Dell".to_string()),
                "00:00:39" => Some("HP".to_string()),
                "00:00:50" => Some("AMD".to_string()),
                "00:00:aa" => Some("Intel".to_string()),
                "00:00:ac" => Some("Apple".to_string()),
                "00:00:bd" => Some("Realtek".to_string()),
                "00:00:e2" => Some("Broadcom".to_string()),
                "00:00:f2" => Some("Microsoft".to_string()),
                "00:03:47" => Some("Dell".to_string()),
                "00:04:75" => Some("Dell".to_string()),
                "00:04:76" => Some("Dell".to_string()),
                "00:0c:29" => Some("VMware".to_string()),
                "00:0c:42" => Some("HP".to_string()),
                "00:0e:8c" => Some("Samsung".to_string()),
                "00:0f:24" => Some("Dell".to_string()),
                "00:10:18" => Some("Broadcom".to_string()),
                "00:11:24" => Some("Linksys".to_string()),
                "00:12:17" => Some("Apple".to_string()),
                "00:12:3f" => Some("Dell".to_string()),
                "00:13:ce" => Some("Dell".to_string()),
                "00:14:51" => Some("Dell".to_string()),
                "00:14:a5" => Some("Dell".to_string()),
                "00:15:5d" => Some("Microsoft".to_string()),
                "00:15:c5" => Some("Dell".to_string()),
                "00:16:17" => Some("Dell".to_string()),
                "00:16:36" => Some("Dell".to_string()),
                "00:16:6f" => Some("Dell".to_string()),
                "00:16:76" => Some("Dell".to_string()),
                "00:16:cb" => Some("Dell".to_string()),
                "00:16:ec" => Some("Dell".to_string()),
                "00:17:c4" => Some("HP".to_string()),
                "00:17:f2" => Some("Dell".to_string()),
                "00:18:8b" => Some("Dell".to_string()),
                "00:18:8d" => Some("Dell".to_string()),
                "00:19:b9" => Some("Dell".to_string()),
                "00:1a:4b" => Some("Dell".to_string()),
                "00:1b:63" => Some("Dell".to_string()),
                "00:1c:42" => Some("HP".to_string()),
                "00:1d:09" => Some("Dell".to_string()),
                "00:1e:4f" => Some("Dell".to_string()),
                "00:1e:68" => Some("Dell".to_string()),
                "00:1e:c9" => Some("Dell".to_string()),
                "00:1f:3c" => Some("Dell".to_string()),
                "00:1f:3d" => Some("Dell".to_string()),
                "00:1f:3e" => Some("Dell".to_string()),
                "00:20:e0" => Some("Dell".to_string()),
                "00:21:5e" => Some("Dell".to_string()),
                "00:21:cc" => Some("HP".to_string()),
                "00:21:70" => Some("Intel".to_string()),
                "00:22:19" => Some("Dell".to_string()),
                "00:22:64" => Some("Dell".to_string()),
                "00:22:68" => Some("Dell".to_string()),
                "00:22:6a" => Some("Dell".to_string()),
                "00:22:6b" => Some("Dell".to_string()),
                "00:22:6c" => Some("Dell".to_string()),
                "00:22:6d" => Some("Dell".to_string()),
                "00:22:6e" => Some("Dell".to_string()),
                "00:22:6f" => Some("Dell".to_string()),
                "00:22:70" => Some("Dell".to_string()),
                "00:22:71" => Some("Dell".to_string()),
                "00:22:72" => Some("Dell".to_string()),
                "00:22:73" => Some("Dell".to_string()),
                "00:22:74" => Some("Dell".to_string()),
                "00:22:75" => Some("Dell".to_string()),
                "00:22:76" => Some("Dell".to_string()),
                "00:22:77" => Some("Dell".to_string()),
                "00:22:78" => Some("Dell".to_string()),
                "00:22:79" => Some("Dell".to_string()),
                "00:22:7a" => Some("Dell".to_string()),
                "00:22:7b" => Some("Dell".to_string()),
                "00:22:7c" => Some("Dell".to_string()),
                "00:22:7d" => Some("Dell".to_string()),
                "00:22:7e" => Some("Dell".to_string()),
                "00:22:7f" => Some("Dell".to_string()),
                "00:22:b0" => Some("Dell".to_string()),
                "00:22:b1" => Some("Dell".to_string()),
                "00:22:b2" => Some("Dell".to_string()),
                "00:22:b3" => Some("Dell".to_string()),
                "00:22:b4" => Some("Dell".to_string()),
                "00:22:b5" => Some("Dell".to_string()),
                "00:22:b6" => Some("Dell".to_string()),
                "00:22:b7" => Some("Dell".to_string()),
                "00:22:b8" => Some("Dell".to_string()),
                "00:22:b9" => Some("Dell".to_string()),
                "00:22:ba" => Some("Dell".to_string()),
                "00:22:bb" => Some("Dell".to_string()),
                "00:22:bc" => Some("Dell".to_string()),
                "00:22:bd" => Some("Dell".to_string()),
                "00:22:be" => Some("Dell".to_string()),
                "00:22:bf" => Some("Dell".to_string()),
                "00:22:c0" => Some("Dell".to_string()),
                "00:22:c1" => Some("Dell".to_string()),
                "00:22:c2" => Some("Dell".to_string()),
                "00:22:c3" => Some("Dell".to_string()),
                "00:22:c4" => Some("Dell".to_string()),
                "00:22:c5" => Some("Dell".to_string()),
                "00:22:c6" => Some("Dell".to_string()),
                "00:22:c7" => Some("Dell".to_string()),
                "00:22:c8" => Some("Dell".to_string()),
                "00:22:c9" => Some("Dell".to_string()),
                "00:22:ca" => Some("Dell".to_string()),
                "00:22:cb" => Some("Dell".to_string()),
                "00:22:cc" => Some("Dell".to_string()),
                "00:22:cd" => Some("Dell".to_string()),
                "00:22:ce" => Some("Dell".to_string()),
                "00:22:cf" => Some("Dell".to_string()),
                "00:22:d0" => Some("Dell".to_string()),
                "00:22:d1" => Some("Dell".to_string()),
                "00:22:d2" => Some("Dell".to_string()),
                "00:22:d3" => Some("Dell".to_string()),
                "00:22:d4" => Some("Dell".to_string()),
                "00:22:d5" => Some("Dell".to_string()),
                "00:22:d6" => Some("Dell".to_string()),
                "00:22:d7" => Some("Dell".to_string()),
                "00:22:d8" => Some("Dell".to_string()),
                "00:22:d9" => Some("Dell".to_string()),
                "00:22:da" => Some("Dell".to_string()),
                "00:22:db" => Some("Dell".to_string()),
                "00:22:dc" => Some("Dell".to_string()),
                "00:22:dd" => Some("Dell".to_string()),
                "00:22:de" => Some("Dell".to_string()),
                "00:22:df" => Some("Dell".to_string()),
                "00:22:e0" => Some("Dell".to_string()),
                "00:22:e1" => Some("Dell".to_string()),
                "00:22:e2" => Some("Dell".to_string()),
                "00:22:e3" => Some("Dell".to_string()),
                "00:22:e4" => Some("Dell".to_string()),
                "00:22:e5" => Some("Dell".to_string()),
                "00:22:e6" => Some("Dell".to_string()),
                "00:22:e7" => Some("Dell".to_string()),
                "00:22:e8" => Some("Dell".to_string()),
                "00:22:e9" => Some("Dell".to_string()),
                "00:22:ea" => Some("Dell".to_string()),
                "00:22:eb" => Some("Dell".to_string()),
                "00:22:ec" => Some("Dell".to_string()),
                "00:22:ed" => Some("Dell".to_string()),
                "00:22:ee" => Some("Dell".to_string()),
                "00:22:ef" => Some("Dell".to_string()),
                "00:22:f0" => Some("Dell".to_string()),
                "00:22:f1" => Some("Dell".to_string()),
                "00:22:f2" => Some("Dell".to_string()),
                "00:22:f3" => Some("Dell".to_string()),
                "00:22:f4" => Some("Dell".to_string()),
                "00:22:f5" => Some("Dell".to_string()),
                "00:22:f6" => Some("Dell".to_string()),
                "00:22:f7" => Some("Dell".to_string()),
                "00:22:f8" => Some("Dell".to_string()),
                "00:22:f9" => Some("Dell".to_string()),
                "00:22:fa" => Some("Dell".to_string()),
                "00:22:fb" => Some("Dell".to_string()),
                "00:22:fc" => Some("Dell".to_string()),
                "00:22:fd" => Some("Dell".to_string()),
                "00:22:fe" => Some("Dell".to_string()),
                "00:22:ff" => Some("Dell".to_string()),
                "00:23:ae" => Some("Intel".to_string()),
                "00:24:2d" => Some("Intel".to_string()),
                "00:24:e8" => Some("Intel".to_string()),
                "00:25:4b" => Some("Dell".to_string()),
                "00:25:64" => Some("Dell".to_string()),
                "00:26:18" => Some("Dell".to_string()),
                "00:26:b9" => Some("Dell".to_string()),
                "00:26:bb" => Some("Dell".to_string()),
                "00:26:c7" => Some("Realtek".to_string()),
                "00:27:0e" => Some("Intel".to_string()),
                "00:28:6b" => Some("Dell".to_string()),
                "00:28:c8" => Some("Dell".to_string()),
                "00:28:f8" => Some("Broadcom".to_string()),
                "00:30:48" => Some("Dell".to_string()),
                "00:30:c1" => Some("Cisco".to_string()),
                "00:30:bd" => Some("Belkin".to_string()),
                "00:30:65" => Some("Dell".to_string()),
                "00:30:ab" => Some("Netgear".to_string()),
                "00:30:f1" => Some("Asus".to_string()),
                "00:30:f2" => Some("Asus".to_string()),
                "00:30:f9" => Some("Asus".to_string()),
                "00:30:fd" => Some("Asus".to_string()),
                "00:30:fe" => Some("Asus".to_string()),
                "00:30:ff" => Some("Asus".to_string()),
                "00:40:96" => Some("Cisco".to_string()),
                "00:40:f4" => Some("Intel".to_string()),
                "00:50:04" => Some("3Com".to_string()),
                "00:50:56" => Some("VMware".to_string()),
                "00:50:8b" => Some("3Com".to_string()),
                "00:50:c2" => Some("Broadcom".to_string()),
                "00:50:da" => Some("3Com".to_string()),
                "00:50:e4" => Some("3Com".to_string()),
                "00:50:f2" => Some("Microsoft".to_string()),
                "00:60:1c" => Some("Cisco".to_string()),
                "00:60:6e" => Some("Cisco".to_string()),
                "00:60:97" => Some("Cisco".to_string()),
                "00:60:b0" => Some("Cisco".to_string()),
                "00:60:dd" => Some("Cisco".to_string()),
                "00:60:e0" => Some("Cisco".to_string()),
                "00:60:ef" => Some("Cisco".to_string()),
                "00:60:f2" => Some("Cisco".to_string()),
                "00:60:fc" => Some("Cisco".to_string()),
                "00:60:fd" => Some("Cisco".to_string()),
                "00:60:fe" => Some("Cisco".to_string()),
                "00:60:ff" => Some("Cisco".to_string()),
                "00:80:48" => Some("Hewlett Packard".to_string()),
                "00:80:86" => Some("Intel".to_string()),
                "00:90:27" => Some("Cisco".to_string()),
                "00:90:a9" => Some("Cisco".to_string()),
                "00:90:d0" => Some("Intel".to_string()),
                "00:90:f5" => Some("Intel".to_string()),
                "00:a0:c9" => Some("Intel".to_string()),
                "00:a0:cc" => Some("Intel".to_string()),
                "00:a0:cd" => Some("Intel".to_string()),
                "00:a0:ce" => Some("Intel".to_string()),
                "00:a0:cf" => Some("Intel".to_string()),
                "00:a0:d1" => Some("Intel".to_string()),
                "00:a0:d2" => Some("Intel".to_string()),
                "00:a0:d3" => Some("Intel".to_string()),
                "00:a0:d4" => Some("Intel".to_string()),
                "00:a0:d5" => Some("Intel".to_string()),
                "00:a0:d6" => Some("Intel".to_string()),
                "00:a0:d7" => Some("Intel".to_string()),
                "00:a0:d8" => Some("Intel".to_string()),
                "00:a0:d9" => Some("Intel".to_string()),
                "00:a0:da" => Some("Intel".to_string()),
                "00:a0:db" => Some("Intel".to_string()),
                "00:a0:dc" => Some("Intel".to_string()),
                "00:a0:dd" => Some("Intel".to_string()),
                "00:a0:de" => Some("Intel".to_string()),
                "00:a0:df" => Some("Intel".to_string()),
                "00:a0:e0" => Some("Intel".to_string()),
                "00:a0:e1" => Some("Intel".to_string()),
                "00:a0:e2" => Some("Intel".to_string()),
                "00:a0:e3" => Some("Intel".to_string()),
                "00:a0:e4" => Some("Intel".to_string()),
                "00:a0:e5" => Some("Intel".to_string()),
                "00:a0:e6" => Some("Intel".to_string()),
                "00:a0:e7" => Some("Intel".to_string()),
                "00:a0:e8" => Some("Intel".to_string()),
                "00:a0:e9" => Some("Intel".to_string()),
                "00:a0:ea" => Some("Intel".to_string()),
                "00:a0:eb" => Some("Intel".to_string()),
                "00:a0:ec" => Some("Intel".to_string()),
                "00:a0:ed" => Some("Intel".to_string()),
                "00:a0:ee" => Some("Intel".to_string()),
                "00:a0:ef" => Some("Intel".to_string()),
                "00:a0:f0" => Some("Intel".to_string()),
                "00:a0:f1" => Some("Intel".to_string()),
                "00:a0:f2" => Some("Intel".to_string()),
                "00:a0:f3" => Some("Intel".to_string()),
                "00:a0:f4" => Some("Intel".to_string()),
                "00:a0:f5" => Some("Intel".to_string()),
                "00:a0:f6" => Some("Intel".to_string()),
                "00:a0:f7" => Some("Intel".to_string()),
                "00:a0:f8" => Some("Intel".to_string()),
                "00:a0:f9" => Some("Intel".to_string()),
                "00:a0:fa" => Some("Intel".to_string()),
                "00:a0:fb" => Some("Intel".to_string()),
                "00:a0:fc" => Some("Intel".to_string()),
                "00:a0:fd" => Some("Intel".to_string()),
                "00:a0:fe" => Some("Intel".to_string()),
                "00:a0:ff" => Some("Intel".to_string()),
                "00:b0:d0" => Some("Compex".to_string()),
                "00:e0:4c" => Some("Realtek".to_string()),
                "04:18:d6" => Some("Espressif".to_string()),
                "dc:a6:32" => Some("Espressif".to_string()),
                "e8:50:8b" => Some("Espressif".to_string()),
                "84:cc:a8" => Some("Espressif".to_string()),
                "ac:d1:b6" => Some("Espressif".to_string()),
                "a0:20:a6" => Some("Espressif".to_string()),
                "4c:11:bf" => Some("Espressif".to_string()),
                "30:ae:a4" => Some("Espressif".to_string()),
                "24:0a:c4" => Some("Espressif".to_string()),
                "bc:dd:c2" => Some("Espressif".to_string()),
                "f8:ff:c2" => Some("Apple".to_string()),
                "da:a1:19" => Some("Samsung".to_string()),
                "b4:2e:99" => Some("Samsung".to_string()),
                "70:85:c2" => Some("Intel".to_string()),
                "3c:71:bf" => Some("Espressif".to_string()),
                "a4:c1:38" => Some("Google".to_string()),
                "f4:f5:db" => Some("Google".to_string()),
                "44:67:55" => Some("Google".to_string()),
                "40:4e:36" => Some("Google".to_string()),
                "3a:2e:39" => Some("Google".to_string()),
                _ => None,
            };
        }
        None
    }
}
