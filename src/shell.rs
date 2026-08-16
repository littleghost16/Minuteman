use crate::logger::Database;
use colored::*;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use uuid::Uuid;

pub struct InteractiveShell {
    db: Database,
    telemetry_bind: String,
    running: Arc<AtomicBool>,
}

impl InteractiveShell {
    pub fn new(db: Database, telemetry_bind: String, running: Arc<AtomicBool>) -> Self {
        Self {
            db,
            telemetry_bind,
            running,
        }
    }

    pub fn run_loop(&self) {
        println!("{}", "Minuteman Interactive Shell initialized. Type 'help' for commands.\n".green().bold());

        let stdin = io::stdin();
        let mut handle = stdin.lock();

        while self.running.load(Ordering::Relaxed) {
            print!("{}", "minuteman> ".cyan().bold());
            let _ = io::stdout().flush();

            let mut line = String::new();
            if handle.read_line(&mut line).is_err() {
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let command = parts[0].to_lowercase();

            match command.as_str() {
                "help" | "?" => {
                    self.print_help();
                }
                "targets" | "list" => {
                    let limit = parts
                        .get(1)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(20);
                    self.show_targets(limit);
                }
                "obs" | "packets" | "sniff" => {
                    let limit = parts
                        .get(1)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(15);
                    self.show_observations(limit);
                }
                "lookup" | "inspect" => {
                    if let Some(query) = parts.get(1) {
                        self.lookup_target(query);
                    } else {
                        println!("{}", "Usage: lookup <MAC_ADDRESS | IP_ADDRESS | TARGET_ID>".red());
                    }
                }
                "leases" => {
                    let limit = parts
                        .get(1)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(20);
                    self.show_leases(limit);
                }
                "heatmap" => {
                    self.show_heatmap();
                }
                "rssi" => {
                    self.show_rssi_meter();
                }
                "stats" | "status" => {
                    self.show_stats();
                }
                "track" | "beacon" => {
                    let token = parts
                        .get(1)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| Uuid::new_v4().to_string());
                    self.generate_beacon_asset(&token);
                }
                "export" => {
                    if parts.len() < 3 {
                        println!("{}", "Usage: export <json|csv|geojson|kml> <output_file_path>".red());
                    } else {
                        let fmt = parts[1].to_lowercase();
                        let path = parts[2];
                        match fmt.as_str() {
                            "json" => match self.db.export_targets_json(path) {
                                Ok(_) => println!("{} Exported targets to {}", "[+]".green().bold(), path),
                                Err(e) => println!("{} Export failed: {:?}", "[-]".red().bold(), e),
                            },
                            "csv" => match self.db.export_targets_csv(path) {
                                Ok(_) => println!("{} Exported targets to {}", "[+]".green().bold(), path),
                                Err(e) => println!("{} Export failed: {:?}", "[-]".red().bold(), e),
                            },
                            "geojson" => match self.db.export_targets_geojson_string() {
                                Ok(geojson) => {
                                    if let Err(e) = std::fs::write(path, geojson) {
                                        println!("{} Export failed: {:?}", "[-]".red().bold(), e);
                                    } else {
                                        println!("{} Exported targets to {}", "[+]".green().bold(), path);
                                    }
                                }
                                Err(e) => println!("{} Export failed: {:?}", "[-]".red().bold(), e),
                            },
                            "kml" => match self.db.export_targets_kml_string() {
                                Ok(kml) => {
                                    if let Err(e) = std::fs::write(path, kml) {
                                        println!("{} Export failed: {:?}", "[-]".red().bold(), e);
                                    } else {
                                        println!("{} Exported targets to {}", "[+]".green().bold(), path);
                                    }
                                }
                                Err(e) => println!("{} Export failed: {:?}", "[-]".red().bold(), e),
                            },
                            _ => println!("{}", "Unsupported export format. Use 'json', 'csv', 'geojson', or 'kml'".red()),
                        }
                    }
                }
                "clear" | "cls" => {
                    print!("\x1B[2J\x1B[1;1H");
                    let _ = io::stdout().flush();
                }
                "quit" | "exit" | "q" => {
                    println!("{}", "Shutting down Minuteman engine...".yellow());
                    self.running.store(false, Ordering::Relaxed);
                    break;
                }
                cmd => {
                    println!(
                        "{} Unknown command '{}'. Type 'help' for command list.",
                        "[-]".red().bold(),
                        cmd
                    );
                }
            }
        }
    }

    fn print_help(&self) {
        println!("\n{}", "=== MINUTEMAN SHELL COMMAND REFERENCE ===".white().bold());
        println!("  {:<25} {}", "targets [limit]".cyan(), "Display correlated RF-to-IP target devices");
        println!("  {:<25} {}", "obs [limit]".cyan(), "Inspect recent 802.11 & SDR packet observations");
        println!("  {:<25} {}", "lookup <mac|ip|id>".cyan(), "Detailed deep inspection of a device record");
        println!("  {:<25} {}", "leases [limit]".cyan(), "View DHCP lease table entries");
        println!("  {:<25} {}", "heatmap".cyan(), "Display WiFi channel occupancy heatmap");
        println!("  {:<25} {}", "rssi".cyan(), "Show live RSSI signal strength meter");
        println!("  {:<25} {}", "track [token]".cyan(), "Generate application layer web beacon tracking link");
        println!("  {:<25} {}", "stats".cyan(), "Display real-time RF capture and correlation statistics");
        println!("  {:<25} {}", "export <fmt> <file>".cyan(), "Export correlation database (json|csv|geojson|kml)");
        println!("  {:<25} {}", "clear".cyan(), "Clear the terminal screen");
        println!("  {:<25} {}", "exit / quit".cyan(), "Safely terminate engine session");
        println!("{}\n", "=".repeat(60).white());
    }

    fn show_targets(&self, limit: usize) {
        match self.db.get_recent_targets(limit) {
            Ok(targets) => {
                if targets.is_empty() {
                    println!("{}", "No correlated targets found in session yet.".yellow());
                    return;
                }
                println!("\n{}", "--- CORRELATED IDENTIFIERS (MAC -> LOCAL IP -> PUBLIC IP) ---".green().bold());
                println!(
                    "{:<20} {:<8} {:<16} {:<18} {:<18} {:<8} {:<6} {:<12} {:<18}",
                    "MAC ADDRESS", "RAND", "HOSTNAME", "LOCAL IP (DHCP)", "PUBLIC IP (BEACON)", "RSSI", "FRAMES", "DIST (m)", "LAST SEEN"
                );
                println!("{}", "-".repeat(130));
                for t in targets {
                    let local_str = t
                        .local_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "<pending>".to_string());
                    let public_str = t
                        .public_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "<unresolved>".to_string());
                    let host_str = t.hostname.unwrap_or_else(|| "-".to_string());
                    let rand_str = if t.is_randomized_mac { "Y".red().bold() } else { "N".green() };
                    let rssi_str = format!("{} dBm", t.last_rssi);
                    let dist_str = t.estimated_distance_meters.map(|d| format!("{:.1}", d)).unwrap_or_else(|| "-".to_string());
                    let seen_str = t.last_seen.format("%H:%M:%S UTC").to_string();

                    println!(
                        "{:<20} {:<8} {:<16} {:<18} {:<18} {:<8} {:<6} {:<12} {:<18}",
                        t.mac_address.yellow().bold(),
                        rand_str,
                        host_str.white(),
                        local_str.cyan(),
                        public_str.magenta().bold(),
                        rssi_str,
                        t.observation_count,
                        dist_str,
                        seen_str
                    );
                }
                println!("{}\n", "-".repeat(130));
            }
            Err(e) => println!("{} Failed to query targets: {:?}", "[-]".red().bold(), e),
        }
    }

    fn show_observations(&self, limit: usize) {
        match self.db.get_recent_observations(limit) {
            Ok(obs_list) => {
                if obs_list.is_empty() {
                    println!("{}", "No raw packet observations recorded yet.".yellow());
                    return;
                }
                println!("\n{}", "--- RECENT L1/L2 RAW OBSERVATIONS ---".green().bold());
                println!(
                    "{:<20} {:<16} {:<8} {:<8} {:<8} {:<22} {:<18}",
                    "SOURCE MAC", "FRAME TYPE", "MEDIUM", "RSSI", "CH", "SSID", "TIMESTAMP"
                );
                println!("{}", "-".repeat(110));
                for obs in obs_list {
                    let frame_kind_str = format!("{:?}", obs.frame_type);
                    let medium_str = format!("{:?}", obs.medium);
                    let rssi_str = format!("{} dBm", obs.rssi);
                    let channel_str = obs.channel.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string());
                    let ssid_str = obs.ssid.unwrap_or_else(|| "-".to_string());
                    let ts_str = obs.timestamp.format("%H:%M:%S.%3f").to_string();

                    println!(
                        "{:<20} {:<16} {:<8} {:<8} {:<8} {:<22} {:<18}",
                        obs.source_mac.yellow(),
                        frame_kind_str.cyan(),
                        medium_str.white(),
                        rssi_str,
                        channel_str,
                        ssid_str.green(),
                        ts_str
                    );
                }
                println!("{}\n", "-".repeat(110));
            }
            Err(e) => println!("{} Failed to query observations: {:?}", "[-]".red().bold(), e),
        }
    }

    fn show_leases(&self, limit: usize) {
        match self.db.get_recent_targets(limit) {
            Ok(targets) => {
                if targets.is_empty() {
                    println!("{}", "No DHCP lease records found.".yellow());
                    return;
                }
                println!("\n{}", "--- DHCP LEASE TABLE ---".green().bold());
                println!(
                    "{:<20} {:<18} {:<16} {:<12} {:<18}",
                    "MAC ADDRESS", "IP ADDRESS", "HOSTNAME", "SOURCE", "LAST SEEN"
                );
                println!("{}", "-".repeat(90));
                for t in targets {
                    if let Some(local_ip) = t.local_ip {
                        let host_str = t.hostname.unwrap_or_else(|| "-".to_string());
                        let seen_str = t.last_seen.format("%H:%M:%S UTC").to_string();
                        println!(
                            "{:<20} {:<18} {:<16} {:<12} {:<18}",
                            t.mac_address.yellow().bold(),
                            local_ip.to_string().cyan(),
                            host_str.white(),
                            "DHCP".green(),
                            seen_str
                        );
                    }
                }
                println!("{}\n", "-".repeat(90));
            }
            Err(e) => println!("{} Failed to query leases: {:?}", "[-]".red().bold(), e),
        }
    }

    fn show_heatmap(&self) {
        match self.db.get_channel_occupancy() {
            Ok(occupancy) => {
                if occupancy.is_empty() {
                    println!("{}", "No channel occupancy data available.".yellow());
                    return;
                }
                println!("\n{}", "--- WIFI CHANNEL OCCUPANCY HEATMAP ---".green().bold());
                println!("{}", "Channel  |  Frame Count  |  Visualization".cyan());
                println!("{}", "-".repeat(50));
                for (channel, count) in occupancy {
                    let bar_len = (count as f64).log10().ceil() as usize * 2;
                    let bar = "█".repeat(bar_len.min(30));
                    println!(
                        "CH {:<4} |  {:<12}  |  {}",
                        channel,
                        count,
                        bar.green()
                    );
                }
                println!("{}\n", "-".repeat(50));
            }
            Err(e) => println!("{} Failed to query channel occupancy: {:?}", "[-]".red().bold(), e),
        }
    }

    fn show_rssi_meter(&self) {
        match self.db.get_recent_targets(10) {
            Ok(targets) => {
                if targets.is_empty() {
                    println!("{}", "No RSSI data available.".yellow());
                    return;
                }
                println!("\n{}", "--- LIVE RSSI SIGNAL STRENGTH METER ---".green().bold());
                println!("{}", "MAC Address          |  RSSI  |  Signal Quality".cyan());
                println!("{}", "-".repeat(55));
                for t in targets {
                    let quality = t.signal_quality_percent.unwrap_or(0.0);
                    let bar_len = (quality / 10.0) as usize;
                    let bar = if quality > 70 {
                        "█".repeat(bar_len).green()
                    } else if quality > 40 {
                        "█".repeat(bar_len).yellow()
                    } else {
                        "█".repeat(bar_len).red()
                    };
                    println!(
                        "{:<20} |  {:<5} |  {:.0}% {}",
                        t.mac_address.yellow(),
                        format!("{} dBm", t.last_rssi),
                        quality,
                        bar
                    );
                }
                println!("{}\n", "-".repeat(55));
            }
            Err(e) => println!("{} Failed to query RSSI data: {:?}", "[-]".red().bold(), e),
        }
    }

    fn lookup_target(&self, query: &str) {
        match self.db.get_target_by_identifier(query) {
            Ok(Some(t)) => {
                println!("\n{}", "=== TARGET RECORD DOSSIER ===".white().bold());
                println!("  Target ID           : {}", t.target_id.cyan());
                println!("  Hardware MAC        : {}", t.mac_address.yellow().bold());
                println!("  Randomized MAC      : {}", if t.is_randomized_mac { "Yes".red().bold() } else { "No".green() });
                println!("  MAC Vendor          : {}", t.mac_vendor.unwrap_or_else(|| "Unknown".to_string()).white());
                println!(
                    "  Assigned Local IP  : {}",
                    t.local_ip.map(|i| i.to_string()).unwrap_or_else(|| "N/A (Unassociated)".to_string()).cyan()
                );
                println!(
                    "  Resolved Pub IP    : {}",
                    t.public_ip.map(|i| i.to_string()).unwrap_or_else(|| "N/A (Unresolved)".to_string()).magenta().bold()
                );
                println!("  DHCP Hostname       : {}", t.hostname.unwrap_or_else(|| "Unknown".to_string()).white());
                println!("  Last Known SSID     : {}", t.last_ssid.unwrap_or_else(|| "None".to_string()).green());
                println!("  Last Channel        : {}", t.last_channel.map(|c| c.to_string()).unwrap_or_else(|| "N/A".to_string()));
                println!("  Last Signal RSSI    : {} dBm", t.last_rssi);
                println!("  Est. Distance       : {} m (confidence: {:.0}%)", 
                    t.estimated_distance_meters.map(|d| format!("{:.1}", d)).unwrap_or_else(|| "N/A".to_string()),
                    t.distance_confidence.map(|c| c * 100.0).unwrap_or(0.0));
                println!("  Signal Quality      : {}%", t.signal_quality_percent.map(|q| format!("{:.0}", q)).unwrap_or_else(|| "N/A".to_string()));
                println!("  Total Frames        : {}", t.observation_count);
                println!("  First Detected      : {}", t.first_seen.to_rfc3339());
                println!("  Last Detected       : {}", t.last_seen.to_rfc3339());
                if let Some(ua) = t.user_agent {
                    println!("  HTTP User-Agent     : {}", ua);
                }
                println!("{}\n", "=".repeat(45).white());
            }
            Ok(None) => {
                println!("{} No target record matching '{}' found.", "[-]".yellow().bold(), query);
            }
            Err(e) => {
                println!("{} Lookup query error: {:?}", "[-]".red().bold(), e);
            }
        }
    }

    fn show_stats(&self) {
        match self.db.get_system_stats() {
            Ok(s) => {
                println!("\n{}", "=== MINUTEMAN LAB TELEMETRY & CAPTURE METRICS ===".white().bold());
                println!("  Total Raw Frames Processed : {}", s.total_frames.to_string().cyan().bold());
                println!("  Unique Hardware MACs       : {}", s.unique_macs.to_string().yellow().bold());
                println!("  802.11 Probe Requests      : {}", s.wifi_probes.to_string().green());
                println!("  802.11 Beacon Frames       : {}", s.wifi_beacons);
                println!("  802.11 Association Frames  : {}", s.wifi_associations);
                println!("  Cellular / SDR Bursts      : {}", s.cellular_bursts.to_string().magenta());
                println!("  Active DHCP Leases         : {}", s.active_leases.to_string().cyan());
                println!("  Telemetry Beacon Hits      : {}", s.telemetry_hits.to_string().green().bold());
                println!("{}\n", "=".repeat(50).white());
            }
            Err(e) => println!("{} Failed to compute statistics: {:?}", "[-]".red().bold(), e),
        }
    }

    fn generate_beacon_asset(&self, token: &str) {
        let base = format!("http://{}", self.telemetry_bind);
        println!("\n{}", "=== INVISIBLE WEB BEACON ASSETS GENERATED ===".green().bold());
        println!("  Target Token ID : {}", token.yellow().bold());
        println!("  Pixel GIF URL   : {}/beacon.gif?id={}", base, token);
        println!("  Track Path URL  : {}/track/{}", base, token);
        println!("  HTML Embed Tag  : {}", format!("<img src=\"{}/beacon.gif?id={}\" width=\"1\" height=\"1\" style=\"display:none;\" />", base, token).cyan());
        println!("{}\n", "=".repeat(55).green());
    }
}
