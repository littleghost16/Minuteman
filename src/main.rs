mod banner;
mod logger;
mod network_stack;
mod radio_engine;
mod shell;
mod telemetry;
mod types;

use anyhow::Result;
use banner::print_startup_banner;
use clap::Parser;
use colored::*;
use logger::Database;
use network_stack::NetworkStack;
use radio_engine::RadioEngine;
use shell::InteractiveShell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use telemetry::TelemetryEngine;
use tokio::signal;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use types::{CliArgs, TargetResolution};

#[tokio::main]
async fn main() -> Result<()> {
    print_startup_banner();

    let args = CliArgs::parse();

    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    let running = Arc::new(AtomicBool::new(true));

    let db = Database::new(&args.db_path)?;
    info!("SQLite database initialized: {}", args.db_path);

    println!("{}", "=== MINUTEMAN 0.1 ACTIVE ENGINE CONFIGURATION ===".cyan().bold());
    println!("  {:<20}: {:?}", "Radio Medium".white().bold(), args.mode);
    println!("  {:<20}: {:?}", "Resolution Target".white().bold(), args.target);
    println!("  {:<20}: {}", "Hardware Interface".white().bold(), args.interface);
    println!("  {:<20}: {}", "Stealth Mode".white().bold(), args.stealth);
    println!("  {:<20}: {}", "Database Storage".white().bold(), args.db_path);
    println!("  {:<20}: {}", "Telemetry Server".white().bold(), args.telemetry_bind);
    println!("  {:<20}: {}", "Interactive Shell".white().bold(), args.interactive);
    println!("  {:<20}: {}", "DHCP Lease Path".white().bold(), args.leases_path);
    println!("{}\n", "=".repeat(55).cyan());

    let radio = RadioEngine::new(
        args.interface.clone(),
        args.mode,
        args.stealth,
        args.pcap_file.clone(),
        None,
        false,
        db.clone(),
        running.clone(),
    );

    let net_stack = NetworkStack::new(
        &args.leases_path,
        db.clone(),
        args.stealth,
        running.clone(),
    );

    let telemetry = TelemetryEngine::new(
        args.telemetry_bind.clone(),
        db.clone(),
        running.clone(),
    );

    radio.start().await?;
    net_stack.start().await?;

    if args.target == TargetResolution::Public || !args.stealth {
        telemetry.start().await?;
    }

    let running_ctrl = running.clone();
    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        println!("\n{}", "Received interrupt. Shutting down Minuteman...".yellow());
        running_ctrl.store(false, Ordering::Relaxed);
    });

    if args.interactive {
        let shell_instance = InteractiveShell::new(
            db.clone(),
            args.telemetry_bind.clone(),
            running.clone(),
        );

        tokio::task::spawn_blocking(move || {
            shell_instance.run_loop();
        })
        .await?;
    } else {
        let db_dash = db.clone();
        let running_dash = running.clone();

        tokio::spawn(async move {
            while running_dash.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Ok(targets) = db_dash.get_recent_targets(10) {
                    if !targets.is_empty() {
                        println!("\n{}", "--- CORRELATED IDENTIFIER & GEOLOCATION MAPPING ---".green().bold());
                        println!(
                            "{:<20} {:<18} {:<18} {:<8} {:<24}",
                            "MAC / HARDWARE ID", "LOCAL IP (DHCP)", "PUBLIC IP (BEACON)", "RSSI", "LAST SEEN"
                        );
                        println!("{}", "-".repeat(92));
                        for t in targets {
                            let local_str = t
                                .local_ip
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| "<pending>".to_string());
                            let public_str = t
                                .public_ip
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| "<unresolved>".to_string());
                            let rssi_str = format!("{} dBm", t.last_rssi);
                            let seen_str = t.last_seen.format("%H:%M:%S UTC").to_string();

                            println!(
                                "{:<20} {:<18} {:<18} {:<8} {:<24}",
                                t.mac_address.yellow(),
                                local_str.cyan(),
                                public_str.magenta(),
                                rssi_str,
                                seen_str
                            );
                        }
                        println!("{}\n", "-".repeat(92));
                    }
                }
            }
        });

        while running.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    info!("Minuteman session terminated cleanly.");
    Ok(())
}
