use crate::types::{
    CorrelatedTarget, DeviceObservation, FrameSubtype, NetworkLease, ParsedInformationElements,
    RadioMedium, RssiDistanceEstimate, SystemStatistics, TelemetryHit,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).context("Failed to open SQLite database")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_mac TEXT NOT NULL,
                is_randomized_mac INTEGER NOT NULL DEFAULT 0,
                mac_vendor TEXT,
                destination_mac TEXT,
                bssid TEXT,
                ssid TEXT,
                rssi INTEGER NOT NULL,
                noise_dbm INTEGER,
                snr_db REAL,
                channel INTEGER,
                frequency_mhz INTEGER,
                frame_type TEXT NOT NULL,
                frame_control_json TEXT,
                medium TEXT NOT NULL,
                sequence_number INTEGER,
                retry_flag INTEGER NOT NULL DEFAULT 0,
                power_mgmt_flag INTEGER NOT NULL DEFAULT 0,
                more_data_flag INTEGER NOT NULL DEFAULT 0,
                protected_flag INTEGER NOT NULL DEFAULT 0,
                information_elements_json TEXT,
                radiotap_json TEXT,
                sdr_burst_json TEXT,
                cellular_info_json TEXT,
                raw_length INTEGER NOT NULL,
                estimated_distance_meters REAL
            );

            CREATE INDEX IF NOT EXISTS idx_obs_source_mac ON observations(source_mac);
            CREATE INDEX IF NOT EXISTS idx_obs_timestamp ON observations(timestamp);
            CREATE INDEX IF NOT EXISTS idx_obs_frame_type ON observations(frame_type);
            CREATE INDEX IF NOT EXISTS idx_obs_ssid ON observations(ssid);

            CREATE TABLE IF NOT EXISTS leases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                client_id TEXT,
                vendor_class TEXT,
                dhcp_fingerprint_opt55 TEXT,
                parameter_request_list TEXT,
                lease_duration_secs INTEGER,
                source_type TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_leases_mac ON leases(mac_address);
            CREATE INDEX IF NOT EXISTS idx_leases_ip ON leases(ip_address);

            CREATE TABLE IF NOT EXISTS telemetry_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                forwarded_for TEXT,
                user_agent TEXT,
                sec_ch_ua TEXT,
                sec_ch_ua_platform TEXT,
                query_params TEXT,
                path TEXT NOT NULL,
                client_fingerprint_json TEXT,
                geolocation_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_telemetry_token ON telemetry_hits(token);
            CREATE INDEX IF NOT EXISTS idx_telemetry_ip ON telemetry_hits(remote_ip);

            CREATE TABLE IF NOT EXISTS correlated_targets (
                target_id TEXT PRIMARY KEY,
                mac_address TEXT NOT NULL UNIQUE,
                is_randomized_mac INTEGER NOT NULL DEFAULT 0,
                mac_vendor TEXT,
                local_ip TEXT,
                public_ip TEXT,
                hostname TEXT,
                last_rssi INTEGER NOT NULL,
                last_ssid TEXT,
                last_channel INTEGER,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 1,
                user_agent TEXT,
                estimated_distance_meters REAL,
                distance_confidence REAL,
                signal_quality_percent REAL
            );

            CREATE INDEX IF NOT EXISTS idx_targets_mac ON correlated_targets(mac_address);
            CREATE INDEX IF NOT EXISTS idx_targets_local_ip ON correlated_targets(local_ip);
            CREATE INDEX IF NOT EXISTS idx_targets_public_ip ON correlated_targets(public_ip);
            CREATE INDEX IF NOT EXISTS idx_targets_last_seen ON correlated_targets(last_seen);

            CREATE TABLE IF NOT EXISTS randomized_mac_clusters (
                cluster_id TEXT PRIMARY KEY,
                pattern_prefix TEXT NOT NULL,
                mac_addresses TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_clusters_prefix ON randomized_mac_clusters(pattern_prefix);
            "#,
        )?;
        Ok(())
    }

    pub fn record_observation(&self, obs: &DeviceObservation) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let frame_type_str = serde_json::to_string(&obs.frame_type)?;
        let medium_str = serde_json::to_string(&obs.medium)?;
        let ie_json_str = serde_json::to_string(&obs.information_elements)?;
        let is_randomized = Self::is_randomized_mac(&obs.source_mac);
        let mac_vendor = crate::network_stack::NetworkStack::lookup_oui(&obs.source_mac);
        let distance_est = Self::estimate_distance_from_rssi(obs.rssi);
        let frame_control_json = serde_json::to_string(&obs.frame_control)?;
        let radiotap_json = serde_json::to_string(&obs.radiotap_header)?;
        let sdr_burst_json = obs.sdr_burst_info.as_ref().and_then(|b| serde_json::to_string(b).ok());
        let cellular_info_json = obs.cellular_burst_info.as_ref().and_then(|b| serde_json::to_string(b).ok());

        conn.execute(
            r#"
            INSERT INTO observations (
                id, timestamp, source_mac, is_randomized_mac, mac_vendor, destination_mac, bssid, ssid, rssi,
                noise_dbm, snr_db, channel, frequency_mhz, frame_type, frame_control_json, medium,
                sequence_number, retry_flag, power_mgmt_flag, more_data_flag, protected_flag,
                information_elements_json, radiotap_json, sdr_burst_json, cellular_info_json, raw_length, estimated_distance_meters
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)
            "#,
            params![
                obs.id,
                obs.timestamp.to_rfc3339(),
                obs.source_mac,
                is_randomized as i32,
                mac_vendor,
                obs.destination_mac,
                obs.bssid,
                obs.ssid,
                obs.rssi,
                obs.noise_dbm,
                obs.snr_db,
                obs.channel,
                obs.frequency_mhz,
                frame_type_str,
                frame_control_json,
                medium_str,
                obs.sequence_number,
                obs.frame_control.retry as i32,
                obs.frame_control.power_mgmt as i32,
                obs.frame_control.more_data as i32,
                obs.frame_control.protected as i32,
                ie_json_str,
                radiotap_json,
                sdr_burst_json,
                cellular_info_json,
                obs.raw_length as i64,
                distance_est.estimated_distance_meters,
            ],
        )?;

        if is_randomized {
            Self::update_randomized_mac_cluster(&conn, &obs.source_mac, &obs.timestamp)?;
        }

        let now_str = obs.timestamp.to_rfc3339();
        let signal_quality = Self::calculate_signal_quality(obs.rssi, obs.noise_dbm);
        conn.execute(
            r#"
            INSERT INTO correlated_targets (
                target_id, mac_address, is_randomized_mac, mac_vendor, local_ip, public_ip, hostname, last_rssi, last_ssid,
                last_channel, first_seen, last_seen, observation_count, user_agent, estimated_distance_meters,
                distance_confidence, signal_quality_percent
            ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, ?5, ?6, ?7, ?8, ?8, 1, NULL, ?9, ?10, ?11)
            ON CONFLICT(mac_address) DO UPDATE SET
                last_rssi = excluded.last_rssi,
                last_ssid = COALESCE(excluded.last_ssid, correlated_targets.last_ssid),
                last_channel = excluded.last_channel,
                last_seen = excluded.last_seen,
                observation_count = correlated_targets.observation_count + 1,
                estimated_distance_meters = excluded.estimated_distance_meters,
                distance_confidence = excluded.distance_confidence,
                signal_quality_percent = excluded.signal_quality_percent
            "#,
            params![
                Uuid::new_v4().to_string(),
                obs.source_mac,
                is_randomized as i32,
                mac_vendor,
                obs.rssi,
                obs.ssid,
                obs.channel,
                now_str,
                distance_est.estimated_distance_meters,
                distance_est.confidence,
                signal_quality,
            ],
        )?;

        Ok(())
    }

    fn is_randomized_mac(mac: &str) -> bool {
        let bytes: Vec<&str> = mac.split(':').collect();
        if bytes.len() != 6 {
            return false;
        }
        if let Ok(second_byte) = u8::from_str_radix(bytes[1], 16) {
            let second_bit = (second_byte & 0x02) != 0;
            let locally_administered = (second_byte & 0x02) != 0;
            let is_unicast = (second_byte & 0x01) == 0;
            return locally_administered && is_unicast;
        }
        false
    }

    fn estimate_distance_from_rssi(rssi: i16) -> RssiDistanceEstimate {
        let tx_power_dbm: f64 = -30.0;
        let path_loss_exponent: f64 = 2.0;
        let reference_distance: f64 = 1.0;

        let path_loss = (tx_power_dbm - rssi as f64).abs();
        let distance_meters = reference_distance * (10.0_f64).powf(path_loss / (10.0 * path_loss_exponent));
        
        let confidence = if rssi > -50 { 0.95 } else if rssi > -60 { 0.85 } else if rssi > -70 { 0.70 } else { 0.50 };

        RssiDistanceEstimate {
            estimated_distance_meters: distance_meters,
            confidence,
            path_loss_db: path_loss,
            rssi_used: rssi,
        }
    }

    fn calculate_signal_quality(rssi: i16, noise: Option<i16>) -> f64 {
        let noise_dbm = noise.unwrap_or(-95);
        let snr = (rssi - noise_dbm) as f64;
        let quality = ((snr + 30.0) / 50.0).clamp(0.0, 1.0) * 100.0;
        quality
    }

    fn update_randomized_mac_cluster(conn: &Connection, mac: &str, timestamp: &DateTime<Utc>) -> Result<()> {
        let bytes: Vec<&str> = mac.split(':').collect();
        if bytes.len() >= 4 {
            let prefix = format!("{}:{}:{}:*", bytes[0], bytes[1], bytes[2]);
            let cluster_id = format!("cluster-{}", prefix.replace(':', "-"));
            let ts_str = timestamp.to_rfc3339();

            conn.execute(
                r#"
                INSERT INTO randomized_mac_clusters (cluster_id, pattern_prefix, mac_addresses, first_seen, last_seen, observation_count)
                VALUES (?1, ?2, ?3, ?4, ?4, 1)
                ON CONFLICT(cluster_id) DO UPDATE SET
                    mac_addresses = mac_addresses || ',' || excluded.mac_addresses,
                    last_seen = excluded.last_seen,
                    observation_count = observation_count + 1
                "#,
                params![cluster_id, prefix, mac, ts_str],
            )?;
        }
        Ok(())
    }

    pub fn record_lease(&self, lease: &NetworkLease) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let ip_str = lease.ip_address.to_string();
        let ts_str = lease.timestamp.to_rfc3339();
        let source_type_str = serde_json::to_string(&lease.source_type)?;
        let param_list_str = if lease.parameter_request_list.is_empty() { None } else { Some(lease.parameter_request_list.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")) };

        conn.execute(
            r#"
            INSERT INTO leases (
                timestamp, mac_address, ip_address, hostname, client_id, vendor_class,
                dhcp_fingerprint_opt55, parameter_request_list, lease_duration_secs, source_type
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                ts_str,
                lease.mac_address,
                ip_str,
                lease.hostname,
                lease.client_id,
                lease.vendor_class,
                lease.dhcp_fingerprint_opt55,
                param_list_str,
                lease.lease_duration_secs,
                source_type_str,
            ],
        )?;

        let mac_vendor = crate::network_stack::NetworkStack::lookup_oui(&lease.mac_address);
        conn.execute(
            r#"
            INSERT INTO correlated_targets (
                target_id, mac_address, is_randomized_mac, mac_vendor, local_ip, public_ip, hostname, last_rssi, last_ssid,
                last_channel, first_seen, last_seen, observation_count, user_agent, estimated_distance_meters,
                distance_confidence, signal_quality_percent
            ) VALUES (?1, ?2, 0, ?3, ?4, NULL, ?5, 0, NULL, NULL, ?6, ?6, 1, NULL, NULL, NULL, NULL)
            ON CONFLICT(mac_address) DO UPDATE SET
                local_ip = excluded.local_ip,
                hostname = COALESCE(excluded.hostname, correlated_targets.hostname),
                mac_vendor = COALESCE(excluded.mac_vendor, correlated_targets.mac_vendor),
                last_seen = excluded.last_seen
            "#,
            params![
                Uuid::new_v4().to_string(),
                lease.mac_address,
                mac_vendor,
                ip_str,
                lease.hostname,
                ts_str,
            ],
        )?;

        Ok(())
    }

    pub fn record_telemetry_hit(&self, hit: &TelemetryHit) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let ip_str = hit.remote_ip.to_string();
        let ts_str = hit.timestamp.to_rfc3339();
        let fp_json = hit.client_fingerprint.as_ref().and_then(|f| serde_json::to_string(f).ok());
        let geo_json = hit.geolocation.as_ref().and_then(|g| serde_json::to_string(g).ok());

        conn.execute(
            r#"
            INSERT INTO telemetry_hits (
                token, timestamp, remote_ip, forwarded_for, user_agent, sec_ch_ua, sec_ch_ua_platform,
                query_params, path, client_fingerprint_json, geolocation_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                hit.token,
                ts_str,
                ip_str,
                hit.forwarded_for,
                hit.user_agent,
                hit.sec_ch_ua,
                hit.sec_ch_ua_platform,
                hit.query_params,
                hit.path,
                fp_json,
                geo_json,
            ],
        )?;

        conn.execute(
            r#"
            UPDATE correlated_targets
            SET public_ip = ?1,
                user_agent = COALESCE(?2, user_agent),
                last_seen = ?3
            WHERE target_id = ?4 OR mac_address = ?4 OR local_ip = ?4
            "#,
            params![
                ip_str,
                hit.user_agent,
                ts_str,
                hit.token,
            ],
        )?;

        Ok(())
    }

    pub fn get_recent_targets(&self, limit: usize) -> Result<Vec<CorrelatedTarget>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT target_id, mac_address, is_randomized_mac, mac_vendor, local_ip, public_ip, hostname, last_rssi, last_ssid,
                   last_channel, first_seen, last_seen, observation_count, user_agent, estimated_distance_meters,
                   distance_confidence, signal_quality_percent
            FROM correlated_targets
            ORDER BY last_seen DESC
            LIMIT ?1
            "#,
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let target_id: String = row.get(0)?;
            let mac_address: String = row.get(1)?;
            let is_randomized_mac: i32 = row.get(2)?;
            let mac_vendor: Option<String> = row.get(3)?;
            let local_ip_str: Option<String> = row.get(4)?;
            let public_ip_str: Option<String> = row.get(5)?;
            let hostname: Option<String> = row.get(6)?;
            let last_rssi: i16 = row.get(7)?;
            let last_ssid: Option<String> = row.get(8)?;
            let last_channel: Option<u8> = row.get(9)?;
            let first_seen_str: String = row.get(10)?;
            let last_seen_str: String = row.get(11)?;
            let observation_count: i64 = row.get(12)?;
            let user_agent: Option<String> = row.get(13)?;
            let estimated_distance_meters: Option<f64> = row.get(14)?;
            let distance_confidence: Option<f64> = row.get(15)?;
            let signal_quality_percent: Option<f64> = row.get(16)?;

            let local_ip = local_ip_str.and_then(|s| IpAddr::from_str(&s).ok());
            let public_ip = public_ip_str.and_then(|s| IpAddr::from_str(&s).ok());
            let first_seen = DateTime::parse_from_rfc3339(&first_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(CorrelatedTarget {
                target_id,
                mac_address,
                is_randomized_mac: is_randomized_mac != 0,
                mac_vendor,
                local_ip,
                public_ip,
                hostname,
                last_rssi,
                last_ssid,
                last_channel,
                first_seen,
                last_seen,
                observation_count: observation_count as u64,
                user_agent,
                estimated_distance_meters,
                distance_confidence,
                signal_quality_percent,
            })
        })?;

        let mut targets = Vec::new();
        for r in rows {
            targets.push(r?);
        }
        Ok(targets)
    }

    pub fn get_target_by_identifier(&self, id_or_mac: &str) -> Result<Option<CorrelatedTarget>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT target_id, mac_address, is_randomized_mac, mac_vendor, local_ip, public_ip, hostname, last_rssi, last_ssid,
                   last_channel, first_seen, last_seen, observation_count, user_agent, estimated_distance_meters,
                   distance_confidence, signal_quality_percent
            FROM correlated_targets
            WHERE target_id = ?1 OR mac_address = ?1 OR local_ip = ?1 OR public_ip = ?1
            LIMIT 1
            "#,
        )?;

        let mut rows = stmt.query_map(params![id_or_mac], |row| {
            let target_id: String = row.get(0)?;
            let mac_address: String = row.get(1)?;
            let is_randomized_mac: i32 = row.get(2)?;
            let mac_vendor: Option<String> = row.get(3)?;
            let local_ip_str: Option<String> = row.get(4)?;
            let public_ip_str: Option<String> = row.get(5)?;
            let hostname: Option<String> = row.get(6)?;
            let last_rssi: i16 = row.get(7)?;
            let last_ssid: Option<String> = row.get(8)?;
            let last_channel: Option<u8> = row.get(9)?;
            let first_seen_str: String = row.get(10)?;
            let last_seen_str: String = row.get(11)?;
            let observation_count: i64 = row.get(12)?;
            let user_agent: Option<String> = row.get(13)?;
            let estimated_distance_meters: Option<f64> = row.get(14)?;
            let distance_confidence: Option<f64> = row.get(15)?;
            let signal_quality_percent: Option<f64> = row.get(16)?;

            let local_ip = local_ip_str.and_then(|s| IpAddr::from_str(&s).ok());
            let public_ip = public_ip_str.and_then(|s| IpAddr::from_str(&s).ok());
            let first_seen = DateTime::parse_from_rfc3339(&first_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(CorrelatedTarget {
                target_id,
                mac_address,
                is_randomized_mac: is_randomized_mac != 0,
                mac_vendor,
                local_ip,
                public_ip,
                hostname,
                last_rssi,
                last_ssid,
                last_channel,
                first_seen,
                last_seen,
                observation_count: observation_count as u64,
                user_agent,
                estimated_distance_meters,
                distance_confidence,
                signal_quality_percent,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn get_recent_observations(&self, limit: usize) -> Result<Vec<DeviceObservation>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, timestamp, source_mac, destination_mac, bssid, ssid, rssi, noise_dbm, snr_db, channel,
                   frequency_mhz, frame_type, frame_control_json, medium, sequence_number, retry_flag,
                   power_mgmt_flag, more_data_flag, protected_flag, information_elements_json,
                   radiotap_json, sdr_burst_json, cellular_info_json, raw_length, estimated_distance_meters
            FROM observations
            ORDER BY timestamp DESC
            LIMIT ?1
            "#,
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let id: String = row.get(0)?;
            let ts_str: String = row.get(1)?;
            let source_mac: String = row.get(2)?;
            let destination_mac: Option<String> = row.get(3)?;
            let bssid: Option<String> = row.get(4)?;
            let ssid: Option<String> = row.get(5)?;
            let rssi: i16 = row.get(6)?;
            let noise_dbm: Option<i16> = row.get(7)?;
            let snr_db: Option<f64> = row.get(8)?;
            let channel: Option<u8> = row.get(9)?;
            let frequency_mhz: Option<u16> = row.get(10)?;
            let frame_type_str: String = row.get(11)?;
            let frame_control_json: Option<String> = row.get(12)?;
            let medium_str: String = row.get(13)?;
            let sequence_number: Option<u16> = row.get(14)?;
            let retry_flag: i32 = row.get(15)?;
            let power_mgmt_flag: i32 = row.get(16)?;
            let more_data_flag: i32 = row.get(17)?;
            let protected_flag: i32 = row.get(18)?;
            let information_elements_json: Option<String> = row.get(19)?;
            let radiotap_json: Option<String> = row.get(20)?;
            let sdr_burst_json: Option<String> = row.get(21)?;
            let cellular_info_json: Option<String> = row.get(22)?;
            let raw_length: i64 = row.get(23)?;
            let estimated_distance_meters: Option<f64> = row.get(24)?;

            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let frame_type: FrameSubtype = serde_json::from_str(&frame_type_str)
                .unwrap_or(FrameSubtype::Unknown);
            let medium: RadioMedium = serde_json::from_str(&medium_str)
                .unwrap_or(RadioMedium::Wifi);
            let information_elements: ParsedInformationElements = information_elements_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let frame_control = frame_control_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let radiotap_header = radiotap_json
                .and_then(|s| serde_json::from_str(&s).ok());
            let sdr_burst_info = sdr_burst_json
                .and_then(|s| serde_json::from_str(&s).ok());
            let cellular_burst_info = cellular_info_json
                .and_then(|s| serde_json::from_str(&s).ok());

            Ok(DeviceObservation {
                id,
                timestamp,
                source_mac,
                destination_mac,
                bssid,
                ssid,
                rssi,
                noise_dbm,
                snr_db,
                channel,
                frequency_mhz,
                frame_type,
                frame_control,
                medium,
                sequence_number,
                information_elements,
                radiotap_header,
                sdr_burst_info,
                cellular_burst_info,
                raw_length: raw_length as usize,
                estimated_distance_meters,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn get_system_stats(&self) -> Result<SystemStatistics> {
        let conn = self.conn.lock().unwrap();

        let total_frames: i64 = conn.query_row(
            "SELECT COUNT(*) FROM observations",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let unique_macs: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT source_mac) FROM observations",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let active_leases: i64 = conn.query_row(
            "SELECT COUNT(*) FROM leases",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let telemetry_hits: i64 = conn.query_row(
            "SELECT COUNT(*) FROM telemetry_hits",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let cellular_bursts: i64 = conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE medium = '\"cellular\"'",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let wifi_probes: i64 = conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE frame_type = '\"ProbeRequest\"'",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let wifi_beacons: i64 = conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE frame_type = '\"Beacon\"'",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let wifi_associations: i64 = conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE frame_type IN ('\"AssociationRequest\"', '\"AssociationResponse\"')",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        Ok(SystemStatistics {
            total_frames: total_frames as u64,
            wifi_probes: wifi_probes as u64,
            wifi_beacons: wifi_beacons as u64,
            wifi_associations: wifi_associations as u64,
            cellular_bursts: cellular_bursts as u64,
            unique_macs: unique_macs as u64,
            active_leases: active_leases as u64,
            telemetry_hits: telemetry_hits as u64,
        })
    }

    pub fn get_channel_occupancy(&self) -> Result<Vec<(u8, u64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT channel, COUNT(*) as count
            FROM observations
            WHERE channel IS NOT NULL
            GROUP BY channel
            ORDER BY channel
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            let channel: u8 = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((channel, count as u64))
        })?;

        let mut occupancy = Vec::new();
        for r in rows {
            occupancy.push(r?);
        }
        Ok(occupancy)
    }

    pub fn export_targets_geojson_string(&self) -> Result<String> {
        let targets = self.get_recent_targets(10000)?;
        let mut features = Vec::new();

        for t in targets {
            if let (Some(local_ip), Some(estimated_distance)) = (t.local_ip, t.estimated_distance_meters) {
                let feature = serde_json::json!({
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [0.0, 0.0]
                    },
                    "properties": {
                        "target_id": t.target_id,
                        "mac_address": t.mac_address,
                        "local_ip": local_ip.to_string(),
                        "public_ip": t.public_ip.map(|i| i.to_string()),
                        "hostname": t.hostname,
                        "last_rssi": t.last_rssi,
                        "last_ssid": t.last_ssid,
                        "last_channel": t.last_channel,
                        "first_seen": t.first_seen.to_rfc3339(),
                        "last_seen": t.last_seen.to_rfc3339(),
                        "observation_count": t.observation_count,
                        "user_agent": t.user_agent,
                        "estimated_distance_meters": estimated_distance,
                        "distance_confidence": t.distance_confidence,
                        "signal_quality_percent": t.signal_quality_percent,
                        "is_randomized_mac": t.is_randomized_mac,
                        "mac_vendor": t.mac_vendor
                    }
                });
                features.push(feature);
            }
        }

        let geojson = serde_json::json!({
            "type": "FeatureCollection",
            "features": features
        });

        Ok(serde_json::to_string_pretty(&geojson)?)
    }

    pub fn export_targets_kml_string(&self) -> Result<String> {
        let targets = self.get_recent_targets(10000)?;
        let mut placemarks = Vec::new();

        for t in targets {
            let placemark = format!(
                r#"<Placemark>
                    <name>{}</name>
                    <description>
                        MAC: {}
                        Local IP: {}
                        Public IP: {}
                        Hostname: {}
                        Last RSSI: {} dBm
                        Last SSID: {}
                        Observations: {}
                        Estimated Distance: {:.2} m
                    </description>
                    <Point>
                        <coordinates>0,0,0</coordinates>
                    </Point>
                </Placemark>"#,
                t.mac_address,
                t.mac_address,
                t.local_ip.map(|i| i.to_string()).unwrap_or_default(),
                t.public_ip.map(|i| i.to_string()).unwrap_or_default(),
                t.hostname.unwrap_or_default(),
                t.last_rssi,
                t.last_ssid.unwrap_or_default(),
                t.observation_count,
                t.estimated_distance_meters.unwrap_or(0.0)
            );
            placemarks.push(placemark);
        }

        let kml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <kml xmlns="http://www.opengis.net/kml/2.2">
                <Document>
                    {}
                </Document>
            </kml>"#,
            placemarks.join("\n")
        );

        Ok(kml)
    }

    pub fn export_targets_json<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let targets = self.get_recent_targets(10000)?;
        let json_str = serde_json::to_string_pretty(&targets)?;
        let mut file = File::create(path)?;
        file.write_all(json_str.as_bytes())?;
        Ok(())
    }

    pub fn export_targets_csv<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let targets = self.get_recent_targets(10000)?;
        let mut file = File::create(path)?;
        writeln!(
            file,
            "target_id,mac_address,local_ip,public_ip,hostname,last_rssi,last_ssid,first_seen,last_seen,observations,user_agent"
        )?;

        for t in targets {
            writeln!(
                file,
                "{},{},{},{},{},{},{},{},{},{},{}",
                t.target_id,
                t.mac_address,
                t.local_ip.map(|i| i.to_string()).unwrap_or_default(),
                t.public_ip.map(|i| i.to_string()).unwrap_or_default(),
                t.hostname.unwrap_or_default(),
                t.last_rssi,
                t.last_ssid.unwrap_or_default(),
                t.first_seen.to_rfc3339(),
                t.last_seen.to_rfc3339(),
                t.observation_count,
                t.user_agent.unwrap_or_default().replace(',', ";")
            )?;
        }
        Ok(())
    }
}
