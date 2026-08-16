use crate::logger::Database;
use crate::types::{
    CapabilityInformation, CellularBurstInfo, CipherSuite, CountryInfo, DeviceObservation, 
    DuplexMode, FrameControl, FrameSubtype, HtCapabilities, HtOperation, IqSample, 
    ModulationType, ParsedInformationElements, PowerSpectrum, RadiotapHeader, 
    RadiotapChannel, RadioMedium, RssiDistanceEstimate, RsnCapabilities, RsnInfo, 
    SdrBurstProperties, VhtCapabilities, VhtOperation, WpsInfo,
};
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

pub struct RadioEngine {
    interface: String,
    medium: RadioMedium,
    stealth: bool,
    pcap_file: Option<String>,
    sdr_source: Option<String>,
    channel_hop: bool,
    db: Database,
    running: Arc<AtomicBool>,
}

impl RadioEngine {
    pub fn new(
        interface: String,
        medium: RadioMedium,
        stealth: bool,
        pcap_file: Option<String>,
        sdr_source: Option<String>,
        channel_hop: bool,
        db: Database,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            interface,
            medium,
            stealth,
            pcap_file,
            sdr_source,
            channel_hop,
            db,
            running,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel::<DeviceObservation>(5000);
        let db_clone = self.db.clone();

        tokio::spawn(async move {
            while let Some(obs) = rx.recv().await {
                if let Err(e) = db_clone.record_observation(&obs) {
                    error!("Database observation record failed: {:?}", e);
                }
            }
        });

        match self.medium {
            RadioMedium::Wifi => {
                if self.channel_hop && self.pcap_file.is_none() {
                    self.spawn_channel_hopper();
                }
                self.run_wifi_sniffer(tx).await?;
            }
            RadioMedium::Cellular | RadioMedium::RawSdr => {
                self.run_sdr_dsp_processor(tx).await?;
            }
            RadioMedium::Bluetooth => {
                self.run_bluetooth_le_processor(tx).await?;
            }
        }

        Ok(())
    }

    fn spawn_channel_hopper(&self) {
        let running = self.running.clone();
        let db = self.db.clone();

        tokio::spawn(async move {
            let channels_2g: &[u8] = &[1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10];
            let channels_5g: &[u8] = &[36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 149, 153, 157, 161, 165];
            let mut all_channels = Vec::new();
            all_channels.extend_from_slice(channels_2g);
            all_channels.extend_from_slice(channels_5g);

            let mut idx = 0;
            while running.load(Ordering::Relaxed) {
                let current_ch = all_channels[idx % all_channels.len()];
                idx += 1;
                let _ = db.record_channel_hop(current_ch);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }

    async fn run_wifi_sniffer(&self, tx: mpsc::Sender<DeviceObservation>) -> Result<()> {
        let running = self.running.clone();
        let pcap_file = self.pcap_file.clone();
        let interface = self.interface.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            if let Some(ref file_path) = pcap_file {
                info!("Initializing 802.11 monitor capture from PCAP: {}", file_path);
                match pcap::Capture::from_file(file_path) {
                    Ok(mut cap) => {
                        while running.load(Ordering::Relaxed) {
                            match cap.next_packet() {
                                Ok(packet) => {
                                    if let Some(obs) = Self::dissect_radiotap_80211(packet.data) {
                                        let _ = tx.blocking_send(obs);
                                    }
                                }
                                Err(pcap::Error::NoMorePackets) => {
                                    info!("PCAP file replay finished.");
                                    break;
                                }
                                Err(pcap::Error::TimeoutExpired) => continue,
                                Err(e) => {
                                    warn!("PCAP parse error: {:?}", e);
                                    break;
                                }
                            }
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        error!("Failed to open PCAP file {}: {:?}", file_path, e);
                        return Err(e.into());
                    }
                }
            }

            info!("Attempting live monitor bind on interface: {}", interface);
            match pcap::Capture::from_device(interface.as_str()) {
                Ok(builder) => {
                    let open_result = builder
                        .promisc(true)
                        .snaplen(65535)
                        .timeout(100)
                        .immediate_mode(true)
                        .open();

                    match open_result {
                        Ok(mut active_cap) => {
                            info!("Live 802.11 monitor mode active on {}", interface);
                            while running.load(Ordering::Relaxed) {
                                match active_cap.next_packet() {
                                    Ok(packet) => {
                                        if let Some(obs) = Self::dissect_radiotap_80211(packet.data) {
                                            let _ = tx.blocking_send(obs);
                                        }
                                    }
                                    Err(pcap::Error::TimeoutExpired) => continue,
                                    Err(e) => {
                                        warn!("Live capture read warning: {:?}", e);
                                    }
                                }
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            error!("Physical monitor open failed on {}: {}. Monitor mode requires root/admin privileges and compatible wireless hardware.", interface, e);
                            return Err(e.into());
                        }
                    }
                }
                Err(e) => {
                    error!("Device lookup failed on {}: {}. Interface not found or incompatible.", interface, e);
                    return Err(e.into());
                }
            }
        })
        .await
        .context("Radio capture worker panicked")??;

        Ok(())
    }


    async fn run_sdr_dsp_processor(&self, tx: mpsc::Sender<DeviceObservation>) -> Result<()> {
        info!("Starting Real-Time SDR Baseband I/Q Signal & Cellular Burst DSP Pipeline...");
        let running = self.running.clone();
        let sdr_source = self.sdr_source.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            if let Some(ref source) = sdr_source {
                info!("Connecting to SDR source: {}", source);
                
                match source {
                    s if s.starts_with("rtlsdr://") => {
                        error!("RTL-SDR hardware requires librtlsdr. Install librtlsdr-dev and enable the rtl-sdr feature.");
                        return Err(anyhow::anyhow!("RTL-SDR hardware not available. Install librtlsdr-dev and rebuild with rtl-sdr feature."));
                    }
                    s if s.starts_with("hackrf://") => {
                        error!("HackRF hardware requires libhackrf. Install libhackrf-dev and enable the hackrf feature.");
                        return Err(anyhow::anyhow!("HackRF hardware not available. Install libhackrf-dev and rebuild with hackrf feature."));
                    }
                    s if s.ends_with(".bin") || s.ends_with(".iq") => {
                        info!("Processing I/Q samples from file: {}", source);
                        if let Ok(iq_data) = std::fs::read(source) {
                            let sample_rate = 2400000;
                            let mut iq_samples = Vec::new();
                            for chunk in iq_data.chunks(8) {
                                if chunk.len() >= 8 {
                                    let i = i16::from_le_bytes([chunk[0], chunk[1]]) as f32 / 127.0;
                                    let q = i16::from_le_bytes([chunk[2], chunk[3]]) as f32 / 127.0;
                                    iq_samples.push(IqSample { i, q });
                                }
                            }
                            if let Some(power_spectrum) = Self::process_iq_samples(&iq_samples, sample_rate) {
                                let burst_info = CellularBurstInfo {
                                    center_frequency_hz: Some(power_spectrum.peak_frequency_hz),
                                    bandwidth_hz: Some(sample_rate as f64),
                                    peak_power_dbm: Some(power_spectrum.peak_power_db),
                                    modulation_type: Some(ModulationType::Unknown),
                                    snr_db: Some(power_spectrum.peak_power_db - (-90.0)),
                                };
                                
                                let obs = DeviceObservation {
                                    id: Uuid::new_v4().to_string(),
                                    timestamp: Utc::now(),
                                    source_mac: "00:00:00:00:00:00".to_string(),
                                    is_randomized_mac: false,
                                    mac_vendor: None,
                                    destination_mac: None,
                                    bssid: None,
                                    ssid: None,
                                    rssi: power_spectrum.peak_power_db as i16,
                                    noise_dbm: Some(-90),
                                    snr_db: Some(power_spectrum.peak_power_db - (-90.0)),
                                    channel: None,
                                    frequency_mhz: Some((power_spectrum.peak_frequency_hz / 1e6) as u16),
                                    frame_type: FrameSubtype::Unknown,
                                    frame_control: None,
                                    medium: RadioMedium::RawSdr,
                                    sequence_number: None,
                                    retry_flag: false,
                                    power_mgmt_flag: false,
                                    more_data_flag: false,
                                    protected_flag: false,
                                    information_elements: ParsedInformationElements::default(),
                                    radiotap_header: None,
                                    sdr_burst_info: Some(SdrBurstProperties {
                                        sample_rate_hz: sample_rate,
                                        center_frequency_hz: power_spectrum.peak_frequency_hz,
                                        gain_db: None,
                                        iq_samples: iq_samples.len(),
                                        power_spectrum: Some(power_spectrum),
                                    }),
                                    cellular_burst_info: Some(burst_info),
                                    raw_length: iq_data.len(),
                                    estimated_distance_meters: None,
                                };
                                let _ = tx.blocking_send(obs);
                            }
                        }
                        return Ok(());
                    }
                    _ => {
                        error!("Unsupported SDR source format. Use rtlsdr://, hackrf://, or .bin/.iq file.");
                        return Err(anyhow::anyhow!("Unsupported SDR source format"));
                    }
                }
            } else {
                error!("No SDR source specified. Use --sdr-source to specify device or file.");
                return Err(anyhow::anyhow!("SDR source not specified"));
            }
        })
        .await
        .context("SDR baseband worker panicked")??;

        Ok(())
    }

    async fn run_bluetooth_le_processor(&self, tx: mpsc::Sender<DeviceObservation>) -> Result<()> {
        info!("Starting Bluetooth Low Energy (BLE) Advertising Channel Dissector...");
        let running = self.running.clone();
        let interface = self.interface.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            info!("Attempting BLE capture on interface: {}", interface);
            
            #[cfg(target_os = "linux")]
            {
                match std::fs::read_to_string("/sys/kernel/debug/bluetooth/hci0/identity") {
                    Ok(_) => {
                        info!("HCI interface detected. BLE scanning requires BlueZ D-Bus API or HCI socket access.");
                        error!("BLE scanning requires BlueZ library (bluez-rs) or HCI socket privileges. Install bluez and run with appropriate permissions.");
                        return Err(anyhow::anyhow!("BLE scanning requires BlueZ library and root privileges for HCI socket access."));
                    }
                    Err(_) => {
                        error!("No HCI interface found. Ensure Bluetooth hardware is available and BlueZ is running.");
                        return Err(anyhow::anyhow!("No HCI interface found. Bluetooth hardware not available."));
                    }
                }
            }
            
            #[cfg(target_os = "windows")]
            {
                error!("BLE scanning on Windows requires Windows Bluetooth APIs. Use windows-rs crate with Bluetooth LE APIs.");
                return Err(anyhow::anyhow!("BLE scanning on Windows requires Windows Bluetooth APIs. Enable windows-rs feature."));
            }
            
            #[cfg(target_os = "macos")]
            {
                error!("BLE scanning on macOS requires CoreBluetooth framework. Use objc-rs and CoreBluetooth bindings.");
                return Err(anyhow::anyhow!("BLE scanning on macOS requires CoreBluetooth framework. Enable macOS feature."));
            }
            
            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            {
                error!("BLE scanning not supported on this platform.");
                return Err(anyhow::anyhow!("BLE scanning not supported on this platform."));
            }
        })
        .await
        .context("BLE worker panicked")??;

        Ok(())
    }

    fn process_iq_samples(iq_samples: &[IqSample], sample_rate: u32) -> Option<PowerSpectrum> {
        if iq_samples.len() < 128 {
            return None;
        }

        let sum_i: f32 = iq_samples.iter().map(|s| s.i).sum();
        let sum_q: f32 = iq_samples.iter().map(|s| s.q).sum();
        let mean_i = sum_i / iq_samples.len() as f32;
        let mean_q = sum_q / iq_samples.len() as f32;

        let n = iq_samples.len();
        let mut power_db = Vec::with_capacity(n / 2);
        
        for k in 0..n / 2 {
            let mut real: f32 = 0.0;
            let mut imag: f32 = 0.0;
            
            for (i, sample) in iq_samples.iter().enumerate() {
                let angle = -2.0 * std::f32::consts::PI * (k * i) as f32 / n as f32;
                let i_dc = sample.i - mean_i;
                let q_dc = sample.q - mean_q;
                real += i_dc * angle.cos() - q_dc * angle.sin();
                imag += i_dc * angle.sin() + q_dc * angle.cos();
            }
            
            let magnitude = (real * real + imag * imag).sqrt();
            let power_db = 20.0 * (magnitude / n as f32).log10().max(-100.0);
            power_db.push(power_db);
        }

        let peak_index = power_db.iter().enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(i, _)| i)
            .unwrap_or(0);

        let peak_power_db = power_db[peak_index];
        let peak_frequency_hz = (peak_index as f64 * sample_rate as f64 / n as f64);

        let frequency_bins: Vec<f64> = (0..n / 2)
            .map(|k| k as f64 * sample_rate as f64 / n as f64)
            .collect();

        Some(PowerSpectrum {
            frequency_bins,
            power_db,
            peak_index,
            peak_frequency_hz,
            peak_power_db,
        })
    }

    pub fn estimate_distance_from_rssi(rssi: i16, freq_mhz: u16) -> RssiDistanceEstimate {
        let tx_power_1m = if freq_mhz > 4000 { -45.0 } else { -40.0 };
        let path_loss_exponent = 2.8;

        let diff = tx_power_1m - (rssi as f64);
        let distance_meters = 10.0f64.powf(diff / (10.0 * path_loss_exponent));
        let distance_meters = distance_meters.max(0.1).min(500.0);

        let signal_quality_percent = ((rssi + 100) as f32 / 70.0 * 100.0).max(0.0).min(100.0);

        let confidence = if distance_meters < 10.0 {
            0.95
        } else if distance_meters < 50.0 {
            0.75
        } else if distance_meters < 100.0 {
            0.50
        } else {
            0.25
        };

        RssiDistanceEstimate {
            distance_meters: distance_meters as f32,
            confidence,
            path_loss_exponent,
            tx_power_1m,
            signal_quality_percent,
        }
    }

    pub fn dissect_radiotap_80211(raw: &[u8]) -> Option<DeviceObservation> {
        if raw.len() < 24 {
            return None;
        }

        let mut offset = 0;
        let mut radiotap = RadiotapHeader::default();
        let mut rssi: i16 = -70;
        let mut noise_dbm: Option<i16> = None;
        let mut freq_mhz: Option<u16> = None;
        let mut channel_calc: Option<u8> = None;

        if raw[0] == 0 && raw[1] == 0 {
            if raw.len() < 4 {
                return None;
            }
            let r_len = u16::from_le_bytes([raw[2], raw[3]]) as usize;
            if raw.len() < r_len {
                return None;
            }

            if r_len >= 8 {
                let present = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
                let mut pos = 8;
                while pos < r_len && (raw[pos - 4] & 0x80) != 0 {
                    pos += 4;
                }

                if (present & (1 << 0)) != 0 {
                    pos = (pos + 7) & !7;
                    if pos + 8 <= r_len {
                        radiotap.tsft = Some(u64::from_le_bytes([
                            raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3],
                            raw[pos + 4], raw[pos + 5], raw[pos + 6], raw[pos + 7],
                        ]));
                    }
                    pos += 8;
                }
                if (present & (1 << 1)) != 0 && pos < r_len {
                    let flags = raw[pos];
                    radiotap.flags = Some(crate::types::RadiotapFlags {
                        cfp: (flags & 0x01) != 0,
                        short_preamble: (flags & 0x02) != 0,
                        wep: (flags & 0x04) != 0,
                        fragment: (flags & 0x08) != 0,
                        fcs: (flags & 0x10) != 0,
                        data_pad: (flags & 0x20) != 0,
                        bad_fcs: (flags & 0x40) != 0,
                        short_gi: (flags & 0x80) != 0,
                    });
                    pos += 1;
                }
                if (present & (1 << 2)) != 0 && pos < r_len {
                    radiotap.rate = Some(raw[pos]);
                    pos += 1;
                }
                if (present & (1 << 3)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 4 <= r_len {
                        let f = u16::from_le_bytes([raw[pos], raw[pos + 1]]);
                        let flags = u16::from_le_bytes([raw[pos + 2], raw[pos + 3]]);
                        freq_mhz = Some(f);
                        channel_calc = Self::frequency_to_channel(f);
                        radiotap.channel = Some(RadiotapChannel {
                            frequency_mhz: f,
                            flags,
                        });
                    }
                    pos += 4;
                }
                if (present & (1 << 4)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 2 <= r_len {
                        radiotap.fhss = Some(crate::types::RadiotapFhss {
                            hop_set: u16::from_le_bytes([raw[pos], raw[pos + 1]]) >> 8,
                            hop_pattern: raw[pos + 1],
                        });
                    }
                    pos += 2;
                }
                if (present & (1 << 5)) != 0 && pos < r_len {
                    let sig = raw[pos] as i8;
                    rssi = sig as i16;
                    radiotap.dbm_antenna_signal = Some(sig);
                    pos += 1;
                }
                if (present & (1 << 6)) != 0 && pos < r_len {
                    let n = raw[pos] as i8;
                    noise_dbm = Some(n as i16);
                    radiotap.dbm_antenna_noise = Some(n);
                }
                if (present & (1 << 7)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 2 <= r_len {
                        radiotap.lock_quality = Some(u16::from_le_bytes([raw[pos], raw[pos + 1]]));
                    }
                    pos += 2;
                }
                if (present & (1 << 8)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 2 <= r_len {
                        radiotap.tx_attenuation = Some(u16::from_le_bytes([raw[pos], raw[pos + 1]]));
                    }
                    pos += 2;
                }
                if (present & (1 << 9)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 2 <= r_len {
                        radiotap.db_tx_attenuation = Some(u16::from_le_bytes([raw[pos], raw[pos + 1]]));
                    }
                    pos += 2;
                }
                if (present & (1 << 10)) != 0 && pos < r_len {
                    radiotap.dbm_tx_power = Some(raw[pos] as i8);
                    pos += 1;
                }
                if (present & (1 << 11)) != 0 && pos < r_len {
                    radiotap.antenna = Some(raw[pos]);
                    pos += 1;
                }
                if (present & (1 << 12)) != 0 && pos < r_len {
                    radiotap.db_antenna_signal = Some(raw[pos]);
                    pos += 1;
                }
                if (present & (1 << 13)) != 0 && pos < r_len {
                    radiotap.db_antenna_noise = Some(raw[pos]);
                    pos += 1;
                }
                if (present & (1 << 14)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 2 <= r_len {
                        let flags = u16::from_le_bytes([raw[pos], raw[pos + 1]]);
                        radiotap.rx_flags = Some(crate::types::RadiotapRxFlags {
                            bad_plcp: (flags & 0x02) != 0,
                        });
                    }
                    pos += 2;
                }
                if (present & (1 << 15)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 2 <= r_len {
                        let flags = u16::from_le_bytes([raw[pos], raw[pos + 1]]);
                        radiotap.tx_flags = Some(crate::types::RadiotapTxFlags {
                            fail: (flags & 0x01) != 0,
                        });
                    }
                    pos += 2;
                }
                if (present & (1 << 16)) != 0 && pos + 3 <= r_len {
                    radiotap.mcs = Some(crate::types::RadiotapMcs {
                        known: raw[pos],
                        flags: raw[pos + 1],
                        mcs_rate: raw[pos + 2],
                    });
                    pos += 3;
                }
                if (present & (1 << 17)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 8 <= r_len {
                        radiotap.ampdu_status = Some(crate::types::RadiotapAmpduStatus {
                            reference: u32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]),
                            flags: u16::from_le_bytes([raw[pos + 4], raw[pos + 5]]),
                        });
                    }
                    pos += 8;
                }
                if (present & (1 << 18)) != 0 {
                    pos = (pos + 1) & !1;
                    if pos + 12 <= r_len {
                        radiotap.vht = Some(crate::types::RadiotapVht {
                            known: u16::from_le_bytes([raw[pos], raw[pos + 1]]),
                            flags: u16::from_le_bytes([raw[pos + 2], raw[pos + 3]]),
                            bandwidth: raw[pos + 4],
                            mcs_nss: [raw[pos + 5], raw[pos + 6], raw[pos + 7], raw[pos + 8]],
                            coding: raw[pos + 9],
                            group_id: raw[pos + 10],
                            partial_aid: u16::from_le_bytes([raw[pos + 11], raw[pos + 12]]),
                        });
                    }
                    pos += 12;
                }
                if (present & (1 << 19)) != 0 {
                    pos = (pos + 7) & !7;
                    if pos + 8 <= r_len {
                        radiotap.timestamp = Some(u64::from_le_bytes([
                            raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3],
                            raw[pos + 4], raw[pos + 5], raw[pos + 6], raw[pos + 7],
                        ]));
                    }
                    pos += 8;
                }
                if (present & (1 << 20)) != 0 {
                    pos = (pos + 7) & !7;
                    if pos + 12 <= r_len {
                        radiotap.he = Some(crate::types::RadiotapHe {
                            data1: u16::from_le_bytes([raw[pos], raw[pos + 1]]),
                            data2: u16::from_le_bytes([raw[pos + 2], raw[pos + 3]]),
                            data3: u16::from_le_bytes([raw[pos + 4], raw[pos + 5]]),
                            data4: u16::from_le_bytes([raw[pos + 6], raw[pos + 7]]),
                            data5: u16::from_le_bytes([raw[pos + 8], raw[pos + 9]]),
                            data6: u16::from_le_bytes([raw[pos + 10], raw[pos + 11]]),
                        });
                    }
                    pos += 12;
                }
            }
            offset = r_len;
        }

        let f = &raw[offset..];
        if f.len() < 24 {
            return None;
        }

        let fc = u16::from_le_bytes([f[0], f[1]]);
        let frame_control = FrameControl::from((f[0], f[1]));
        let retry_flag = frame_control.retry;
        let pwr_mgmt_flag = frame_control.power_mgmt;
        let more_data_flag = frame_control.more_data;
        let protected_flag = frame_control.protected;

        let dest_mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            f[4], f[5], f[6], f[7], f[8], f[9]
        );
        let src_mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            f[10], f[11], f[12], f[13], f[14], f[15]
        );
        let bssid_mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            f[16], f[17], f[18], f[19], f[20], f[21]
        );

        let is_randomized_mac = (f[10] & 0x02) != 0;
        let mac_vendor = Self::lookup_oui(&src_mac);

        let seq_ctrl = u16::from_le_bytes([f[22], f[23]]);
        let sequence_number = seq_ctrl >> 4;

        let mut ie = ParsedInformationElements::default();

        if matches!(frame_control.frame_type, crate::types::FrameType::Management) {
            let frame_subtype_num = (f[0] & 0xF0) >> 4;
            let mut tag_offset = 24;
            
            match frame_subtype_num {
                8 | 5 => tag_offset = 36,
                0 | 2 => tag_offset = 28,
                4 => tag_offset = 24,
                _ => {}
            }

            let mut tag_sequence = Vec::new();

            while tag_offset + 2 <= f.len() {
                let tag_num = f[tag_offset];
                let tag_len = f[tag_offset + 1] as usize;
                let tag_end = tag_offset + 2 + tag_len;
                if tag_end > f.len() {
                    break;
                }

                tag_sequence.push(tag_num);
                let tag_data = &f[tag_offset + 2..tag_end];

                Self::parse_information_element(tag_num, tag_data, &mut ie);

                tag_offset = tag_end;
            }

            ie.tag_sequence = tag_sequence.clone();
            let mut hasher = DefaultHasher::new();
            tag_sequence.hash(&mut hasher);
            ie.tag_sequence_hash = format!("{:016x}", hasher.finish());
        }

        let channel = ie.channel_number.or(channel_calc);
        let ssid_clone = ie.ssid.clone();
        let snr = noise_dbm.map(|n| (rssi - n) as f32);
        let distance = Self::estimate_distance_from_rssi(rssi, freq_mhz.unwrap_or(2412));

        Some(DeviceObservation {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source_mac: src_mac,
            is_randomized_mac,
            mac_vendor,
            destination_mac: Some(dest_mac),
            bssid: Some(bssid_mac),
            ssid: ssid_clone,
            rssi,
            noise_dbm,
            snr_db: snr,
            channel,
            frequency_mhz: freq_mhz,
            frame_type: frame_control.frame_subtype,
            frame_control: Some(frame_control),
            medium: RadioMedium::Wifi,
            sequence_number: Some(sequence_number),
            retry_flag,
            power_mgmt_flag: pwr_mgmt_flag,
            more_data_flag,
            protected_flag,
            information_elements: ie,
            radiotap_header: Some(radiotap),
            sdr_burst_info: None,
            cellular_burst_info: None,
            raw_length: raw.len(),
            estimated_distance_meters: Some(distance),
        })
    }

    fn parse_information_element(tag_num: u8, tag_data: &[u8], ie: &mut ParsedInformationElements) {
        match tag_num {
            0 => {
                if let Ok(s) = std::str::from_utf8(tag_data) {
                    if !s.is_empty() {
                        ie.ssid = Some(s.to_string());
                    }
                }
            }
            1 => {
                for &rate_byte in tag_data {
                    let rate = (rate_byte & 0x7f) as f32 * 0.5;
                    ie.supported_rates.push(rate);
                }
            }
            3 => {
                if !tag_data.is_empty() {
                    ie.channel_number = Some(tag_data[0]);
                }
            }
            7 => {
                if tag_data.len() >= 3 {
                    let country_code = std::str::from_utf8(&tag_data[0..3])
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| "XX".to_string());
                    let mut triplets = Vec::new();
                    let mut pos = 3;
                    while pos + 3 <= tag_data.len() {
                        triplets.push(crate::types::ChannelTriplet {
                            first_channel: tag_data[pos],
                            num_channels: tag_data[pos + 1],
                            max_tx_power_dbm: tag_data[pos + 2],
                        });
                        pos += 3;
                    }
                    ie.country = Some(crate::types::CountryInfo {
                        country_code,
                        environment: crate::types::EnvironmentType::Any,
                        channel_triplets: triplets,
                    });
                }
            }
            20 => {
                if !tag_data.is_empty() {
                    ie.power_constraint = Some(tag_data[0]);
                }
            }
            32 => {
                if !tag_data.is_empty() {
                    ie.erp_info = Some(crate::types::ErpInfo {
                        non_erp_present: (tag_data[0] & 0x01) != 0,
                        use_protection: (tag_data[0] & 0x02) != 0,
                        Barker_preamble_mode: (tag_data[0] & 0x04) != 0,
                    });
                }
            }
            45 => {
                if tag_data.len() >= 26 {
                    let ht_caps_info = u16::from_le_bytes([tag_data[0], tag_data[1]]);
                    let a_mpdu_params = tag_data[2];
                    let mut supported_mcs = Vec::new();
                    for i in 3..16 {
                        supported_mcs.push(tag_data[i]);
                    }
                    let ht_ext_caps = u16::from_le_bytes([tag_data[16], tag_data[17]]);
                    let tx_bf_caps = u32::from_le_bytes([
                        tag_data[18], tag_data[19], tag_data[20], tag_data[21],
                    ]);
                    let asel_caps = tag_data[22];
                    
                    ie.ht_capabilities = Some(HtCapabilities {
                        ht_capabilities_info: ht_caps_info,
                        a_mpdu_parameters: a_mpdu_params,
                        supported_mcs_set: supported_mcs,
                        ht_extended_capabilities: ht_ext_caps,
                        tx_bf_capabilities: tx_bf_caps,
                        asel_capabilities: asel_caps,
                    });
                }
            }
            48 => {
                ie.rsn = Self::parse_rsn_element(tag_data);
            }
            50 => {
                for &rate_byte in tag_data {
                    let rate = (rate_byte & 0x7f) as f32 * 0.5;
                    ie.extended_supported_rates.push(rate);
                }
            }
            61 => {
                if tag_data.len() >= 5 {
                    ie.ht_operation = Some(HtOperation {
                        primary_channel: tag_data[0],
                        ht_operation_info: u16::from_le_bytes([tag_data[1], tag_data[2]]),
                        supported_mcs_set: tag_data[3..].to_vec(),
                    });
                }
            }
            191 => {
                if tag_data.len() >= 12 {
                    let vht_caps_info = u32::from_le_bytes([
                        tag_data[0], tag_data[1], tag_data[2], tag_data[3],
                    ]);
                    let mut vht_mcs = Vec::new();
                    for i in 4..8 {
                        vht_mcs.push(tag_data[i]);
                    }
                    let vht_tx_bf = u32::from_le_bytes([
                        tag_data[8], tag_data[9], tag_data[10], tag_data[11],
                    ]);
                    
                    ie.vht_capabilities = Some(VhtCapabilities {
                        vht_capabilities_info: vht_caps_info,
                        supported_vht_mcs_and_nss_set: vht_mcs,
                        vht_tx_bf_capabilities: vht_tx_bf,
                    });
                }
            }
            192 => {
                if tag_data.len() >= 5 {
                    ie.vht_operation = Some(VhtOperation {
                        channel_width: tag_data[0],
                        center_freq_segment_0: tag_data[1],
                        center_freq_segment_1: tag_data[2],
                        basic_vht_mcs_and_nss_set: tag_data[3..].to_vec(),
                    });
                }
            }
            255 => {
                if tag_data.len() >= 21 {
                    let he_caps_info = tag_data[0];
                    let he_mac_caps = tag_data[1];
                    let he_phy_caps = tag_data[2..6].to_vec();
                    let he_tx_bf_caps = tag_data[6..12].to_vec();
                    
                    ie.he_capabilities = Some(HeCapabilities {
                        he_capabilities_info: he_caps_info,
                        he_mac_capabilities: he_mac_caps,
                        he_phy_capabilities: he_phy_caps,
                        he_tx_bf_capabilities: he_tx_bf_caps,
                        su_beamformer_capable: (he_caps_info & 0x80) != 0,
                        su_beamformee_capable: (he_caps_info & 0x40) != 0,
                    });
                }
            }
            221 => {
                if tag_data.len() >= 3 {
                    let oui = format!(
                        "{:02x}:{:02x}:{:02x}",
                        tag_data[0], tag_data[1], tag_data[2]
                    );
                    
                    let parsed_type = match (tag_data.get(3).copied(), &oui[..]) {
                        (Some(0x04), "00:50:f2") => Some("WPS".to_string()),
                        (Some(0x01), "00:50:f2") => Some("WPA".to_string()),
                        (Some(0x02), "00:50:f2") => Some("WPA2".to_string()),
                        _ => None,
                    };

                    ie.vendor_specific.push(crate::types::VendorSpecificIe {
                        oui: oui.clone(),
                        oui_type: *tag_data.get(3).unwrap_or(&0),
                        data: tag_data[3..].to_vec(),
                        parsed_type,
                    });

                    if tag_data.len() >= 4 && tag_data[0..4] == [0x00, 0x50, 0xf2, 0x04] {
                        ie.wps = Self::parse_wps_element(&tag_data[4..]);
                    }
                }
            }
            127 => {
                ie.extended_capabilities = tag_data.to_vec();
            }
            54 => {
                if tag_data.len() >= 4 {
                    ie.mobility_domain = Some(crate::types::MobilityDomain {
                        mobility_domain_id: u16::from_le_bytes([tag_data[0], tag_data[1]]),
                        ft_capability: u16::from_le_bytes([tag_data[2], tag_data[3]]),
                    });
                }
            }
            113 => {
                if let Ok(s) = std::str::from_utf8(tag_data) {
                    ie.mesh_id = Some(s.to_string());
                }
            }
            147 => {
                if tag_data.len() >= 7 {
                    ie.mesh_configuration = Some(crate::types::MeshConfiguration {
                        active_path_selection_protocol_id: tag_data[0],
                        active_path_selection_metric_id: tag_data[1],
                        mesh_capability: tag_data[2],
                        mesh_peer_concurrency: u16::from_le_bytes([tag_data[3], tag_data[4]]),
                    });
                }
            }
            _ => {}
        }
    }

    fn parse_rsn_element(data: &[u8]) -> Option<RsnInfo> {
        if data.len() < 8 {
            return None;
        }

        let version = u16::from_le_bytes([data[0], data[1]]);
        
        let group_oui = format!("{:02x}:{:02x}:{:02x}", data[2], data[3], data[4]);
        let group_suite_type = data[5];
        let group_cipher = CipherSuite {
            oui: group_oui,
            suite_type: group_suite_type,
            name: Self::cipher_suite_name(&group_oui, group_suite_type),
        };

        let mut pos = 6;
        let mut pairwise_ciphers = Vec::new();
        
        if pos + 2 <= data.len() {
            let pairwise_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            for _ in 0..pairwise_count {
                if pos + 4 <= data.len() {
                    let oui = format!("{:02x}:{:02x}:{:02x}", data[pos], data[pos + 1], data[pos + 2]);
                    let suite_type = data[pos + 3];
                    pairwise_ciphers.push(CipherSuite {
                        oui: oui.clone(),
                        suite_type,
                        name: Self::cipher_suite_name(&oui, suite_type),
                    });
                    pos += 4;
                }
            }
        }

        let mut akm_suites = Vec::new();
        if pos + 2 <= data.len() {
            let akm_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            for _ in 0..akm_count {
                if pos + 4 <= data.len() {
                    let oui = format!("{:02x}:{:02x}:{:02x}", data[pos], data[pos + 1], data[pos + 2]);
                    let suite_type = data[pos + 3];
                    akm_suites.push(AkmSuite {
                        oui: oui.clone(),
                        suite_type,
                        name: Self::akm_suite_name(&oui, suite_type),
                    });
                    pos += 4;
                }
            }
        }

        let mut rsn_capabilities = None;
        if pos + 2 <= data.len() {
            let caps = u16::from_le_bytes([data[pos], data[pos + 1]]);
            rsn_capabilities = Some(RsnCapabilities {
                preauth: (caps & 0x0001) != 0,
                no_pairwise: (caps & 0x0002) != 0,
                ptk_sa_replay_counter: ((caps >> 2) & 0x0F) as u8,
                gtk_sa_replay_counter: ((caps >> 6) & 0x0F) as u8,
                mfp_required: (caps & 0x0040) != 0,
                mfp_capable: (caps & 0x0080) != 0,
                joint_management: (caps & 0x0100) != 0,
                peerkey_enabled: (caps & 0x0200) != 0,
                spp_a_capable: (caps & 0x0400) != 0,
                ssp_a_mandatory: (caps & 0x0800) != 0,
            });
            pos += 2;
        }

        let mut pmkid_list = Vec::new();
        if pos + 2 <= data.len() {
            let pmkid_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            for _ in 0..pmkid_count {
                if pos + 16 <= data.len() {
                    let pmkid = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        data[pos], data[pos+1], data[pos+2], data[pos+3],
                        data[pos+4], data[pos+5], data[pos+6], data[pos+7],
                        data[pos+8], data[pos+9], data[pos+10], data[pos+11],
                        data[pos+12], data[pos+13], data[pos+14], data[pos+15]);
                    pmkid_list.push(pmkid);
                    pos += 16;
                }
            }
        }

        Some(RsnInfo {
            version,
            group_cipher,
            pairwise_ciphers,
            akm_suites,
            rsn_capabilities,
            pmkid_list,
            group_management_cipher: None,
        })
    }

    fn cipher_suite_name(oui: &str, suite_type: u8) -> String {
        match (oui, suite_type) {
            ("00:0f:ac", 0) => "Use group cipher".to_string(),
            ("00:0f:ac", 1) => "WEP-40".to_string(),
            ("00:0f:ac", 2) => "TKIP".to_string(),
            ("00:0f:ac", 3) => "RESERVED".to_string(),
            ("00:0f:ac", 4) => "CCMP".to_string(),
            ("00:0f:ac", 5) => "WEP-104".to_string(),
            ("00:0f:ac", 6) => "BIP-CMAC-128".to_string(),
            ("00:0f:ac", 7) => "GCMP".to_string(),
            ("00:0f:ac", 8) => "GCMP-256".to_string(),
            ("00:0f:ac", 9) => "CCMP-256".to_string(),
            ("00:0f:ac", 10) => "BIP-GMAC-128".to_string(),
            ("00:0f:ac", 11) => "BIP-GMAC-256".to_string(),
            ("00:0f:ac", 12) => "BIP-CMAC-256".to_string(),
            _ => format!("Unknown ({}, {})", oui, suite_type),
        }
    }

    fn akm_suite_name(oui: &str, suite_type: u8) -> String {
        match (oui, suite_type) {
            ("00:0f:ac", 1) => "802.1X".to_string(),
            ("00:0f:ac", 2) => "PSK".to_string(),
            ("00:0f:ac", 3) => "FT-802.1X".to_string(),
            ("00:0f:ac", 4) => "FT-PSK".to_string(),
            ("00:0f:ac", 5) => "WPA-SHA256".to_string(),
            ("00:0f:ac", 6) => "WPA-PSK-SHA256".to_string(),
            ("00:0f:ac", 7) => "TDLS".to_string(),
            ("00:0f:ac", 8) => "SAE".to_string(),
            ("00:0f:ac", 9) => "FT-SAE".to_string(),
            ("00:0f:ac", 11) => "AP-PEER-KEY".to_string(),
            ("00:0f:ac", 12) => "WPA-SHA384".to_string(),
            ("00:0f:ac", 13) => "FT-SHA384".to_string(),
            ("00:0f:ac", 14) => "OWE".to_string(),
            _ => format!("Unknown ({}, {})", oui, suite_type),
        }
    }

    fn parse_wps_element(data: &[u8]) -> Option<WpsInfo> {
        let mut wps = WpsInfo::default();
        let mut pos = 0;

        while pos + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + attr_len > data.len() {
                break;
            }

            let attr_data = &data[pos..pos + attr_len];
            match attr_type {
                0x1042 => {
                    // Version
                    if !attr_data.is_empty() {
                        wps.version = attr_data[0];
                    }
                }
                0x1044 => {
                    // WPS State
                    if !attr_data.is_empty() {
                        wps.wps_state = if attr_data[0] == 0x01 {
                            crate::types::WpsState::NotConfigured
                        } else {
                            crate::types::WpsState::Configured
                        };
                    }
                }
                0x1054 => {
                    // AP Setup Locked
                    if !attr_data.is_empty() {
                        wps.ap_setup_locked = attr_data[0] != 0;
                    }
                }
                0x1057 => {
                    // Selected Registrar
                    if !attr_data.is_empty() {
                        wps.selected_registrar = attr_data[0] != 0;
                    }
                }
                0x1011 => {
                    // Device Name
                    if let Ok(s) = std::str::from_utf8(attr_data) {
                        wps.device_name = Some(s.to_string());
                    }
                }
                0x1021 => {
                    // Manufacturer
                    if let Ok(s) = std::str::from_utf8(attr_data) {
                        wps.manufacturer = Some(s.to_string());
                    }
                }
                0x1023 => {
                    // Model Name
                    if let Ok(s) = std::str::from_utf8(attr_data) {
                        wps.model_name = Some(s.to_string());
                    }
                }
                0x1024 => {
                    // Model Number
                    if let Ok(s) = std::str::from_utf8(attr_data) {
                        wps.model_number = Some(s.to_string());
                    }
                }
                0x1045 => {
                    // Serial Number
                    if let Ok(s) = std::str::from_utf8(attr_data) {
                        wps.serial_number = Some(s.to_string());
                    }
                }
                0x1044 => {
                    // UUID-E
                    if attr_data.len() == 16 {
                        wps.uuid_e = Some(format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                            attr_data[0], attr_data[1], attr_data[2], attr_data[3],
                            attr_data[4], attr_data[5], attr_data[6], attr_data[7],
                            attr_data[8], attr_data[9], attr_data[10], attr_data[11],
                            attr_data[12], attr_data[13], attr_data[14], attr_data[15]));
                    }
                }
                0x1054 => {
                    // Primary Device Type
                    if attr_data.len() >= 8 {
                        wps.primary_device_type = Some(crate::types::DeviceType {
                            category: u16::from_be_bytes([attr_data[0], attr_data[1]]),
                            oui: format!("{:02x}:{:02x}:{:02x}", attr_data[2], attr_data[3], attr_data[4]),
                            sub_category: u16::from_be_bytes([attr_data[6], attr_data[7]]),
                        });
                    }
                }
                0x105C => {
                    // RF Bands
                    if !attr_data.is_empty() {
                        wps.rf_bands = Some(crate::types::RfBands {
                            _24ghz: (attr_data[0] & 0x01) != 0,
                            _50ghz: (attr_data[0] & 0x02) != 0,
                            _60ghz: (attr_data[0] & 0x04) != 0,
                        });
                    }
                }
                0x1062 => {
                    // OS Version
                    if attr_data.len() >= 4 {
                        wps.os_version = Some(u32::from_be_bytes([
                            attr_data[0], attr_data[1], attr_data[2], attr_data[3],
                        ]));
                    }
                }
                0x105B => {
                    // Config Methods
                    if attr_data.len() >= 2 {
                        wps.config_methods = u16::from_be_bytes([attr_data[0], attr_data[1]]);
                    }
                }
                _ => {}
            }
            pos += attr_len;
        }

        Some(wps)
    }

    pub fn lookup_oui(mac: &str) -> Option<String> {
        let clean = mac.replace([':', '-'], "").to_lowercase();
        if clean.len() < 6 {
            return None;
        }
        let prefix = &clean[0..6];

        match prefix {
            "f8ffc2" | "bcfe43" | "f01898" | "a483e7" | "3c2eef" | "286ac4" | "acde48" => {
                Some("Apple, Inc.".to_string())
            }
            "b42e99" | "50c8e5" | "dc7144" | "380195" | "00166c" | "a00bba" => {
                Some("Samsung Electronics".to_string())
            }
            "7085c2" | "0013e8" | "001b21" | "0024d7" | "84a93e" => {
                Some("Intel Corporate".to_string())
            }
            "3c71bf" | "246f28" | "30aea4" | "84f3eb" | "ec94cb" => {
                Some("Espressif Systems".to_string())
            }
            "b827eb" | "dca632" | "e45f01" => Some("Raspberry Pi Foundation".to_string()),
            "001a11" | "00259c" | "0026b9" | "687f74" => Some("Cisco Systems".to_string()),
            "000c29" | "005056" => Some("VMware, Inc.".to_string()),
            "080027" => Some("Oracle VirtualBox".to_string()),
            "00155d" => Some("Microsoft Hyper-V".to_string()),
            _ => None,
        }
    }

    fn frequency_to_channel(freq: u16) -> Option<u8> {
        match freq {
            2412 => Some(1),
            2417 => Some(2),
            2422 => Some(3),
            2427 => Some(4),
            2432 => Some(5),
            2437 => Some(6),
            2442 => Some(7),
            2447 => Some(8),
            2452 => Some(9),
            2457 => Some(10),
            2462 => Some(11),
            2467 => Some(12),
            2472 => Some(13),
            2484 => Some(14),
            5180 => Some(36),
            5200 => Some(40),
            5220 => Some(44),
            5240 => Some(48),
            5260 => Some(52),
            5280 => Some(56),
            5300 => Some(60),
            5320 => Some(64),
            5500 => Some(100),
            5520 => Some(104),
            5540 => Some(108),
            5560 => Some(112),
            5580 => Some(116),
            5600 => Some(120),
            5660 => Some(132),
            5700 => Some(140),
            5745 => Some(149),
            5765 => Some(153),
            5785 => Some(157),
            5805 => Some(161),
            5825 => Some(165),
            _ => None,
        }
    }
}
