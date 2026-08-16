use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

// ============================================================================
// CLI Configuration
// ============================================================================

#[derive(Parser, Debug, Clone)]
#[command(
    name = "minuteman",
    version = "0.2.0",
    about = "Wireless Presence & Geolocation-to-IP Correlation Laboratory Engine"
)]
pub struct CliArgs {
    #[arg(long, value_enum, default_value_t = RadioMedium::Wifi)]
    pub mode: RadioMedium,

    #[arg(long, value_enum, default_value_t = TargetResolution::Public)]
    pub target: TargetResolution,

    #[arg(long, default_value = "wlan0")]
    pub interface: String,

    #[arg(long, default_value = "info")]
    pub log_level: String,

    #[arg(long, default_value_t = false)]
    pub stealth: bool,

    #[arg(long, default_value = "session.db")]
    pub db_path: String,

    #[arg(long, default_value = "0.0.0.0:8080")]
    pub telemetry_bind: String,

    #[arg(long, default_value = "/var/lib/misc/dnsmasq.leases")]
    pub leases_path: String,

    #[arg(long)]
    pub pcap_file: Option<String>,

    #[arg(long)]
    pub sdr_source: Option<String>,

    #[arg(long, default_value_t = true)]
    pub channel_hop: bool,

    #[arg(long, default_value_t = true)]
    pub interactive: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RadioMedium {
    Wifi,
    Cellular,
    Bluetooth,
    RawSdr,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetResolution {
    Local,
    Public,
    MultiHop,
}

// ============================================================================
// IEEE 802.11 Radiotap & Frame Models
// ============================================================================

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RadiotapHeader {
    pub tsft: Option<u64>,
    pub flags: Option<RadiotapFlags>,
    pub rate: Option<u8>,
    pub channel: Option<RadiotapChannel>,
    pub fhss: Option<RadiotapFhss>,
    pub dbm_antenna_signal: Option<i8>,
    pub dbm_antenna_noise: Option<i8>,
    pub lock_quality: Option<u16>,
    pub tx_attenuation: Option<u16>,
    pub db_tx_attenuation: Option<u16>,
    pub dbm_tx_power: Option<i8>,
    pub antenna: Option<u8>,
    pub db_antenna_signal: Option<u8>,
    pub db_antenna_noise: Option<u8>,
    pub rx_flags: Option<RadiotapRxFlags>,
    pub tx_flags: Option<RadiotapTxFlags>,
    pub mcs: Option<RadiotapMcs>,
    pub ampdu_status: Option<RadiotapAmpduStatus>,
    pub vht: Option<RadiotapVht>,
    pub timestamp: Option<u64>,
    pub he: Option<RadiotapHe>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapFlags {
    pub cfp: bool,
    pub short_preamble: bool,
    pub wep: bool,
    pub fragment: bool,
    pub fcs: bool,
    pub data_pad: bool,
    pub bad_fcs: bool,
    pub short_gi: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapChannel {
    pub frequency_mhz: u16,
    pub flags: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapFhss {
    pub hop_set: u16,
    pub hop_pattern: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapRxFlags {
    pub bad_plcp: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapTxFlags {
    pub fail: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapMcs {
    pub known: u8,
    pub flags: u8,
    pub mcs_rate: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapAmpduStatus {
    pub reference: u32,
    pub flags: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapVht {
    pub known: u16,
    pub flags: u16,
    pub bandwidth: u8,
    pub mcs_nss: [u8; 4],
    pub coding: u8,
    pub group_id: u8,
    pub partial_aid: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadiotapHe {
    pub data1: u16,
    pub data2: u16,
    pub data3: u16,
    pub data4: u16,
    pub data5: u16,
    pub data6: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameControl {
    pub protocol_version: u8,
    pub frame_type: FrameType,
    pub frame_subtype: FrameSubtype,
    pub to_ds: bool,
    pub from_ds: bool,
    pub more_fragments: bool,
    pub retry: bool,
    pub power_mgmt: bool,
    pub more_data: bool,
    pub protected: bool,
    pub order: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Extension,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameSubtype {
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    ActionNoAck,
    UnknownManagement(u8),
    BlockAckReq,
    BlockAck,
    PsPoll,
    Rts,
    Cts,
    Ack,
    CfEnd,
    CfEndCfAck,
    UnknownControl(u8),
    Data,
    DataCfAck,
    DataCfPoll,
    DataCfAckCfPoll,
    Null,
    CfAck,
    CfPoll,
    CfAckCfPoll,
    QosData,
    QosDataCfAck,
    QosDataCfPoll,
    QosDataCfAckCfPoll,
    QosNull,
    QosCfPoll,
    QosCfAck,
    UnknownData(u8),
    UnknownExtension(u8),
}

impl From<(u8, u8)> for FrameControl {
    fn from((fc_low, fc_high): (u8, u8)) -> Self {
        let protocol_version = (fc_low & 0x03) >> 0;
        let frame_type_num = (fc_low & 0x0C) >> 2;
        let frame_subtype_num = (fc_low & 0xF0) >> 4;
        
        let frame_type = match frame_type_num {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            3 => FrameType::Extension,
            _ => FrameType::Management,
        };
        
        let frame_subtype = match (frame_type, frame_subtype_num) {
            (FrameType::Management, 0) => FrameSubtype::AssociationRequest,
            (FrameType::Management, 1) => FrameSubtype::AssociationResponse,
            (FrameType::Management, 2) => FrameSubtype::ReassociationRequest,
            (FrameType::Management, 3) => FrameSubtype::ReassociationResponse,
            (FrameType::Management, 4) => FrameSubtype::ProbeRequest,
            (FrameType::Management, 5) => FrameSubtype::ProbeResponse,
            (FrameType::Management, 6) => FrameSubtype::Beacon,
            (FrameType::Management, 7) => FrameSubtype::Atim,
            (FrameType::Management, 8) => FrameSubtype::Disassociation,
            (FrameType::Management, 9) => FrameSubtype::Authentication,
            (FrameType::Management, 10) => FrameSubtype::Deauthentication,
            (FrameType::Management, 11) => FrameSubtype::Action,
            (FrameType::Management, 12) => FrameSubtype::ActionNoAck,
            (FrameType::Management, n) => FrameSubtype::UnknownManagement(n),
            (FrameType::Control, 8) => FrameSubtype::BlockAckReq,
            (FrameType::Control, 9) => FrameSubtype::BlockAck,
            (FrameType::Control, 10) => FrameSubtype::PsPoll,
            (FrameType::Control, 11) => FrameSubtype::Rts,
            (FrameType::Control, 12) => FrameSubtype::Cts,
            (FrameType::Control, 13) => FrameSubtype::Ack,
            (FrameType::Control, 14) => FrameSubtype::CfEnd,
            (FrameType::Control, 15) => FrameSubtype::CfEndCfAck,
            (FrameType::Control, n) => FrameSubtype::UnknownControl(n),
            (FrameType::Data, 0) => FrameSubtype::Data,
            (FrameType::Data, 1) => FrameSubtype::DataCfAck,
            (FrameType::Data, 2) => FrameSubtype::DataCfPoll,
            (FrameType::Data, 3) => FrameSubtype::DataCfAckCfPoll,
            (FrameType::Data, 4) => FrameSubtype::Null,
            (FrameType::Data, 5) => FrameSubtype::CfAck,
            (FrameType::Data, 6) => FrameSubtype::CfPoll,
            (FrameType::Data, 7) => FrameSubtype::CfAckCfPoll,
            (FrameType::Data, 8) => FrameSubtype::QosData,
            (FrameType::Data, 9) => FrameSubtype::QosDataCfAck,
            (FrameType::Data, 10) => FrameSubtype::QosDataCfPoll,
            (FrameType::Data, 11) => FrameSubtype::QosDataCfAckCfPoll,
            (FrameType::Data, 12) => FrameSubtype::QosNull,
            (FrameType::Data, 14) => FrameSubtype::QosCfPoll,
            (FrameType::Data, 15) => FrameSubtype::QosCfAck,
            (FrameType::Data, n) => FrameSubtype::UnknownData(n),
            (FrameType::Extension, n) => FrameSubtype::UnknownExtension(n),
            _ => FrameSubtype::UnknownManagement(frame_subtype_num),
        };
        
        Self {
            protocol_version,
            frame_type,
            frame_subtype,
            to_ds: (fc_high & 0x01) != 0,
            from_ds: (fc_high & 0x02) != 0,
            more_fragments: (fc_high & 0x04) != 0,
            retry: (fc_high & 0x08) != 0,
            power_mgmt: (fc_high & 0x10) != 0,
            more_data: (fc_high & 0x20) != 0,
            protected: (fc_high & 0x40) != 0,
            order: (fc_high & 0x80) != 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityInformation {
    pub ess: bool,
    pub ibss: bool,
    pub cf_pollable: bool,
    pub cf_poll_req: bool,
    pub privacy: bool,
    pub short_preamble: bool,
    pub pbcc: bool,
    pub channel_agility: bool,
    pub spectrum_mgmt: bool,
    pub qos: bool,
    pub short_slot_time: bool,
    pub apsd: bool,
    pub radio_measurement: bool,
    pub dsss_ofdm: bool,
    pub delayed_block_ack: bool,
    pub immediate_block_ack: bool,
}

impl From<u16> for CapabilityInformation {
    fn from(cap: u16) -> Self {
        Self {
            ess: (cap & 0x0001) != 0,
            ibss: (cap & 0x0002) != 0,
            cf_pollable: (cap & 0x0004) != 0,
            cf_poll_req: (cap & 0x0008) != 0,
            privacy: (cap & 0x0010) != 0,
            short_preamble: (cap & 0x0020) != 0,
            pbcc: (cap & 0x0040) != 0,
            channel_agility: (cap & 0x0080) != 0,
            spectrum_mgmt: (cap & 0x0100) != 0,
            qos: (cap & 0x0200) != 0,
            short_slot_time: (cap & 0x0400) != 0,
            apsd: (cap & 0x0800) != 0,
            radio_measurement: (cap & 0x1000) != 0,
            dsss_ofdm: (cap & 0x2000) != 0,
            delayed_block_ack: (cap & 0x4000) != 0,
            immediate_block_ack: (cap & 0x8000) != 0,
        }
    }
}

// ============================================================================
// IEEE 802.11 Information Elements (IE)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ParsedInformationElements {
    pub ssid: Option<String>,
    pub supported_rates: Vec<f32>,
    pub extended_supported_rates: Vec<f32>,
    pub channel_number: Option<u8>,
    pub country: Option<CountryInfo>,
    pub power_constraint: Option<u8>,
    pub tpc_report: Option<TpcReport>,
    pub erp_info: Option<ErpInfo>,
    pub rsn: Option<RsnInfo>,
    pub wps: Option<WpsInfo>,
    pub ht_capabilities: Option<HtCapabilities>,
    pub ht_operation: Option<HtOperation>,
    pub vht_capabilities: Option<VhtCapabilities>,
    pub vht_operation: Option<VhtOperation>,
    pub he_capabilities: Option<HeCapabilities>,
    pub he_operation: Option<HeOperation>,
    pub vendor_specific: Vec<VendorSpecificIe>,
    pub extended_capabilities: Vec<u8>,
    pub mobility_domain: Option<MobilityDomain>,
    pub mesh_id: Option<String>,
    pub mesh_configuration: Option<MeshConfiguration>,
    pub tag_sequence: Vec<u8>,
    pub tag_sequence_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CountryInfo {
    pub country_code: String,
    pub environment: EnvironmentType,
    pub channel_triplets: Vec<ChannelTriplet>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EnvironmentType {
    Indoor,
    Outdoor,
    Any,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelTriplet {
    pub first_channel: u8,
    pub num_channels: u8,
    pub max_tx_power_dbm: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TpcReport {
    pub transmit_power: u8,
    pub link_margin: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErpInfo {
    pub non_erp_present: bool,
    pub use_protection: bool,
    pub Barker_preamble_mode: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RsnInfo {
    pub version: u16,
    pub group_cipher: CipherSuite,
    pub pairwise_ciphers: Vec<CipherSuite>,
    pub akm_suites: Vec<AkmSuite>,
    pub rsn_capabilities: Option<RsnCapabilities>,
    pub pmkid_list: Vec<String>,
    pub group_management_cipher: Option<CipherSuite>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CipherSuite {
    pub oui: String,
    pub suite_type: u8,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AkmSuite {
    pub oui: String,
    pub suite_type: u8,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RsnCapabilities {
    pub preauth: bool,
    pub no_pairwise: bool,
    pub ptk_sa_replay_counter: u8,
    pub gtk_sa_replay_counter: u8,
    pub mfp_required: bool,
    pub mfp_capable: bool,
    pub joint_management: bool,
    pub peerkey_enabled: bool,
    pub spp_a_capable: bool,
    pub ssp_a_mandatory: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WpsInfo {
    pub version: u8,
    pub wps_state: WpsState,
    pub ap_setup_locked: bool,
    pub selected_registrar: bool,
    pub device_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub serial_number: Option<String>,
    pub uuid_e: Option<String>,
    pub primary_device_type: Option<DeviceType>,
    pub rf_bands: Option<RfBands>,
    pub os_version: Option<u32>,
    pub config_methods: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WpsState {
    NotConfigured,
    Configured,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceType {
    pub category: u16,
    pub oui: String,
    pub sub_category: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RfBands {
    pub _24ghz: bool,
    pub _50ghz: bool,
    pub _60ghz: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HtCapabilities {
    pub ht_capabilities_info: u16,
    pub a_mpdu_parameters: u8,
    pub supported_mcs_set: Vec<u8>,
    pub ht_extended_capabilities: u16,
    pub tx_bf_capabilities: u32,
    pub asel_capabilities: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HtOperation {
    pub primary_channel: u8,
    pub ht_operation_info: u16,
    pub supported_mcs_set: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VhtCapabilities {
    pub vht_capabilities_info: u32,
    pub supported_vht_mcs_and_nss_set: Vec<u8>,
    pub vht_tx_bf_capabilities: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VhtOperation {
    pub channel_width: u8,
    pub center_freq_segment_0: u8,
    pub center_freq_segment_1: u8,
    pub basic_vht_mcs_and_nss_set: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeCapabilities {
    pub he_capabilities_info: u8,
    pub he_mac_capabilities: u8,
    pub he_phy_capabilities: Vec<u8>,
    pub he_tx_bf_capabilities: Vec<u8>,
    pub su_beamformer_capable: bool,
    pub su_beamformee_capable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeOperation {
    pub he_operation_parameters: u32,
    pub he_default_pe_duration: u8,
    pub he_twt_required: bool,
    pub he_twt_responder: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VendorSpecificIe {
    pub oui: String,
    pub oui_type: u8,
    pub data: Vec<u8>,
    pub parsed_type: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MobilityDomain {
    pub mobility_domain_id: u16,
    pub ft_capability: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshConfiguration {
    pub active_path_selection_protocol_id: u8,
    pub active_path_selection_metric_id: u8,
    pub mesh_capability: u8,
    pub mesh_peer_concurrency: u8,
}

// ============================================================================
// SDR / Baseband DSP Models
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IqSample {
    pub i: f32,
    pub q: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdrBurstProperties {
    pub center_frequency_mhz: f64,
    pub sample_rate_sps: u32,
    pub bandwidth_khz: f64,
    pub burst_duration_us: u64,
    pub peak_power_dbm: f64,
    pub average_power_dbm: f64,
    pub snr_db: f64,
    pub noise_floor_dbm: f64,
    pub peak_frequency_offset_hz: f64,
    pub modulation_type: ModulationType,
    pub estimated_standard: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ModulationType {
    Unknown,
    Fsk,
    Gmsk,
    Qpsk,
    Qam16,
    Qam64,
    Qam256,
    Ofdm,
    Lte,
    Nr5g,
    Gsm,
    Cdma,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowerSpectrum {
    pub frequency_bins: Vec<f64>,
    pub power_db: Vec<f32>,
    pub peak_index: usize,
    pub peak_frequency_hz: f64,
    pub peak_power_db: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellularBurstInfo {
    pub band: String,
    pub channel_number: u32,
    pub uplink_mhz: f64,
    pub downlink_mhz: f64,
    pub duplex_mode: DuplexMode,
    pub frame_number: u32,
    pub subframe_number: u8,
    pub slot_number: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DuplexMode {
    Fdd,
    Tdd,
}

// ============================================================================
// Network / DHCP Models
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkLease {
    pub timestamp: DateTime<Utc>,
    pub mac_address: String,
    pub ip_address: IpAddr,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
    pub vendor_class: Option<String>,
    pub dhcp_fingerprint_opt55: Option<String>,
    pub parameter_request_list: Vec<u8>,
    pub lease_duration_secs: Option<u32>,
    pub source_type: LeaseSourceType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LeaseSourceType {
    Dnsmasq,
    IscDhcpd,
    Kea,
    SystemdNetworkd,
    DhcpSniffer,
    ArpTable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhcpOption {
    pub code: u8,
    pub length: Option<u8>,
    pub data: Vec<u8>,
    pub parsed_value: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip_address: IpAddr,
    pub mac_address: String,
    pub interface: Option<String>,
    pub device_type: Option<String>,
    pub last_seen: DateTime<Utc>,
}

// ============================================================================
// IEEE OUI Manufacturer Database
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OuiEntry {
    pub prefix: String,
    pub manufacturer: String,
    pub country: Option<String>,
}

// ============================================================================
// Layer 7 Telemetry & Fingerprint Models
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ClientHardwareFingerprint {
    pub canvas_hash: Option<String>,
    pub webgl_renderer: Option<String>,
    pub webgl_vendor: Option<String>,
    pub screen_resolution: Option<String>,
    pub screen_available_resolution: Option<String>,
    pub color_depth: Option<u8>,
    pub pixel_ratio: Option<f32>,
    pub timezone: Option<String>,
    pub timezone_offset_minutes: Option<i32>,
    pub hardware_concurrency: Option<u8>,
    pub device_memory_gb: Option<f32>,
    pub platform: Option<String>,
    pub languages: Vec<String>,
    pub touch_support: Option<bool>,
    pub max_touch_points: Option<u8>,
    pub audio_fingerprint: Option<String>,
    pub webrtc_candidate_ip: Option<String>,
    pub webrtc_local_ip: Option<String>,
    pub battery_level: Option<f32>,
    pub connection_type: Option<String>,
    pub effective_connection_type: Option<String>,
    pub do_not_track: Option<bool>,
    pub cookies_enabled: Option<bool>,
    pub plugins: Vec<String>,
    pub fonts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryHit {
    pub token: String,
    pub timestamp: DateTime<Utc>,
    pub remote_ip: IpAddr,
    pub forwarded_for_chain: Vec<IpAddr>,
    pub user_agent: Option<String>,
    pub sec_ch_ua: Option<String>,
    pub sec_ch_ua_platform: Option<String>,
    pub sec_ch_ua_arch: Option<String>,
    pub sec_ch_ua_model: Option<String>,
    pub sec_ch_ua_mobile: Option<bool>,
    pub referer: Option<String>,
    pub query_params: Option<String>,
    pub path: String,
    pub method: String,
    pub client_fingerprint: Option<ClientHardwareFingerprint>,
    pub geolocation: Option<GeoLocationEstimate>,
    pub reverse_dns: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GeoLocationEstimate {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_radius_km: f64,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub postal_code: Option<String>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub organization: Option<String>,
    pub asn: Option<String>,
    pub asn_number: Option<u32>,
    pub connection_type: Option<String>,
    pub is_mobile: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_tor: Option<bool>,
    pub is_vpn: Option<bool>,
}

// ============================================================================
// Correlation Models
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorrelatedTarget {
    pub target_id: String,
    pub mac_address: String,
    pub is_randomized_mac: bool,
    pub mac_vendor: Option<String>,
    pub local_ip: Option<IpAddr>,
    pub public_ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub dhcp_vendor_class: Option<String>,
    pub dhcp_fingerprint: Option<String>,
    pub last_rssi: i16,
    pub min_rssi: i16,
    pub max_rssi: i16,
    pub avg_rssi: f32,
    pub estimated_distance_meters: f32,
    pub distance_confidence: f32,
    pub last_ssid: Option<String>,
    pub probed_ssids: HashSet<String>,
    pub associated_bssid: Option<String>,
    pub ie_tag_hash: Option<String>,
    pub ie_tag_sequence: Vec<u8>,
    pub wps_device_name: Option<String>,
    pub wps_manufacturer: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub observation_count: u64,
    pub user_agent: Option<String>,
    pub client_fingerprint: Option<ClientHardwareFingerprint>,
    pub geolocation: Option<GeoLocationEstimate>,
    pub correlation_score: f32,
    pub confidence_level: ConfidenceLevel,
    pub cluster_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Verified,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RssiDistanceEstimate {
    pub distance_meters: f32,
    pub confidence: f32,
    pub path_loss_exponent: f32,
    pub tx_power_1m: f32,
    pub signal_quality_percent: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomizedMacCluster {
    pub cluster_id: String,
    pub mac_addresses: Vec<String>,
    pub ie_signature: Vec<u8>,
    pub supported_rates: Vec<f32>,
    pub ht_capabilities: Option<HtCapabilities>,
    pub vht_capabilities: Option<VhtCapabilities>,
    pub vendor_oui: Option<String>,
    pub wps_device_name: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub observation_count: u64,
}

// ============================================================================
// Device Observation Model
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceObservation {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source_mac: String,
    pub is_randomized_mac: bool,
    pub mac_vendor: Option<String>,
    pub destination_mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub rssi: i16,
    pub noise_dbm: Option<i16>,
    pub snr_db: Option<f32>,
    pub channel: Option<u8>,
    pub frequency_mhz: Option<u16>,
    pub frame_type: FrameSubtype,
    pub frame_control: Option<FrameControl>,
    pub medium: RadioMedium,
    pub sequence_number: Option<u16>,
    pub retry_flag: bool,
    pub power_mgmt_flag: bool,
    pub more_data_flag: bool,
    pub protected_flag: bool,
    pub information_elements: ParsedInformationElements,
    pub radiotap: Option<RadiotapHeader>,
    pub sdr_burst: Option<SdrBurstProperties>,
    pub cellular_info: Option<CellularBurstInfo>,
    pub raw_length: usize,
    pub estimated_distance: Option<RssiDistanceEstimate>,
}

// ============================================================================
// Channel Occupancy & Statistics
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelOccupancy {
    pub channel: u8,
    pub band: String,
    pub frequency_mhz: u16,
    pub frame_count: u64,
    pub beacon_count: u64,
    pub probe_count: u64,
    pub data_count: u64,
    pub max_rssi: i16,
    pub min_rssi: i16,
    pub avg_rssi: f32,
    pub unique_macs: usize,
    pub active_ssids: Vec<String>,
    pub utilization_percent: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SystemStatistics {
    pub total_frames: u64,
    pub wifi_probes: u64,
    pub wifi_beacons: u64,
    pub wifi_associations: u64,
    pub wifi_data_frames: u64,
    pub cellular_bursts: u64,
    pub sdr_energy_bursts: u64,
    pub unique_macs: u64,
    pub randomized_macs: u64,
    pub active_leases: u64,
    pub telemetry_hits: u64,
    pub correlated_identities: u64,
    pub mac_clusters: u64,
    pub channel_hop_count: u64,
    pub start_time: Option<DateTime<Utc>>,
    pub uptime_seconds: u64,
    pub frames_per_second: f32,
    pub bytes_processed: u64,
}

// ============================================================================
// Export Formats
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoJsonFeature {
    pub r#type: String,
    pub geometry: GeoJsonGeometry,
    pub properties: CorrelatedTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoJsonGeometry {
    pub r#type: String,
    pub coordinates: Vec<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoJsonCollection {
    pub r#type: String,
    pub features: Vec<GeoJsonFeature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KmlPlacemark {
    pub name: String,
    pub description: String,
    pub point: KmlPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KmlPoint {
    pub coordinates: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KmlDocument {
    pub placemarks: Vec<KmlPlacemark>,
}
