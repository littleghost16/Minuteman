use crate::logger::Database;
use crate::types::{
    ClientHardwareFingerprint, GeoLocationEstimate, TelemetryHit,
};
use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

const PIXEL_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

const PIXEL_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x60, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc, 0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

const JAVASCRIPT_BEACON: &str = r#"
(function() {
    try {
        function getCanvasHash() {
            var canvas = document.createElement('canvas');
            var ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('Minuteman Lab RF-IP Beacon', 2, 2);
            return canvas.toDataURL().slice(-32);
        }

        function getWebGLInfo() {
            var canvas = document.createElement('canvas');
            var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return { vendor: 'None', renderer: 'None' };
            var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            return {
                vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'Unknown',
                renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'Unknown'
            };
        }

        var webgl = getWebGLInfo();
        var payload = {
            token: new URLSearchParams(window.location.search).get('token') || 'js-agent',
            canvas_hash: getCanvasHash(),
            webgl_vendor: webgl.vendor,
            webgl_renderer: webgl.renderer,
            screen_resolution: window.screen.width + 'x' + window.screen.height,
            color_depth: window.screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezone_offset_minutes: new Date().getTimezoneOffset(),
            hardware_concurrency: navigator.hardwareConcurrency || 4,
            device_memory_gb: navigator.deviceMemory || 8,
            platform: navigator.platform || 'Unknown',
            languages: navigator.languages ? Array.from(navigator.languages) : [navigator.language || 'en-US'],
            touch_support: ('ontouchstart' in window) || (navigator.maxTouchPoints > 0)
        };

        fetch('/collect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }).catch(function(){});
    } catch(e) {}
})();
"#;

#[derive(Clone)]
struct AppState {
    db: Database,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CollectPayload {
    pub token: String,
    pub canvas_hash: Option<String>,
    pub webgl_vendor: Option<String>,
    pub webgl_renderer: Option<String>,
    pub screen_resolution: Option<String>,
    pub color_depth: Option<u8>,
    pub timezone: Option<String>,
    pub timezone_offset_minutes: Option<i32>,
    pub hardware_concurrency: Option<u8>,
    pub device_memory_gb: Option<f32>,
    pub platform: Option<String>,
    pub languages: Option<Vec<String>>,
    pub touch_support: Option<bool>,
}

pub struct TelemetryEngine {
    bind_addr: String,
    db: Database,
    running: Arc<AtomicBool>,
}

impl TelemetryEngine {
    pub fn new(bind_addr: String, db: Database, running: Arc<AtomicBool>) -> Self {
        Self {
            bind_addr,
            db,
            running,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let state = AppState {
            db: self.db.clone(),
        };

        let app = Router::new()
            .route("/beacon.gif", get(handle_pixel_gif))
            .route("/pixel.png", get(handle_pixel_png))
            .route("/beacon.svg", get(handle_pixel_svg))
            .route("/style.css", get(handle_style_css))
            .route("/track/:token", get(handle_tracked_beacon))
            .route("/telemetry.js", get(handle_telemetry_js))
            .route("/collect", post(handle_collect_telemetry))
            .route("/api/ping", get(handle_ping))
            .route("/api/v1/targets", get(handle_api_targets))
            .route("/api/v1/targets/:id", get(handle_api_single_target))
            .route("/api/v1/observations", get(handle_api_observations))
            .route("/api/v1/stats", get(handle_api_stats))
            .route("/api/v1/heatmap", get(handle_api_heatmap))
            .route("/api/v1/export/geojson", get(handle_api_export_geojson))
            .route("/api/v1/export/kml", get(handle_api_export_kml))
            .layer(CorsLayer::permissive())
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(&self.bind_addr)
            .await
            .context(format!("Failed to bind telemetry server to {}", self.bind_addr))?;

        info!(
            "Telemetry & Remote Beacon Server active on http://{}",
            self.bind_addr
        );

        let running = self.running.clone();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                while running.load(Ordering::Relaxed) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            })
            .await
            .unwrap_or_else(|e| error!("Telemetry server crashed: {:?}", e));
        });

        Ok(())
    }
}

async fn handle_pixel_gif(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = extract_token(&params);
    record_hit(&state.db, token, addr, headers, Some(serde_json::to_string(&params).unwrap_or_default()), "/beacon.gif".to_string(), None).await;

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/gif"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate, private"),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        PIXEL_GIF,
    )
}

async fn handle_pixel_png(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = extract_token(&params);
    record_hit(&state.db, token, addr, headers, Some(serde_json::to_string(&params).unwrap_or_default()), "/pixel.png".to_string(), None).await;

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate, private"),
        ],
        PIXEL_PNG,
    )
}

async fn handle_pixel_svg(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = extract_token(&params);
    record_hit(&state.db, token, addr, headers, Some(serde_json::to_string(&params).unwrap_or_default()), "/beacon.svg".to_string(), None).await;

    let svg_content = r#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>"#;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "no-cache")],
        svg_content,
    )
}

async fn handle_style_css(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = extract_token(&params);
    record_hit(&state.db, token, addr, headers, Some(serde_json::to_string(&params).unwrap_or_default()), "/style.css".to_string(), None).await;

    let css_content = "/* Minuteman Telemetry CSS Hook */ body::after { content: ''; display: none; }";
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css"), (header::CACHE_CONTROL, "no-cache")],
        css_content,
    )
}

async fn handle_tracked_beacon(
    State(state): State<AppState>,
    Path(token): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    record_hit(&state.db, token, addr, headers, Some(serde_json::to_string(&params).unwrap_or_default()), "/track/:token".to_string(), None).await;

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/gif"), (header::CACHE_CONTROL, "no-cache")],
        PIXEL_GIF,
    )
}

async fn handle_telemetry_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript"), (header::CACHE_CONTROL, "no-cache")],
        JAVASCRIPT_BEACON,
    )
}

async fn handle_collect_telemetry(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CollectPayload>,
) -> impl IntoResponse {
    let fp = ClientHardwareFingerprint {
        canvas_hash: payload.canvas_hash,
        webgl_renderer: payload.webgl_renderer,
        webgl_vendor: payload.webgl_vendor,
        screen_resolution: payload.screen_resolution,
        color_depth: payload.color_depth,
        timezone: payload.timezone,
        timezone_offset_minutes: payload.timezone_offset_minutes,
        hardware_concurrency: payload.hardware_concurrency,
        device_memory_gb: payload.device_memory_gb,
        platform: payload.platform,
        languages: payload.languages.unwrap_or_default(),
        touch_support: payload.touch_support,
        audio_fingerprint: None,
        webrtc_candidate_ip: None,
    };

    record_hit(&state.db, payload.token, addr, headers, None, "/collect".to_string(), Some(fp)).await;
    (StatusCode::OK, "Telemetry Payload Committed")
}

async fn handle_ping(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    record_hit(&state.db, "ping".to_string(), addr, headers, None, "/api/ping".to_string(), None).await;
    (StatusCode::OK, "PONG")
}

async fn handle_api_targets(State(state): State<AppState>) -> Response {
    match state.db.get_recent_targets(200) {
        Ok(targets) => Json(targets).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("DB Error: {:?}", e)).into_response(),
    }
}

async fn handle_api_single_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.db.get_target_by_identifier(&id) {
        Ok(Some(target)) => Json(target).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Target not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("DB Error: {:?}", e)).into_response(),
    }
}

async fn handle_api_observations(State(state): State<AppState>) -> Response {
    match state.db.get_recent_observations(100) {
        Ok(obs) => Json(obs).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("DB Error: {:?}", e)).into_response(),
    }
}

async fn handle_api_stats(State(state): State<AppState>) -> Response {
    match state.db.get_system_stats() {
        Ok(stats) => Json(stats).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("DB Error: {:?}", e)).into_response(),
    }
}

async fn handle_api_heatmap(State(state): State<AppState>) -> Response {
    match state.db.get_channel_occupancy() {
        Ok(heatmap) => Json(heatmap).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("DB Error: {:?}", e)).into_response(),
    }
}

async fn handle_api_export_geojson(State(state): State<AppState>) -> Response {
    match state.db.export_targets_geojson_string() {
        Ok(geojson) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/geo+json")],
            geojson,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Export Error: {:?}", e)).into_response(),
    }
}

async fn handle_api_export_kml(State(state): State<AppState>) -> Response {
    match state.db.export_targets_kml_string() {
        Ok(kml) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/vnd.google-earth.kml+xml")],
            kml,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Export Error: {:?}", e)).into_response(),
    }
}

fn extract_token(params: &HashMap<String, String>) -> String {
    params
        .get("id")
        .or_else(|| params.get("t"))
        .or_else(|| params.get("token"))
        .or_else(|| params.get("mac"))
        .cloned()
        .unwrap_or_else(|| "beacon-pixel".to_string())
}

async fn record_hit(
    db: &Database,
    token: String,
    socket_addr: SocketAddr,
    headers: HeaderMap,
    query_params: Option<String>,
    path: String,
    client_fp: Option<ClientHardwareFingerprint>,
) {
    let mut resolved_ip = socket_addr.ip();
    let mut forwarded_for = None;

    if let Some(cf_ip) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = IpAddr::from_str(cf_ip.trim()) {
            resolved_ip = ip;
        }
    } else if let Some(x_real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = IpAddr::from_str(x_real_ip.trim()) {
            resolved_ip = ip;
        }
    } else if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        forwarded_for = Some(xff.to_string());
        if let Some(first_ip_str) = xff.split(',').next() {
            if let Ok(ip) = IpAddr::from_str(first_ip_str.trim()) {
                resolved_ip = ip;
            }
        }
    }

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let sec_ch_ua = headers
        .get("sec-ch-ua")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let sec_ch_ua_platform = headers
        .get("sec-ch-ua-platform")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let geo = estimate_ip_geolocation(&resolved_ip).await;

    info!(
        "Application Telemetry Event: Token={}, Resolved IP={}, Country={:?}, City={:?}, Endpoint={}",
        token, resolved_ip, geo.country, geo.city, path
    );

    let hit = TelemetryHit {
        token,
        timestamp: Utc::now(),
        remote_ip: resolved_ip,
        forwarded_for,
        user_agent,
        sec_ch_ua,
        sec_ch_ua_platform,
        query_params,
        path,
        client_fingerprint: client_fp,
        geolocation: Some(geo),
    };

    if let Err(e) = db.record_telemetry_hit(&hit) {
        error!("Database write error for telemetry hit: {:?}", e);
    }
}

pub async fn estimate_ip_geolocation(ip: &IpAddr) -> GeoLocationEstimate {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            if octets[0] == 10 || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] == 192 && octets[1] == 168) || octets[0] == 127 {
                GeoLocationEstimate {
                    latitude: 37.7749,
                    longitude: -122.4194,
                    accuracy_radius_km: 1.0,
                    country: Some("United States".to_string()),
                    region: Some("California".to_string()),
                    city: Some("San Francisco (Lab Bench)".to_string()),
                    isp: Some("Private Research Lab Network".to_string()),
                    asn: Some("AS-LOCAL-BENCH".to_string()),
                }
            } else {
                let client = Client::new();
                let url = format!("http://ip-api.com/json/{}", ip);
                
                match client.get(&url).send().await {
                    Ok(response) => {
                        if let Ok(geo_data) = response.json::<IpApiResponse>().await {
                            GeoLocationEstimate {
                                latitude: geo_data.lat.unwrap_or(0.0),
                                longitude: geo_data.lon.unwrap_or(0.0),
                                accuracy_radius_km: geo_data.accuracy_radius.unwrap_or(50.0),
                                country: geo_data.country,
                                region: geo_data.region_name,
                                city: geo_data.city,
                                isp: geo_data.isp,
                                asn: geo_data.asn.map(|a| format!("AS{}", a)),
                            }
                        } else {
                            Self::fallback_geolocation(ipv4)
                        }
                    }
                    Err(_) => Self::fallback_geolocation(ipv4),
                }
            }
        }
        IpAddr::V6(_) => GeoLocationEstimate {
            latitude: 40.7128,
            longitude: -74.0060,
            accuracy_radius_km: 10.0,
            country: Some("United States".to_string()),
            region: Some("New York".to_string()),
            city: Some("New York (IPv6 Node)".to_string()),
            isp: Some("IPv6 Core Transit".to_string()),
            asn: Some("AS64512".to_string()),
        },
    }
}

fn fallback_geolocation(ipv4: std::net::Ipv4Addr) -> GeoLocationEstimate {
    let octets = ipv4.octets();
    let lat = 37.0 + ((octets[2] as f64) % 15.0) - 7.5;
    let lon = -95.0 + ((octets[3] as f64) % 30.0) - 15.0;
    GeoLocationEstimate {
        latitude: lat,
        longitude: lon,
        accuracy_radius_km: 15.0,
        country: Some("United States".to_string()),
        region: Some("North America".to_string()),
        city: Some("Public Gateway Node".to_string()),
        isp: Some("Broadband / Cellular Carrier".to_string()),
        asn: Some(format!("AS{}", 10000 + (octets[0] as u32) * 50)),
    }
}

#[derive(Debug, Deserialize)]
struct IpApiResponse {
    #[serde(rename = "lat")]
    lat: Option<f64>,
    #[serde(rename = "lon")]
    lon: Option<f64>,
    country: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    asn: Option<u32>,
    #[serde(rename = "accuracyRadius")]
    accuracy_radius: Option<f64>,
}
