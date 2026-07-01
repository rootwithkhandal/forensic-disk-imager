use serde::Deserialize;
use std::process::Stdio;
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use crate::ActiveTaskState;
use crate::acquisition::ProgressEvent;
use std::collections::HashMap;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VolatilityConfig {
    pub image_path: String,
    pub vol_path: String,
    pub profile: String,
    pub enrich_vt: bool,
    pub enrich_mb: bool,
    pub enrich_abuseip: bool,
    pub vt_key: String,
    pub mb_key: String,
    pub abuseip_key: String,
}

#[tauri::command]
pub async fn start_volatility_analysis(
    config: VolatilityConfig,
    state: State<'_, ActiveTaskState>,
    app_handle: AppHandle,
) -> Result<(), String> {
    let mut lock = state.lock().unwrap();
    if lock.is_some() {
        return Err("A task is already running.".to_string());
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressEvent>(100);
    *lock = Some(tx.clone());

    let app_handle_clone = app_handle.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = app_handle_clone.emit("volatility-event", event);
        }
    });

    let app_clone = app_handle.clone();
    tokio::spawn(async move {
        let _ = tx.send(ProgressEvent::Log(format!("Executing: {} -f {} {}", config.vol_path, config.image_path, config.profile))).await;
        
        let mut cmd;
        if config.vol_path.ends_with(".py") {
            cmd = Command::new("python");
            cmd.arg(&config.vol_path);
        } else {
            cmd = Command::new(&config.vol_path);
        }

        cmd.arg("-f")
           .arg(&config.image_path)
           .arg(&config.profile)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(ProgressEvent::Error(format!("Failed to start Volatility: {}", e))).await;
                crate::clear_active_task(&app_clone);
                return;
            }
        };

        let stdout = child.stdout.take().expect("Failed to open stdout");
        let stderr = child.stderr.take().expect("Failed to open stderr");

        let mut stdout_reader = BufReader::new(stdout).lines();
        let mut stderr_reader = BufReader::new(stderr).lines();

        let tx_out = tx.clone();
        let _vt_key = config.vt_key.clone();
        let abuseip_key = config.abuseip_key.clone();
        let _enrich_vt = config.enrich_vt;
        let enrich_abuseip = config.enrich_abuseip;
        
        let ip_re = regex::Regex::new(r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)\.(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)\.(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)\.(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)\b").unwrap();

        let stdout_task = tokio::spawn(async move {
            while let Ok(Some(line)) = stdout_reader.next_line().await {
                let _ = tx_out.send(ProgressEvent::Log(line.clone())).await;

                if enrich_abuseip && !abuseip_key.is_empty() {
                    if let Some(caps) = ip_re.captures(&line) {
                        let ip = &caps[0];
                        if !ip.starts_with("127.") && !ip.starts_with("192.168.") && !ip.starts_with("10.") && !ip.starts_with("172.16.") && ip != "0.0.0.0" {
                            let key = abuseip_key.clone();
                            let ip_str = ip.to_string();
                            let tx_inner = tx_out.clone();
                            tokio::spawn(async move {
                                if let Ok(res) = check_abuseip(&ip_str, &key).await {
                                    let _ = tx_inner.send(ProgressEvent::Log(format!("  [AbuseIPDB] Result for {}: {}", ip_str, res))).await;
                                }
                            });
                        }
                    }
                }
            }
        });

        let tx_err = tx.clone();
        let stderr_task = tokio::spawn(async move {
            while let Ok(Some(line)) = stderr_reader.next_line().await {
                let _ = tx_err.send(ProgressEvent::Log(format!("[STDERR] {}", line))).await;
            }
        });

        let _ = tokio::join!(stdout_task, stderr_task);
        let _ = child.wait().await;

        let _ = tx.send(ProgressEvent::Finished {
            bytes_read: 0,
            bad_sectors: 0,
            hashes: HashMap::new(),
        }).await;
        crate::clear_active_task(&app_clone);
    });

    Ok(())
}

async fn check_abuseip(ip: &str, api_key: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let res = client.get("https://api.abuseipdb.com/api/v2/check")
        .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
        
    let json: serde_json::Value = res.json().await?;
    if let Some(data) = json.get("data") {
        let score = data.get("abuseConfidenceScore").and_then(|v| v.as_i64()).unwrap_or(0);
        let country = data.get("countryCode").and_then(|v| v.as_str()).unwrap_or("Unknown");
        Ok(format!("Confidence Score: {}%, Country: {}", score, country))
    } else {
        Ok("No data".to_string())
    }
}
