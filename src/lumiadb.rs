use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use gosh_dl::{DownloadEngine, DownloadEvent, DownloadOptions, EngineConfig};
use serde::Deserialize;

const LUMIADB_DATABASE_URL: &str = "https://lumiadb.com/database.json";
const LUMIADB_API_BASE: &str = "https://api.lumiadb.com";
const LUMIA_520_SBL3: &str = "Engineering-SBL3-Lumia-520-620-625-720-1320.bin";
pub(crate) const DONOR_MODEL: &str = "RM-1085";
pub(crate) const DONOR_PRODUCT_CODE: &str = "059X4T0";
pub(crate) const DONOR_FFU_FILENAME: &str =
    "RM1085_1078.0053.10586.13169.12742.034EE8_retail_prod_signed.ffu";

#[derive(Debug, Deserialize)]
pub(crate) struct LumiaDbDevice {
    #[serde(rename = "hardwareModel")]
    pub(crate) hardware_model: String,
    #[serde(rename = "phoneModel")]
    pub(crate) phone_model: String,
    #[serde(default)]
    pub(crate) variant: String,
    #[serde(rename = "productCodes", default)]
    pub(crate) product_codes: Vec<String>,
    #[serde(default)]
    pub(crate) firmwares: Vec<LumiaDbFirmware>,
}

impl LumiaDbDevice {
    pub(crate) fn matches(&self, query: &str) -> bool {
        self.hardware_model.to_lowercase().contains(query)
            || self.phone_model.to_lowercase().contains(query)
            || self.variant.to_lowercase().contains(query)
            || self
                .product_codes
                .iter()
                .any(|code| code.to_lowercase().contains(query))
            || self
                .firmwares
                .iter()
                .any(|firmware| firmware.matches(query))
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct LumiaDbFirmware {
    #[serde(rename = "packageTitle", default)]
    pub(crate) package_title: String,
    #[serde(default)]
    pub(crate) firmware: String,
    #[serde(default)]
    pub(crate) os: Option<String>,
    #[serde(rename = "productCode", default)]
    pub(crate) product_code: String,
    #[serde(rename = "ffuFilename")]
    pub(crate) ffu_filename: String,
}

impl LumiaDbFirmware {
    pub(crate) fn matches(&self, query: &str) -> bool {
        self.package_title.to_lowercase().contains(query)
            || self.firmware.to_lowercase().contains(query)
            || self.product_code.to_lowercase().contains(query)
            || self.ffu_filename.to_lowercase().contains(query)
            || self
                .os
                .as_deref()
                .unwrap_or_default()
                .to_lowercase()
                .contains(query)
    }
}

pub(crate) struct LumiaDbPlan<'a> {
    pub(crate) device: &'a LumiaDbDevice,
    pub(crate) firmware: &'a LumiaDbFirmware,
    pub(crate) ffu_url: String,
    pub(crate) emergency_url: String,
    pub(crate) sbl3_url: String,
}

impl LumiaDbPlan<'_> {
    pub(crate) fn blobs(&self) -> Vec<PlannedBlob> {
        vec![
            PlannedBlob {
                kind: "ffu",
                url: self.ffu_url.clone(),
                filename: self.firmware.ffu_filename.clone(),
            },
            PlannedBlob {
                kind: "emergency",
                url: self.emergency_url.clone(),
                filename: format!("{}.zip", self.device.hardware_model),
            },
            PlannedBlob {
                kind: "sbl3",
                url: self.sbl3_url.clone(),
                filename: LUMIA_520_SBL3.to_string(),
            },
        ]
    }

    pub(crate) fn manifest_json(&self) -> String {
        serde_json::json!({
            "hardwareModel": self.device.hardware_model,
            "phoneModel": self.device.phone_model,
            "variant": self.device.variant,
            "productCode": self.firmware.product_code,
            "firmware": self.firmware.firmware,
            "os": self.firmware.os,
            "ffu": self.ffu_url,
            "emergency": self.emergency_url,
            "sbl3": self.sbl3_url,
        })
        .to_string()
    }
}

pub(crate) struct PlannedBlob {
    pub(crate) kind: &'static str,
    pub(crate) url: String,
    pub(crate) filename: String,
}

pub(crate) fn fetch_lumiadb_database() -> Result<Vec<LumiaDbDevice>> {
    let client = http_client()?;
    let response = client
        .get(LUMIADB_DATABASE_URL)
        .send()
        .context("failed to fetch LumiaDB database")?
        .error_for_status()
        .context("LumiaDB database request failed")?;

    response
        .json::<Vec<LumiaDbDevice>>()
        .context("failed to parse LumiaDB database")
}

pub(crate) fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent("lp-externals/0.1")
        .build()
        .context("failed to build HTTP client")
}

pub(crate) async fn download_file(url: &str, path: &Path) -> Result<()> {
    if let Ok(metadata) = path.metadata() {
        ensure!(
            metadata.is_file(),
            "download path exists but is not a file: {}",
            path.display()
        );
        if metadata.len() != 0 {
            println!("cached: {} ({} bytes)", path.display(), metadata.len());
            return Ok(());
        }
        fs::remove_file(path)
            .with_context(|| format!("failed to remove empty cache file {}", path.display()))?;
    }

    println!("downloading: {url}");
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("invalid download path: {}", path.display()))?;
    let save_dir = path
        .parent()
        .ok_or_else(|| anyhow!("download path has no parent: {}", path.display()))?;

    let config = EngineConfig {
        download_dir: save_dir.to_path_buf(),
        max_connections_per_download: 8,
        user_agent: "lp-externals/0.1".to_string(),
        ..Default::default()
    };
    let engine = DownloadEngine::new(config)
        .await
        .with_context(|| format!("failed to initialize downloader for {url}"))?;
    let mut events = engine.subscribe();
    let id = engine
        .add_http(
            url,
            DownloadOptions::default()
                .save_dir(save_dir)
                .filename(filename)
                .user_agent("lp-externals/0.1")
                .max_connections(8),
        )
        .await
        .with_context(|| format!("failed to queue download for {url}"))?;

    let mut last_percent = None;
    while let Ok(event) = events.recv().await {
        match event {
            DownloadEvent::Progress {
                id: event_id,
                progress,
            } if event_id == id => {
                let percent = progress.percentage().floor() as u64;
                if last_percent != Some(percent) {
                    last_percent = Some(percent);
                    let total = progress
                        .total_size
                        .map(|size| size.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("  {percent}% ({}/{} bytes)", progress.completed_size, total);
                }
            }
            DownloadEvent::Completed { id: event_id } if event_id == id => break,
            DownloadEvent::Failed {
                id: event_id,
                error,
                ..
            } if event_id == id => {
                bail!("download failed for {url}: {error}");
            }
            _ => {}
        }
    }

    engine
        .shutdown()
        .await
        .with_context(|| format!("failed to shut down downloader for {url}"))?;
    let bytes = path
        .metadata()
        .with_context(|| format!("download did not create {}", path.display()))?
        .len();
    println!("wrote: {} ({} bytes)", path.display(), bytes);

    Ok(())
}

pub(crate) fn make_lumiadb_plan<'a>(
    database: &'a [LumiaDbDevice],
    model: &str,
    product_code: Option<&str>,
) -> Result<LumiaDbPlan<'a>> {
    let devices = database
        .iter()
        .filter(|device| device.hardware_model.eq_ignore_ascii_case(model))
        .collect::<Vec<_>>();

    ensure!(!devices.is_empty(), "no LumiaDB entries found for {model}");

    let firmware = if let Some(product_code) = product_code {
        devices
            .iter()
            .flat_map(|device| {
                device
                    .firmwares
                    .iter()
                    .map(move |firmware| (*device, firmware))
            })
            .find(|(_, firmware)| firmware.product_code.eq_ignore_ascii_case(product_code))
            .with_context(|| {
                format!("no LumiaDB firmware found for {model} product code {product_code}")
            })?
    } else {
        devices
            .iter()
            .flat_map(|device| {
                device
                    .firmwares
                    .iter()
                    .map(move |firmware| (*device, firmware))
            })
            .next()
            .with_context(|| format!("no LumiaDB firmware files listed for {model}"))?
    };

    let (device, firmware) = firmware;

    Ok(LumiaDbPlan {
        device,
        firmware,
        ffu_url: format!(
            "{}/{}/{}",
            LUMIADB_API_BASE, device.hardware_model, firmware.ffu_filename
        ),
        emergency_url: format!(
            "{}/{}/{}.zip",
            LUMIADB_API_BASE, device.hardware_model, device.hardware_model
        ),
        sbl3_url: format!("{}/SBL3/{}", LUMIADB_API_BASE, LUMIA_520_SBL3),
    })
}

pub(crate) fn make_exact_lumiadb_plan<'a>(
    database: &'a [LumiaDbDevice],
    model: &str,
    product_code: &str,
) -> Result<LumiaDbPlan<'a>> {
    let matches = database
        .iter()
        .filter(|device| device.hardware_model.eq_ignore_ascii_case(model))
        .flat_map(|device| {
            device
                .firmwares
                .iter()
                .filter(move |firmware| firmware.product_code.eq_ignore_ascii_case(product_code))
                .map(move |firmware| (device, firmware))
        })
        .collect::<Vec<_>>();

    ensure!(
        !matches.is_empty(),
        "no LumiaDB stock FFU found for {model} product code {product_code}"
    );

    if matches.len() > 1 {
        let candidates = matches
            .iter()
            .map(|(device, firmware)| {
                format!(
                    "{} {} product={} file={}",
                    device.hardware_model,
                    device.variant,
                    firmware.product_code,
                    firmware.ffu_filename
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        bail!(
            "LumiaDB stock FFU is ambiguous for {model} product code {product_code}: {candidates}"
        );
    }

    let (device, firmware) = matches[0];
    Ok(LumiaDbPlan {
        device,
        firmware,
        ffu_url: format!(
            "{}/{}/{}",
            LUMIADB_API_BASE, device.hardware_model, firmware.ffu_filename
        ),
        emergency_url: format!(
            "{}/{}/{}.zip",
            LUMIADB_API_BASE, device.hardware_model, device.hardware_model
        ),
        sbl3_url: format!("{}/SBL3/{}", LUMIADB_API_BASE, LUMIA_520_SBL3),
    })
}

pub(crate) fn cache_dir_for(model: &str, product_code: &str) -> Result<PathBuf> {
    Ok(cache_root()?.join("lumiadb").join(model).join(product_code))
}

pub(crate) fn cached_ffu_path(plan: &LumiaDbPlan<'_>) -> Result<PathBuf> {
    Ok(
        cache_dir_for(&plan.device.hardware_model, &plan.firmware.product_code)?
            .join(&plan.firmware.ffu_filename),
    )
}

pub(crate) fn cached_emergency_path(plan: &LumiaDbPlan<'_>) -> Result<PathBuf> {
    Ok(
        cache_dir_for(&plan.device.hardware_model, &plan.firmware.product_code)?
            .join(format!("{}.zip", plan.device.hardware_model)),
    )
}

pub(crate) fn cached_sbl3_path(plan: &LumiaDbPlan<'_>) -> Result<PathBuf> {
    Ok(
        cache_dir_for(&plan.device.hardware_model, &plan.firmware.product_code)?
            .join(LUMIA_520_SBL3),
    )
}

pub(crate) fn cached_jailbreak_artifact_dir(
    product_type: &str,
    product_code: &str,
    imei: &str,
) -> Result<PathBuf> {
    Ok(cache_root()?
        .join("jailbreak")
        .join(cache_segment(product_type))
        .join(cache_segment(product_code))
        .join(cache_segment(imei))
        .join("artifacts"))
}

pub(crate) fn donor_ffu_url() -> String {
    format!(
        "{}/{}/{}",
        LUMIADB_API_BASE, DONOR_MODEL, DONOR_FFU_FILENAME
    )
}

pub(crate) fn cached_donor_ffu_path() -> Result<PathBuf> {
    Ok(cache_dir_for(DONOR_MODEL, DONOR_PRODUCT_CODE)?.join(DONOR_FFU_FILENAME))
}

fn cache_root() -> Result<PathBuf> {
    if let Some(path) = env::var_os("XDG_CACHE_HOME").filter(|value| !value.as_os_str().is_empty())
    {
        return Ok(PathBuf::from(path).join("lp-externals"));
    }

    let home = env::var_os("HOME").context("HOME is not set and XDG_CACHE_HOME is empty")?;
    Ok(PathBuf::from(home).join(".cache").join("lp-externals"))
}

fn cache_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();

    if segment.is_empty() {
        "_".to_string()
    } else {
        segment
    }
}

pub(crate) fn print_lumiadb_plan(plan: &LumiaDbPlan<'_>) {
    println!("model: {}", plan.device.hardware_model);
    println!("phone: {}", plan.device.phone_model);
    println!("variant: {}", plan.device.variant);
    println!("product code: {}", plan.firmware.product_code);
    println!("firmware: {}", plan.firmware.firmware);
    if let Some(os) = &plan.firmware.os {
        println!("os: {os}");
    }
    println!("ffu: {}", plan.ffu_url);
    println!("emergency: {}", plan.emergency_url);
    println!("sbl3: {}", plan.sbl3_url);
}
