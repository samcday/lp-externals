use std::{
    fmt, fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use gosh_dl::{DownloadEngine, DownloadEvent, DownloadOptions, EngineConfig};
use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType, UsbContext};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const RESET_RETRY_TIMEOUT: Duration = Duration::from_secs(10);
const LUMIADB_DATABASE_URL: &str = "https://lumiadb.com/database.json";
const LUMIADB_API_BASE: &str = "https://api.lumiadb.com";
const LUMIA_520_SBL3: &str = "Engineering-SBL3-Lumia-520-620-625-720-1320.bin";

#[derive(Debug, Parser)]
#[command(name = "lp-externals")]
#[command(about = "LPexternals: portable Lumia/Nokia phone pokery")]
struct Cli {
    /// Wait for the target USB device to appear before running the command.
    #[arg(long, global = true, default_value_t = true, action = clap::ArgAction::Set)]
    wait: bool,

    /// Print raw protocol response bytes for decoded commands.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Identify a Lumia UEFI/BOOTMGR interface with the non-mutating NOKV query.
    Identify {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,
    },

    /// Send a raw ASCII command and print the response.
    Raw {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Raw ASCII commands, for example NOKI or NOKV.
        #[arg(required = true)]
        commands: Vec<String>,
    },

    /// Disable the BootMgr reboot timeout with NOKD.
    StayAwake {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,
    },

    /// Reboot the phone with the write-only NOKR command.
    Reset {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,
    },

    /// Power off the phone with NOKZ where supported.
    Shutdown {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,
    },

    /// Mode switching commands.
    Switch {
        #[command(subcommand)]
        command: SwitchCommand,
    },

    /// FlashApp parameter commands.
    Param {
        #[command(subcommand)]
        command: ParamCommand,
    },

    /// PhoneInfoApp variable commands.
    PhoneInfo {
        #[command(subcommand)]
        command: PhoneInfoCommand,
    },

    /// GPT-related commands.
    Gpt {
        #[command(subcommand)]
        command: GptCommand,
    },

    /// LumiaDB catalog and blob planning commands.
    Lumiadb {
        #[command(subcommand)]
        command: LumiaDbCommand,
    },

    /// Offline FFU inspection commands.
    Ffu {
        #[command(subcommand)]
        command: FfuCommand,
    },

    /// Offline Qualcomm image and loader inspection commands.
    Qcom {
        #[command(subcommand)]
        command: QcomCommand,
    },
}

#[derive(Debug, Subcommand)]
enum QcomCommand {
    /// Parse a raw or Intel HEX Qualcomm image and print signing metadata.
    ImageInfo {
        /// Raw image or Intel HEX path.
        path: PathBuf,

        /// Header search offset for raw images.
        #[arg(long, default_value = "0x0", value_parser = parse_u32)]
        offset: u32,
    },

    /// Scan a Lumia emergency zip or directory for ARMPRG loaders matching an RRKH.
    ScanLoaders {
        /// Emergency zip, loader file, or directory.
        path: PathBuf,

        /// Expected Root Key Hash as hex, for example from `param read RRKH`.
        #[arg(long)]
        rrkh: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum FfuCommand {
    /// Print basic FFU metadata.
    Info {
        /// FFU path.
        path: PathBuf,
    },

    /// Print partitions from the FFU primary GPT.
    Partitions {
        /// FFU path.
        path: PathBuf,
    },

    /// Extract a named partition from an FFU.
    Extract {
        /// FFU path.
        path: PathBuf,

        /// Partition name, for example SBL1, SBL2, SBL3, UEFI, TZ, RPM, WINSECAPP, or EFIESP.
        partition: String,

        /// Output path for raw partition bytes.
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum LumiaDbCommand {
    /// Search LumiaDB database entries by model, name, variant, or product code.
    Search {
        /// Search query, for example RM-914 or 059S083.
        query: String,
    },

    /// Plan downloads for a model/product code pair.
    Plan {
        /// Hardware model, for example RM-914.
        #[arg(long, default_value = "RM-914")]
        model: String,

        /// Product code, for example 059S083.
        #[arg(long)]
        product_code: Option<String>,
    },

    /// Check availability of planned LumiaDB downloads with HEAD requests.
    Check {
        /// Hardware model, for example RM-914.
        #[arg(long, default_value = "RM-914")]
        model: String,

        /// Product code, for example 059S083.
        #[arg(long)]
        product_code: Option<String>,
    },

    /// Download planned LumiaDB blobs.
    Download {
        /// Hardware model, for example RM-914.
        #[arg(long, default_value = "RM-914")]
        model: String,

        /// Product code, for example 059S083.
        #[arg(long)]
        product_code: Option<String>,

        /// Output directory.
        #[arg(long, default_value = "blobs")]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PhoneInfoCommand {
    /// Read a PhoneInfoApp variable with NOKXPH.
    Read {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Variable name, for example TYPE, CTR, or IMEI.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum ParamCommand {
    /// Read a FlashApp parameter with NOKXFR.
    Read {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Parameter name, for example RRKH, FAI, SS, FCS, DPI, or FVER.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum SwitchCommand {
    /// Reboot/switch from BootMgr to FlashApp mode with NOKS.
    Flash {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,
    },

    /// Reboot/switch to PhoneInfoApp mode with NOKP.
    PhoneInfo {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,
    },
}

#[derive(Debug, Subcommand)]
enum GptCommand {
    /// Dump GPT partition entries with the read-only NOKT query.
    Dump {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Output format.
        #[arg(long, default_value_t = GptDumpFormat::Text)]
        format: GptDumpFormat,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum GptDumpFormat {
    Text,
    RawHex,
}

impl fmt::Display for GptDumpFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::RawHex => write!(f, "raw-hex"),
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Identify { vid, pid } => identify(vid, pid, cli.wait, cli.debug),
        Command::Raw { vid, pid, commands } => raw(vid, pid, cli.wait, &commands),
        Command::StayAwake { vid, pid } => stay_awake(vid, pid, cli.wait),
        Command::Reset { vid, pid } => reset(vid, pid, cli.wait),
        Command::Shutdown { vid, pid } => shutdown(vid, pid, cli.wait),
        Command::Switch { command } => match command {
            SwitchCommand::Flash { vid, pid } => switch_flash(vid, pid, cli.wait),
            SwitchCommand::PhoneInfo { vid, pid } => switch_phone_info(vid, pid, cli.wait),
        },
        Command::Param { command } => match command {
            ParamCommand::Read { vid, pid, name } => {
                param_read(vid, pid, cli.wait, cli.debug, &name)
            }
        },
        Command::PhoneInfo { command } => match command {
            PhoneInfoCommand::Read { vid, pid, name } => {
                phone_info_read(vid, pid, cli.wait, cli.debug, &name)
            }
        },
        Command::Gpt { command } => match command {
            GptCommand::Dump { vid, pid, format } => gpt_dump(vid, pid, cli.wait, format),
        },
        Command::Lumiadb { command } => match command {
            LumiaDbCommand::Search { query } => lumiadb_search(&query),
            LumiaDbCommand::Plan {
                model,
                product_code,
            } => lumiadb_plan(&model, product_code.as_deref()),
            LumiaDbCommand::Check {
                model,
                product_code,
            } => lumiadb_check(&model, product_code.as_deref()),
            LumiaDbCommand::Download {
                model,
                product_code,
                output,
            } => lumiadb_download(&model, product_code.as_deref(), &output),
        },
        Command::Ffu { command } => match command {
            FfuCommand::Info { path } => ffu_info(&path),
            FfuCommand::Partitions { path } => ffu_partitions(&path),
            FfuCommand::Extract {
                path,
                partition,
                output,
            } => ffu_extract(&path, &partition, &output),
        },
        Command::Qcom { command } => match command {
            QcomCommand::ImageInfo { path, offset } => qcom_image_info(&path, offset),
            QcomCommand::ScanLoaders { path, rrkh } => qcom_scan_loaders(&path, rrkh.as_deref()),
        },
    }
}

fn ffu_info(path: &Path) -> Result<()> {
    let ffu = ParsedFfu::open(path)?;

    println!("path: {}", path.display());
    println!("file size: {}", ffu.file_size);
    println!("chunk size: {}", ffu.chunk_size);
    println!("platform ID: {}", ffu.platform_id);
    println!("security header: {} bytes", ffu.security_header_len);
    println!("image header: {} bytes", ffu.image_header_len);
    println!("store header: {} bytes", ffu.store_header_len);
    println!("header size: {}", ffu.header_size);
    println!("payload size: {}", ffu.payload_size);
    println!("total chunks: {}", ffu.total_chunk_count);
    println!("mapped disk chunks: {}", ffu.chunk_indexes.len());

    Ok(())
}

fn ffu_partitions(path: &Path) -> Result<()> {
    let ffu = ParsedFfu::open(path)?;
    let gpt = ffu.get_sectors(1, 0x21)?;
    print_gpt(&gpt)
}

fn ffu_extract(path: &Path, partition: &str, output: &Path) -> Result<()> {
    let ffu = ParsedFfu::open(path)?;
    let bytes = ffu.get_partition(partition)?;

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    fs::write(output, &bytes).with_context(|| format!("failed to write {}", output.display()))?;
    println!(
        "extracted {} ({} bytes) to {}",
        partition,
        bytes.len(),
        output.display()
    );

    Ok(())
}

fn qcom_image_info(path: &Path, offset: u32) -> Result<()> {
    let source = read_qcom_source(path)?;
    let image = QualcommImage::parse(&source.bytes, offset)
        .with_context(|| format!("failed to parse Qualcomm image in {}", path.display()))?;

    println!("path: {}", path.display());
    println!("source format: {}", source.format);
    println!("source bytes: {}", source.bytes.len());
    print_qcom_image(&image);

    Ok(())
}

fn qcom_scan_loaders(path: &Path, rrkh: Option<&str>) -> Result<()> {
    let expected_rrkh = rrkh.map(parse_hex_bytes).transpose()?;
    if let Some(rrkh) = &expected_rrkh {
        ensure!(
            rrkh.len() == 0x20,
            "RRKH must be 32 bytes, got {}",
            rrkh.len()
        );
    }

    let candidates = read_qcom_candidates(path)?;
    ensure!(!candidates.is_empty(), "no loader candidates found");

    let mut matches = 0usize;
    for candidate in candidates {
        print!("{}: ", candidate.name);

        if candidate.bytes.len() > 0x80000 {
            println!("skip size={} (> 0x80000)", candidate.bytes.len());
            continue;
        }

        match QualcommImage::parse(&candidate.bytes, 0) {
            Ok(image) => {
                let armprg = contains_utf16le(&candidate.bytes, "QHSUSB_ARMPRG");
                let rkh_matches = expected_rrkh
                    .as_deref()
                    .is_none_or(|rrkh| image.root_key_hash.as_deref() == Some(rrkh));
                let status = if armprg && rkh_matches {
                    matches += 1;
                    "MATCH"
                } else {
                    "skip"
                };

                println!(
                    "{status} format={} size={} armprg={} rkh={}",
                    candidate.format,
                    candidate.bytes.len(),
                    armprg,
                    image
                        .root_key_hash
                        .as_deref()
                        .map(hex_dump_compact)
                        .unwrap_or_else(|| "none".to_string())
                );
            }
            Err(err) => println!("skip parse-error={err:#}"),
        }
    }

    println!("matching loaders: {matches}");

    Ok(())
}

fn lumiadb_search(query: &str) -> Result<()> {
    let database = fetch_lumiadb_database()?;
    let normalized = query.to_lowercase();
    let mut matches = 0usize;

    for device in database.iter().filter(|device| device.matches(&normalized)) {
        matches += 1;
        println!(
            "{} - {} ({})",
            device.hardware_model, device.phone_model, device.variant
        );
        if !device.product_codes.is_empty() {
            println!("  product codes: {}", device.product_codes.join(", "));
        }
        for firmware in &device.firmwares {
            println!(
                "  {} {} product={} file={}",
                firmware.firmware,
                firmware.os.as_deref().unwrap_or("unknown OS"),
                firmware.product_code,
                firmware.ffu_filename
            );
        }
    }

    if matches == 0 {
        println!("no LumiaDB entries matched {query}");
    }

    Ok(())
}

fn lumiadb_plan(model: &str, product_code: Option<&str>) -> Result<()> {
    let database = fetch_lumiadb_database()?;
    let plan = make_lumiadb_plan(&database, model, product_code)?;

    print_lumiadb_plan(&plan);

    Ok(())
}

fn lumiadb_check(model: &str, product_code: Option<&str>) -> Result<()> {
    let database = fetch_lumiadb_database()?;
    let plan = make_lumiadb_plan(&database, model, product_code)?;
    let client = http_client()?;

    print_lumiadb_plan(&plan);
    println!();
    println!("availability:");

    for blob in plan.blobs() {
        let response = client
            .head(&blob.url)
            .send()
            .with_context(|| format!("HEAD failed for {}", blob.url))?;
        let status = response.status();
        let size = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown");
        println!("  {}: {} size={}", blob.kind, status, size);
    }

    Ok(())
}

fn lumiadb_download(model: &str, product_code: Option<&str>, output: &PathBuf) -> Result<()> {
    let database = fetch_lumiadb_database()?;
    let plan = make_lumiadb_plan(&database, model, product_code)?;
    let target_dir = output
        .join(&plan.device.hardware_model)
        .join(&plan.firmware.product_code);

    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;

    print_lumiadb_plan(&plan);
    println!();
    println!("download directory: {}", target_dir.display());

    let runtime = tokio::runtime::Runtime::new().context("failed to create download runtime")?;
    for blob in plan.blobs() {
        let path = target_dir.join(blob.filename);
        runtime.block_on(download_file(&blob.url, &path))?;
    }

    let manifest = plan.manifest_json();
    fs::write(target_dir.join("manifest.json"), manifest)
        .with_context(|| format!("failed to write manifest in {}", target_dir.display()))?;

    Ok(())
}

fn identify(vid: u16, pid: u16, wait: bool, debug: bool) -> Result<()> {
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")
    })?;
    print_identification(&response, debug);

    Ok(())
}

fn raw(vid: u16, pid: u16, wait: bool, commands: &[String]) -> Result<()> {
    let responses = with_device(vid, pid, wait, |handle, endpoints| {
        let mut responses = Vec::with_capacity(commands.len());

        for command in commands {
            responses.push((
                command.clone(),
                send_raw_command(
                    handle,
                    endpoints.out_addr,
                    endpoints.in_addr,
                    command.as_bytes(),
                )?,
            ));
        }

        Ok(responses)
    })?;

    for (index, (command, response)) in responses.iter().enumerate() {
        if responses.len() > 1 {
            println!("command {}: {command}", index + 1);
        }

        print_raw_response(response);
    }

    Ok(())
}

fn stay_awake(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKD")
    })?;

    ensure!(
        response == b"NOKD",
        "unexpected NOKD response: {}",
        hex_dump(&response)
    );

    println!("disabled reboot timeout (NOKD)");

    Ok(())
}

fn reset(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let (app, ack_read) =
        with_device_allow_release_disconnect(vid, pid, wait, |handle, endpoints| {
            let identification =
                send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
            let app = parse_nokv_app_type(&identification)?;

            let mut ack_read = false;
            if app == 3 {
                send_raw_void_command(handle, endpoints.out_addr, b"NOKA")?;
            } else {
                ensure_reset_supported_app(app)?;
                ack_read = send_raw_command_allow_disconnect(
                    handle,
                    endpoints.out_addr,
                    endpoints.in_addr,
                    b"NOKR",
                )?;
            }

            Ok((app, ack_read))
        })?;

    if app == 3 {
        println!("PhoneInfoApp does not support NOKR; sent continue-boot command (NOKA)");
        let (next_app, ack_read) = send_reset_when_available(vid, pid)?;

        println!(
            "sent reset command (NOKR) after PhoneInfoApp continued to {}",
            app_type_name(next_app)
        );
        if ack_read {
            println!("received NOKR response; device may not have reset");
        }
        return Ok(());
    }

    println!("sent reset command (NOKR)");
    if ack_read {
        println!("received NOKR response; device may not have reset");
    }

    Ok(())
}

fn send_reset_when_available(vid: u16, pid: u16) -> Result<(u8, bool)> {
    let started = std::time::Instant::now();
    let mut last_error = None;

    while started.elapsed() < RESET_RETRY_TIMEOUT {
        match with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
            let identification =
                send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
            let app = parse_nokv_app_type(&identification)?;
            ensure_reset_supported_app(app)?;
            let ack_read = send_raw_command_allow_disconnect(
                handle,
                endpoints.out_addr,
                endpoints.in_addr,
                b"NOKR",
            )?;
            Ok((app, ack_read))
        }) {
            Ok(result) => return Ok(result),
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(DEVICE_POLL_INTERVAL);
            }
        }
    }

    match last_error {
        Some(err) => Err(err).context("timed out waiting for reset-capable app after NOKA"),
        None => bail!("timed out waiting for reset-capable app after NOKA"),
    }
}

fn shutdown(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let app = with_device_allow_release_disconnect(vid, pid, wait, |handle, endpoints| {
        let identification =
            send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
        let app = parse_nokv_app_type(&identification)?;

        if app == 3 {
            send_raw_void_command(handle, endpoints.out_addr, b"NOKA")?;
        } else {
            ensure_shutdown_supported_app(app)?;
            send_raw_command_expect_echo(handle, endpoints.out_addr, endpoints.in_addr, b"NOKZ")?;
        }

        Ok(app)
    })?;

    if app == 3 {
        println!("PhoneInfoApp does not support NOKZ; sent continue-boot command (NOKA)");
        let next_app = send_shutdown_when_available(vid, pid)?;

        println!(
            "sent shutdown command (NOKZ) after PhoneInfoApp continued to {}",
            app_type_name(next_app)
        );
        println!("Unplug device to complete shutdown.");
        return Ok(());
    }

    println!("sent shutdown command (NOKZ)");
    println!("Unplug device to complete shutdown.");

    Ok(())
}

fn send_shutdown_when_available(vid: u16, pid: u16) -> Result<u8> {
    let started = std::time::Instant::now();
    let mut last_error = None;

    while started.elapsed() < RESET_RETRY_TIMEOUT {
        match with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
            let identification =
                send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
            let app = parse_nokv_app_type(&identification)?;
            ensure_shutdown_supported_app(app)?;
            send_raw_command_expect_echo(handle, endpoints.out_addr, endpoints.in_addr, b"NOKZ")?;
            Ok(app)
        }) {
            Ok(app) => return Ok(app),
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(DEVICE_POLL_INTERVAL);
            }
        }
    }

    match last_error {
        Some(err) => Err(err).context("timed out waiting for shutdown-capable app after NOKA"),
        None => bail!("timed out waiting for shutdown-capable app after NOKA"),
    }
}

fn switch_flash(vid: u16, pid: u16, wait: bool) -> Result<()> {
    with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_void_command(handle, endpoints.out_addr, b"NOKS")
    })?;

    println!("sent switch-to-FlashApp command (NOKS)");

    Ok(())
}

fn switch_phone_info(vid: u16, pid: u16, wait: bool) -> Result<()> {
    with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_void_command(handle, endpoints.out_addr, b"NOKP")
    })?;

    println!("sent switch-to-PhoneInfoApp command (NOKP)");

    Ok(())
}

fn param_read(vid: u16, pid: u16, wait: bool, debug: bool, name: &str) -> Result<()> {
    ensure!(
        name.len() <= 4,
        "parameter name must be at most 4 ASCII bytes"
    );
    ensure!(name.is_ascii(), "parameter name must be ASCII");

    let request = make_read_param_request(name);
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, &request)
    })?;

    let value = parse_param_response(&response)?;

    if debug {
        print_raw_response(&response);
    }

    println!("param: {name}");
    println!("length: {} bytes", value.len());

    if debug {
        println!("hex: {}", hex_dump(value));
    }

    if let Some(text) = ascii_param_value(value) {
        println!("ascii: {text}");
    }

    print_known_param_decode(name, value);

    Ok(())
}

fn phone_info_read(vid: u16, pid: u16, wait: bool, debug: bool, name: &str) -> Result<()> {
    ensure!(
        name.len() <= 4,
        "variable name must be at most 4 ASCII bytes"
    );
    ensure!(name.is_ascii(), "variable name must be ASCII");

    let request = make_phone_info_read_request(name);
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        let identification =
            send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
        ensure_active_app(&identification, 3, "PhoneInfoApp", "phone-info read")?;
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, &request)
    })?;

    let value = parse_phone_info_response(&response)?;

    if debug {
        print_raw_response(&response);
    }

    println!("variable: {name}");
    println!("length: {} bytes", value.len());

    if debug {
        println!("hex: {}", hex_dump(value));
    }

    if let Some(text) = ascii_param_value(value) {
        println!("ascii: {text}");
    }

    Ok(())
}

fn gpt_dump(vid: u16, pid: u16, wait: bool, format: GptDumpFormat) -> Result<()> {
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKT")
    })?;

    ensure!(
        response.len() >= 8,
        "NOKT response too short: {} bytes",
        response.len()
    );

    if &response[..4] == b"NOKU" {
        bail!("device reported NOKT as unsupported");
    }

    ensure!(
        &response[..4] == b"NOKT",
        "unexpected NOKT response signature: {}",
        ascii_dump(&response[..response.len().min(4)])
    );

    let error = u16::from_be_bytes([response[6], response[7]]);
    ensure!(error == 0, "NOKT failed with error 0x{error:04x}");

    let gpt = response
        .get(8..)
        .context("NOKT response does not contain a GPT payload")?;

    match format {
        GptDumpFormat::Text => print_gpt(gpt),
        GptDumpFormat::RawHex => {
            println!("{}", hex_dump(gpt));
            Ok(())
        }
    }
}

fn with_device<T>(
    vid: u16,
    pid: u16,
    wait: bool,
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &Endpoints) -> Result<T>,
) -> Result<T> {
    with_device_release_policy(vid, pid, wait, false, f)
}

fn with_device_allow_release_disconnect<T>(
    vid: u16,
    pid: u16,
    wait: bool,
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &Endpoints) -> Result<T>,
) -> Result<T> {
    with_device_release_policy(vid, pid, wait, true, f)
}

fn with_device_release_policy<T>(
    vid: u16,
    pid: u16,
    wait: bool,
    allow_release_disconnect: bool,
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &Endpoints) -> Result<T>,
) -> Result<T> {
    let (device, mut handle) = open_device(vid, pid, wait)?;
    let endpoints = find_bulk_endpoints(&device)?;

    if handle
        .kernel_driver_active(endpoints.interface)
        .unwrap_or(false)
    {
        handle
            .detach_kernel_driver(endpoints.interface)
            .with_context(|| {
                format!(
                    "failed to detach kernel driver from interface {}",
                    endpoints.interface
                )
            })?;
    }

    handle
        .claim_interface(endpoints.interface)
        .with_context(|| format!("failed to claim interface {}", endpoints.interface))?;

    let result = f(&mut handle, &endpoints);

    match handle.release_interface(endpoints.interface) {
        Ok(()) => {}
        Err(rusb::Error::NoDevice) if allow_release_disconnect => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to release interface {}", endpoints.interface));
        }
    }

    result
}

fn open_device(
    vid: u16,
    pid: u16,
    wait: bool,
) -> Result<(Device<GlobalContext>, DeviceHandle<GlobalContext>)> {
    loop {
        if let Some(device) = find_device(vid, pid)? {
            let handle = match device.open() {
                Ok(handle) => handle,
                Err(err) if wait => {
                    eprintln!(
                        "found USB device {vid:04x}:{pid:04x}, but opening failed: {err}; waiting..."
                    );
                    std::thread::sleep(DEVICE_POLL_INTERVAL);
                    continue;
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("failed to open USB device {vid:04x}:{pid:04x}"));
                }
            };

            return Ok((device, handle));
        }

        if !wait {
            bail!("USB device {vid:04x}:{pid:04x} not found");
        }

        std::thread::sleep(DEVICE_POLL_INTERVAL);
    }
}

fn find_device(vid: u16, pid: u16) -> Result<Option<Device<GlobalContext>>> {
    let devices = rusb::devices().context("failed to list USB devices")?;

    for device in devices.iter() {
        let descriptor = device
            .device_descriptor()
            .context("failed to read USB device descriptor")?;
        if descriptor.vendor_id() == vid && descriptor.product_id() == pid {
            return Ok(Some(device));
        }
    }

    Ok(None)
}

fn find_bulk_endpoints<T: UsbContext>(device: &Device<T>) -> Result<Endpoints> {
    let config = device
        .active_config_descriptor()
        .context("failed to read active USB config descriptor")?;

    for interface in config.interfaces() {
        for descriptor in interface.descriptors() {
            let mut in_addr = None;
            let mut out_addr = None;

            for endpoint in descriptor.endpoint_descriptors() {
                if endpoint.transfer_type() != TransferType::Bulk {
                    continue;
                }

                match endpoint.direction() {
                    Direction::In => in_addr = Some(endpoint.address()),
                    Direction::Out => out_addr = Some(endpoint.address()),
                }
            }

            if let (Some(in_addr), Some(out_addr)) = (in_addr, out_addr) {
                return Ok(Endpoints {
                    interface: descriptor.interface_number(),
                    in_addr,
                    out_addr,
                });
            }
        }
    }

    Err(anyhow!(
        "no interface with bulk IN and bulk OUT endpoints found"
    ))
}

fn send_raw_command(
    handle: &mut DeviceHandle<GlobalContext>,
    out_addr: u8,
    in_addr: u8,
    command: &[u8],
) -> Result<Vec<u8>> {
    let written = handle
        .write_bulk(out_addr, command, DEFAULT_TIMEOUT)
        .with_context(|| format!("failed to write to bulk OUT endpoint 0x{out_addr:02x}"))?;

    if written != command.len() {
        bail!(
            "short USB write: wrote {written} of {} bytes",
            command.len()
        );
    }

    let mut buffer = vec![0; 0x8000];
    let read = handle
        .read_bulk(in_addr, &mut buffer, DEFAULT_TIMEOUT)
        .with_context(|| format!("failed to read from bulk IN endpoint 0x{in_addr:02x}"))?;
    buffer.truncate(read);

    Ok(buffer)
}

fn send_raw_void_command(
    handle: &mut DeviceHandle<GlobalContext>,
    out_addr: u8,
    command: &[u8],
) -> Result<()> {
    let written = handle
        .write_bulk(out_addr, command, DEFAULT_TIMEOUT)
        .with_context(|| format!("failed to write to bulk OUT endpoint 0x{out_addr:02x}"))?;

    if written != command.len() {
        bail!(
            "short USB write: wrote {written} of {} bytes",
            command.len()
        );
    }

    Ok(())
}

fn send_raw_command_expect_echo(
    handle: &mut DeviceHandle<GlobalContext>,
    out_addr: u8,
    in_addr: u8,
    command: &[u8],
) -> Result<()> {
    let response = send_raw_command(handle, out_addr, in_addr, command)?;
    ensure!(
        response == command,
        "unexpected {} response: {}",
        String::from_utf8_lossy(command),
        hex_dump(&response)
    );

    Ok(())
}

fn send_raw_command_allow_disconnect(
    handle: &mut DeviceHandle<GlobalContext>,
    out_addr: u8,
    in_addr: u8,
    command: &[u8],
) -> Result<bool> {
    let written = handle
        .write_bulk(out_addr, command, DEFAULT_TIMEOUT)
        .with_context(|| format!("failed to write to bulk OUT endpoint 0x{out_addr:02x}"))?;

    if written != command.len() {
        bail!(
            "short USB write: wrote {written} of {} bytes",
            command.len()
        );
    }

    let mut buffer = vec![0; 0x8000];
    let read = match handle.read_bulk(in_addr, &mut buffer, DEFAULT_TIMEOUT) {
        Ok(read) => read,
        Err(rusb::Error::Io | rusb::Error::NoDevice) => return Ok(false),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read from bulk IN endpoint 0x{in_addr:02x}"));
        }
    };
    buffer.truncate(read);

    ensure!(
        buffer == command,
        "unexpected {} response: {}",
        String::from_utf8_lossy(command),
        hex_dump(&buffer)
    );

    Ok(true)
}

fn make_read_param_request(name: &str) -> Vec<u8> {
    let mut request = vec![0; 0x0b];
    request[..6].copy_from_slice(b"NOKXFR");
    request[7..7 + name.len()].copy_from_slice(name.as_bytes());
    request
}

fn parse_param_response(response: &[u8]) -> Result<&[u8]> {
    ensure!(
        response.len() >= 0x10,
        "parameter response too short: {} bytes",
        response.len()
    );

    if response.len() >= 4 && &response[..4] == b"NOKU" {
        bail!("device reported NOKXFR as unsupported");
    }

    ensure!(
        response.len() >= 6 && &response[..6] == b"NOKXFR",
        "unexpected parameter response signature: {}",
        ascii_dump(&response[..response.len().min(6)])
    );

    let value_len = response[0x10] as usize;
    let value_offset = 0x11;
    let value_end = value_offset + value_len;
    ensure!(
        response.len() >= value_end,
        "parameter response truncated: value length {value_len}, response length {}",
        response.len()
    );

    Ok(&response[value_offset..value_end])
}

fn make_phone_info_read_request(name: &str) -> Vec<u8> {
    let mut request = vec![0; 16];
    request[..6].copy_from_slice(b"NOKXPH");
    request[6..6 + name.len()].copy_from_slice(name.as_bytes());
    request[6 + name.len()] = 0;
    request
}

fn parse_phone_info_response(response: &[u8]) -> Result<&[u8]> {
    ensure!(
        response.len() >= 8,
        "PhoneInfo response too short: {} bytes",
        response.len()
    );

    if response.len() >= 4 && &response[..4] == b"NOKU" {
        bail!("device reported NOKXPH as unsupported");
    }

    ensure!(
        response.len() >= 6 && &response[..6] == b"NOKXPH",
        "unexpected PhoneInfo response signature: {}",
        ascii_dump(&response[..response.len().min(6)])
    );

    let value_len = u16::from_be_bytes([response[6], response[7]]) as usize;
    let value_offset = 8;
    let value_end = value_offset + value_len;
    ensure!(
        response.len() >= value_end,
        "PhoneInfo response truncated: value length {value_len}, response length {}",
        response.len()
    );

    Ok(&response[value_offset..value_end])
}

fn ensure_active_app(
    response: &[u8],
    expected_app: u8,
    expected_name: &str,
    command_name: &str,
) -> Result<()> {
    let app = parse_nokv_app_type(response)
        .with_context(|| format!("failed to identify active app before running {command_name}"))?;

    ensure!(
        app == expected_app,
        "{command_name} requires {expected_name}, but NOKV reports app type {} ({}). Run `lp-externals switch phone-info`, wait for USB re-enumeration, then retry.",
        app,
        app_type_name(app)
    );

    Ok(())
}

fn ensure_reset_supported_app(app: u8) -> Result<()> {
    ensure!(
        matches!(app, 1 | 2),
        "reset requires BootManager or FlashApp after PhoneInfoApp escape, but NOKV reports app type {} ({})",
        app,
        app_type_name(app)
    );

    Ok(())
}

fn ensure_shutdown_supported_app(app: u8) -> Result<()> {
    ensure!(
        matches!(app, 1 | 2),
        "shutdown requires BootManager or FlashApp after PhoneInfoApp escape, but NOKV reports app type {} ({})",
        app,
        app_type_name(app)
    );

    Ok(())
}

fn parse_nokv_app_type(response: &[u8]) -> Result<u8> {
    ensure!(
        response.len() >= 6,
        "NOKV response too short: {} bytes",
        response.len()
    );

    if &response[..4] == b"NOKU" {
        bail!("device reported NOKV as unsupported");
    }

    ensure!(
        &response[..4] == b"NOKV",
        "unexpected NOKV response signature: {}",
        ascii_dump(&response[..response.len().min(4)])
    );

    Ok(response[5])
}

fn ascii_param_value(value: &[u8]) -> Option<String> {
    if value.is_empty() {
        return None;
    }

    if value
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ' || *byte == 0)
    {
        let text = ascii_lossy(value).trim_matches([' ', '\0']).to_string();
        if !text.is_empty() {
            return Some(text);
        }
    }

    None
}

fn print_known_param_decode(name: &str, value: &[u8]) {
    match name {
        "FAI" if value.len() >= 6 => {
            println!("flash protocol: {}.{}", value[1], value[2]);
            println!("flash app: {}.{}", value[3], value[4]);
        }
        "FCS" if value.len() == 4 => {
            let flags = u32::from_be_bytes(value.try_into().unwrap());
            println!("security flags: 0x{flags:08x}");
        }
        "SS" if value.len() >= 8 => {
            println!("is test device: {}", value[0]);
            println!("platform secure boot: {}", value[1] != 0);
            println!("secure FFU efuse: {}", value[2] != 0);
            println!("debug: {}", value[3] != 0);
            println!("RDC: {}", value[4] != 0);
            println!("authenticated: {}", value[5] != 0);
            println!("UEFI secure boot: {}", value[6] != 0);
            println!("crypto hardware key: {}", value[7] != 0);
        }
        _ => {}
    }
}

#[derive(Debug, Deserialize)]
struct LumiaDbDevice {
    #[serde(rename = "hardwareModel")]
    hardware_model: String,
    #[serde(rename = "phoneModel")]
    phone_model: String,
    #[serde(default)]
    variant: String,
    #[serde(rename = "productCodes", default)]
    product_codes: Vec<String>,
    #[serde(default)]
    firmwares: Vec<LumiaDbFirmware>,
}

impl LumiaDbDevice {
    fn matches(&self, query: &str) -> bool {
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
struct LumiaDbFirmware {
    #[serde(rename = "packageTitle", default)]
    package_title: String,
    #[serde(default)]
    firmware: String,
    #[serde(default)]
    os: Option<String>,
    #[serde(rename = "productCode", default)]
    product_code: String,
    #[serde(rename = "ffuFilename")]
    ffu_filename: String,
}

impl LumiaDbFirmware {
    fn matches(&self, query: &str) -> bool {
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

struct LumiaDbPlan<'a> {
    device: &'a LumiaDbDevice,
    firmware: &'a LumiaDbFirmware,
    ffu_url: String,
    emergency_url: String,
    sbl3_url: String,
}

impl LumiaDbPlan<'_> {
    fn blobs(&self) -> Vec<PlannedBlob> {
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

    fn manifest_json(&self) -> String {
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

struct PlannedBlob {
    kind: &'static str,
    url: String,
    filename: String,
}

struct QcomSource {
    format: &'static str,
    bytes: Vec<u8>,
}

struct QcomCandidate {
    name: String,
    format: &'static str,
    bytes: Vec<u8>,
}

struct QualcommImage {
    header_type: &'static str,
    image_offset: u32,
    header_offset: u32,
    image_address: u32,
    image_size: u32,
    code_size: u32,
    signature_address: u32,
    signature_size: u32,
    certificates_address: u32,
    certificates_size: u32,
    root_key_hash: Option<Vec<u8>>,
}

impl QualcommImage {
    fn parse(bytes: &[u8], offset: u32) -> Result<Self> {
        let mut image_offset = offset;
        let header_offset;
        let header_type;

        if bytes.get(offset as usize..offset as usize + 4) == Some(b"\x7fELF") {
            header_type = "elf";
            let elf_class = *bytes
                .get(offset as usize + 4)
                .context("ELF header missing class")?;
            if elf_class == 1 {
                let program_header_offset = offset
                    .checked_add(le_u32(bytes, offset as usize + 0x1c)?)
                    .context("ELF program header offset overflow")?;
                let program_header_entry_size = le_u16(bytes, offset as usize + 0x2a)? as u32;
                let hash_program_header_offset = program_header_offset
                    .checked_add(program_header_entry_size)
                    .context("ELF hash program header offset overflow")?;
                image_offset = offset
                    .checked_add(le_u32(bytes, hash_program_header_offset as usize + 0x04)?)
                    .context("ELF image offset overflow")?;
                header_offset = image_offset
                    .checked_add(8)
                    .context("Qualcomm header offset overflow")?;
            } else if elf_class == 2 {
                let program_header_offset = offset
                    .checked_add(le_u32(bytes, offset as usize + 0x20)?)
                    .context("ELF program header offset overflow")?;
                let program_header_entry_size = le_u16(bytes, offset as usize + 0x36)? as u32;
                let hash_program_header_offset = program_header_offset
                    .checked_add(program_header_entry_size)
                    .context("ELF hash program header offset overflow")?;
                image_offset = offset
                    .checked_add(
                        u32::try_from(le_u64(bytes, hash_program_header_offset as usize + 0x08)?)
                            .context("ELF image offset does not fit in u32")?,
                    )
                    .context("ELF image offset overflow")?;
                header_offset = image_offset
                    .checked_add(8)
                    .context("Qualcomm header offset overflow")?;
            } else {
                bail!("unsupported ELF class {elf_class}");
            }
        } else if find_masked_pattern(
            bytes,
            offset as usize,
            LONG_QCOM_HEADER_PATTERN,
            LONG_QCOM_HEADER_MASK,
        )
        .is_none()
        {
            header_type = "short";
            header_offset = image_offset
                .checked_add(8)
                .context("Qualcomm header offset overflow")?;
        } else {
            header_type = "long";
            header_offset = image_offset
                .checked_add(LONG_QCOM_HEADER_PATTERN.len() as u32)
                .context("Qualcomm header offset overflow")?;
        }

        let header = header_offset as usize;
        let explicit_image_offset = le_u32(bytes, header)?;
        if explicit_image_offset != 0 {
            image_offset = explicit_image_offset;
        } else if header_type == "short" || header_type == "elf" {
            image_offset = image_offset
                .checked_add(0x28)
                .context("Qualcomm short image offset overflow")?;
        } else {
            image_offset = image_offset
                .checked_add(0x50)
                .context("Qualcomm long image offset overflow")?;
        }

        let image_address = le_u32(bytes, header + 0x04)?;
        let image_size = le_u32(bytes, header + 0x08)?;
        let code_size = le_u32(bytes, header + 0x0c)?;
        let signature_address = le_u32(bytes, header + 0x10)?;
        let signature_size = le_u32(bytes, header + 0x14)?;
        let certificates_address = le_u32(bytes, header + 0x18)?;
        let certificates_size = le_u32(bytes, header + 0x1c)?;
        let root_key_hash = extract_root_key_hash(bytes);

        Ok(Self {
            header_type,
            image_offset,
            header_offset,
            image_address,
            image_size,
            code_size,
            signature_address,
            signature_size,
            certificates_address,
            certificates_size,
            root_key_hash,
        })
    }
}

const LONG_QCOM_HEADER_PATTERN: &[u8] = &[
    0xd1, 0xdc, 0x4b, 0x84, 0x34, 0x10, 0xd7, 0x73, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
];

const LONG_QCOM_HEADER_MASK: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

fn fetch_lumiadb_database() -> Result<Vec<LumiaDbDevice>> {
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

fn read_qcom_source(path: &Path) -> Result<QcomSource> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("hex"))
    {
        return Ok(QcomSource {
            format: "intel-hex",
            bytes: parse_intel_hex(&bytes)
                .with_context(|| format!("failed to parse Intel HEX {}", path.display()))?,
        });
    }

    Ok(QcomSource {
        format: "raw",
        bytes,
    })
}

fn read_qcom_candidates(path: &Path) -> Result<Vec<QcomCandidate>> {
    if path.is_dir() {
        let mut candidates = Vec::new();
        for entry in
            fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let source = read_qcom_source(&path)?;
                candidates.push(QcomCandidate {
                    name: path.display().to_string(),
                    format: source.format,
                    bytes: source.bytes,
                });
            }
        }
        return Ok(candidates);
    }

    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
    {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let mut archive = ZipArchive::new(Cursor::new(bytes))
            .with_context(|| format!("failed to open zip {}", path.display()))?;
        let mut candidates = Vec::new();

        for index in 0..archive.len() {
            let mut file = archive.by_index(index)?;
            if !file.is_file() {
                continue;
            }

            let name = file.name().to_string();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .with_context(|| format!("failed to read {name} from {}", path.display()))?;
            let (format, bytes) = if name
                .rsplit_once('.')
                .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("hex"))
            {
                ("intel-hex", parse_intel_hex(&bytes)?)
            } else {
                ("raw", bytes)
            };

            candidates.push(QcomCandidate {
                name,
                format,
                bytes,
            });
        }

        return Ok(candidates);
    }

    let source = read_qcom_source(path)?;
    Ok(vec![QcomCandidate {
        name: path.display().to_string(),
        format: source.format,
        bytes: source.bytes,
    }])
}

fn parse_intel_hex(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).context("Intel HEX is not valid UTF-8")?;
    let mut result = Vec::new();

    for (line_number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        ensure!(
            line.starts_with(':'),
            "Intel HEX line {} missing ':'",
            line_number + 1
        );
        let record = parse_hex_bytes(&line[1..])?;
        ensure!(
            record.len() >= 5,
            "Intel HEX line {} too short",
            line_number + 1
        );
        let byte_count = record[0] as usize;
        ensure!(
            record.len() == byte_count + 5,
            "Intel HEX line {} length mismatch",
            line_number + 1
        );

        if record[3] == 0 {
            result.extend_from_slice(&record[4..4 + byte_count]);
        }
    }

    Ok(result)
}

fn extract_root_key_hash(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut signatures = Vec::new();
    let mut last_offset = 0usize;

    for index in 0..bytes.len().saturating_sub(6) {
        let offset0 = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
        let offset1 = i16::from_be_bytes([bytes[index + 2], bytes[index + 3]]);
        let offset2 = u16::from_le_bytes([bytes[index + 4], bytes[index + 5]]);

        if offset0 == 0x8230 && offset1 >= 0 && offset2 == 0x8230 {
            let certificate_size = offset1 as usize + 4;
            if last_offset != 0 && last_offset != index {
                break;
            }
            let end = index.checked_add(certificate_size)?;
            let certificate = bytes.get(index..end)?;
            signatures.push(certificate.to_vec());
            last_offset = end;
        }
    }

    signatures.last().map(|root| Sha256::digest(root).to_vec())
}

fn print_qcom_image(image: &QualcommImage) {
    println!("header type: {}", image.header_type);
    println!("image offset: 0x{:08x}", image.image_offset);
    println!("header offset: 0x{:08x}", image.header_offset);
    println!("image address: 0x{:08x}", image.image_address);
    println!("image size: {}", image.image_size);
    println!("code size: {}", image.code_size);
    println!("signature address: 0x{:08x}", image.signature_address);
    println!("signature size: {}", image.signature_size);
    println!("certificates address: 0x{:08x}", image.certificates_address);
    println!("certificates size: {}", image.certificates_size);
    if let Some(root_key_hash) = &image.root_key_hash {
        println!("root key hash: {}", hex_dump_compact(root_key_hash));
    } else {
        println!("root key hash: none");
    }
}

fn contains_utf16le(bytes: &[u8], needle: &str) -> bool {
    let encoded = needle
        .encode_utf16()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    find_bytes(bytes, &encoded).is_some()
}

fn find_masked_pattern(
    haystack: &[u8],
    offset: usize,
    pattern: &[u8],
    mask: &[u8],
) -> Option<usize> {
    if pattern.len() != mask.len() || offset >= haystack.len() || haystack.len() < pattern.len() {
        return None;
    }

    (offset..=haystack.len() - pattern.len()).find(|candidate| {
        pattern.iter().enumerate().all(|(index, expected)| {
            mask[index] == 0xff || haystack[candidate + index] == *expected
        })
    })
}

fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent("lp-externals/0.1")
        .build()
        .context("failed to build HTTP client")
}

async fn download_file(url: &str, path: &Path) -> Result<()> {
    if path.exists() {
        println!("exists: {}", path.display());
        return Ok(());
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

struct ParsedFfu {
    bytes: Vec<u8>,
    file_size: u64,
    chunk_size: usize,
    platform_id: String,
    security_header_len: usize,
    image_header_len: usize,
    store_header_len: usize,
    header_size: usize,
    payload_size: u64,
    total_chunk_count: u64,
    chunk_indexes: Vec<Option<usize>>,
}

impl ParsedFfu {
    fn open(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let file_size = u64::try_from(bytes.len()).context("FFU too large")?;

        ensure!(bytes.len() >= 0x20, "FFU too short");
        ensure!(
            bytes.get(0x04..0x10) == Some(b"SignedImage "),
            "missing SignedImage header"
        );

        let chunk_size = le_u32(&bytes, 0x10)? as usize * 1024;
        ensure!(chunk_size != 0, "invalid zero chunk size");
        let security_header_size = le_u32(&bytes, 0x00)? as usize;
        let catalog_size = le_u32(&bytes, 0x18)? as usize;
        let hash_table_size = le_u32(&bytes, 0x1c)? as usize;
        let security_header_len = round_up_to_chunk(
            security_header_size + catalog_size + hash_table_size,
            chunk_size,
        );

        ensure!(
            bytes.len() >= security_header_len + 0x1c,
            "FFU too short for image header"
        );
        ensure!(
            bytes.get(security_header_len + 0x04..security_header_len + 0x10)
                == Some(b"ImageFlash  "),
            "missing ImageFlash header"
        );
        let image_header_size = le_u32(&bytes, security_header_len)? as usize;
        let manifest_size = le_u32(&bytes, security_header_len + 0x10)? as usize;
        let image_header_len = round_up_to_chunk(image_header_size + manifest_size, chunk_size);

        let store_offset = security_header_len + image_header_len;
        ensure!(
            bytes.len() >= store_offset + 248,
            "FFU too short for store header"
        );
        let platform_id = ascii_lossy(&bytes[store_offset + 0x0c..store_offset + 0x0c + 192])
            .trim_matches(['\0', ' '])
            .to_string();
        let write_descriptor_count = le_u32(&bytes, store_offset + 208)? as usize;
        let write_descriptor_len = le_u32(&bytes, store_offset + 212)? as usize;
        let validate_descriptor_len = le_u32(&bytes, store_offset + 220)? as usize;
        let store_header_len = round_up_to_chunk(
            248 + write_descriptor_len + validate_descriptor_len,
            chunk_size,
        );
        ensure!(
            bytes.len() >= store_offset + store_header_len,
            "FFU too short for full store header"
        );

        let store = &bytes[store_offset..store_offset + store_header_len];
        let mut highest_chunk_index = 0usize;
        let mut entry_offset = 248 + validate_descriptor_len;
        let mut total_chunk_count = 0usize;

        for _ in 0..write_descriptor_count {
            let location_count = le_u32(store, entry_offset)? as usize;
            let chunk_count = le_u32(store, entry_offset + 4)? as usize;

            for index in 0..location_count {
                let location_offset = entry_offset + 8 + index * 8;
                let disk_access_method = le_u32(store, location_offset)?;
                let chunk_index = le_u32(store, location_offset + 4)? as usize;

                if disk_access_method == 0 && chunk_count > 0 {
                    highest_chunk_index = highest_chunk_index.max(chunk_index + chunk_count - 1);
                }
            }

            entry_offset += 8 + location_count * 8;
            total_chunk_count += chunk_count;
        }

        let mut chunk_indexes = vec![None; highest_chunk_index + 1];
        entry_offset = 248 + validate_descriptor_len;
        let mut ffu_chunk_index = 0usize;

        for _ in 0..write_descriptor_count {
            let location_count = le_u32(store, entry_offset)? as usize;
            let chunk_count = le_u32(store, entry_offset + 4)? as usize;

            for index in 0..location_count {
                let location_offset = entry_offset + 8 + index * 8;
                let disk_access_method = le_u32(store, location_offset)?;
                let chunk_index = le_u32(store, location_offset + 4)? as usize;

                if disk_access_method == 0 {
                    for chunk_offset in 0..chunk_count {
                        chunk_indexes[chunk_index + chunk_offset] =
                            Some(ffu_chunk_index + chunk_offset);
                    }
                }
            }

            entry_offset += 8 + location_count * 8;
            ffu_chunk_index += chunk_count;
        }

        let header_size = security_header_len + image_header_len + store_header_len;
        let payload_size = (total_chunk_count as u64) * (chunk_size as u64);
        let expected_size = header_size as u64 + payload_size;
        ensure!(
            expected_size == file_size,
            "bad FFU size: expected {expected_size}, actual {file_size}"
        );

        Ok(Self {
            bytes,
            file_size,
            chunk_size,
            platform_id,
            security_header_len,
            image_header_len,
            store_header_len,
            header_size,
            payload_size,
            total_chunk_count: total_chunk_count as u64,
            chunk_indexes,
        })
    }

    fn get_sectors(&self, start_sector: usize, sector_count: usize) -> Result<Vec<u8>> {
        let start = start_sector * 0x200;
        let size = sector_count * 0x200;
        let mut result = vec![0; size];
        let sectors_per_chunk = self.chunk_size / 0x200;

        ensure!(sectors_per_chunk != 0, "invalid sectors per chunk");

        let first_chunk = start_sector / sectors_per_chunk;
        let last_sector = start_sector + sector_count - 1;
        let last_chunk = last_sector / sectors_per_chunk;

        for chunk_index in first_chunk..=last_chunk {
            let Some(Some(ffu_chunk_index)) = self.chunk_indexes.get(chunk_index) else {
                continue;
            };
            let source_offset = self.header_size + ffu_chunk_index * self.chunk_size;
            let target_chunk_start = chunk_index * self.chunk_size;
            let copy_start = start.max(target_chunk_start);
            let copy_end = (start + size).min(target_chunk_start + self.chunk_size);

            if copy_start >= copy_end {
                continue;
            }

            let source_start = source_offset + (copy_start - target_chunk_start);
            let source_end = source_start + (copy_end - copy_start);
            let target_start = copy_start - start;
            let target_end = target_start + (copy_end - copy_start);

            result[target_start..target_end].copy_from_slice(&self.bytes[source_start..source_end]);
        }

        Ok(result)
    }

    fn get_partition(&self, name: &str) -> Result<Vec<u8>> {
        let gpt_bytes = self.get_sectors(1, 0x21)?;
        let gpt = ParsedGpt::parse(&gpt_bytes)?;
        let partition = gpt
            .partition(name)
            .with_context(|| format!("FFU does not contain partition {name}"))?;
        let sector_count = partition
            .last_lba
            .checked_sub(partition.first_lba)
            .and_then(|sectors| sectors.checked_add(1))
            .context("partition sector range underflow")?;
        let start_sector = usize::try_from(partition.first_lba)
            .context("partition start sector does not fit in usize")?;
        let sector_count =
            usize::try_from(sector_count).context("partition size does not fit in usize")?;

        self.get_sectors(start_sector, sector_count)
    }
}

struct ParsedGpt {
    partitions: Vec<GptPartition>,
}

impl ParsedGpt {
    fn parse(gpt: &[u8]) -> Result<Self> {
        let layout = GptLayout::parse(gpt)?;
        let mut partitions = Vec::new();

        for index in 0..layout.partition_entry_count {
            let offset = layout
                .entries_offset
                .checked_add(
                    usize::try_from(index)
                        .context("partition index does not fit in usize")?
                        .checked_mul(layout.entry_size)
                        .context("partition entry offset overflow")?,
                )
                .context("partition entry offset overflow")?;
            let Some(entry) = gpt.get(offset..offset + layout.entry_size) else {
                break;
            };

            if entry[..16].iter().all(|byte| *byte == 0) {
                continue;
            }

            partitions.push(GptPartition {
                index: index + 1,
                type_guid: format_guid(&entry[0..16]),
                unique_guid: format_guid(&entry[16..32]),
                first_lba: le_u64(entry, 32)?,
                last_lba: le_u64(entry, 40)?,
                attrs: le_u64(entry, 48)?,
                name: decode_utf16_name(&entry[56..128]),
            });
        }

        Ok(Self { partitions })
    }

    fn partition(&self, name: &str) -> Option<&GptPartition> {
        self.partitions
            .iter()
            .find(|partition| partition.name.eq_ignore_ascii_case(name))
    }
}

struct GptLayout {
    header_offset: usize,
    header_size: u32,
    revision: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: String,
    partition_entries_lba: u64,
    partition_entry_count: u32,
    entry_size: usize,
    entries_offset: usize,
}

impl GptLayout {
    fn parse(gpt: &[u8]) -> Result<Self> {
        ensure!(
            gpt.len() >= 0x200,
            "GPT payload too short: {} bytes",
            gpt.len()
        );

        let header_offset = find_bytes(gpt, b"EFI PART").context("missing GPT header signature")?;
        let header = gpt
            .get(header_offset..)
            .context("GPT payload missing primary header")?;

        ensure!(header.len() >= 92, "GPT header too short");

        let revision = le_u32(header, 8)?;
        let header_size = le_u32(header, 12)?;
        let current_lba = le_u64(header, 24)?;
        let backup_lba = le_u64(header, 32)?;
        let first_usable_lba = le_u64(header, 40)?;
        let last_usable_lba = le_u64(header, 48)?;
        let disk_guid = format_guid(&header[56..72]);
        let partition_entries_lba = le_u64(header, 72)?;
        let partition_entry_count = le_u32(header, 80)?;
        let partition_entry_size = le_u32(header, 84)?;
        let entry_size = usize::try_from(partition_entry_size)
            .context("partition entry size does not fit in usize")?;
        ensure!(
            entry_size >= 128,
            "unsupported GPT entry size: {entry_size}"
        );
        ensure!(
            partition_entries_lba >= current_lba,
            "partition entries precede GPT header"
        );

        let entries_offset = header_offset
            .checked_add(
                usize::try_from(partition_entries_lba - current_lba)
                    .context("partition entries relative LBA does not fit in usize")?
                    .checked_mul(512)
                    .context("partition entries offset overflow")?,
            )
            .context("partition entries offset overflow")?;

        Ok(Self {
            header_offset,
            header_size,
            revision,
            current_lba,
            backup_lba,
            first_usable_lba,
            last_usable_lba,
            disk_guid,
            partition_entries_lba,
            partition_entry_count,
            entry_size,
            entries_offset,
        })
    }
}

struct GptPartition {
    index: u32,
    type_guid: String,
    unique_guid: String,
    first_lba: u64,
    last_lba: u64,
    attrs: u64,
    name: String,
}

fn round_up_to_chunk(size: usize, chunk_size: usize) -> usize {
    size.div_ceil(chunk_size) * chunk_size
}

fn make_lumiadb_plan<'a>(
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

fn print_lumiadb_plan(plan: &LumiaDbPlan<'_>) {
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

fn print_identification(response: &[u8], debug: bool) {
    if debug {
        print_raw_response(response);
    }

    if response.len() < 6 {
        println!("response too short to decode NOKV app type");
        return;
    }

    let signature = ascii_lossy(&response[..response.len().min(4)]);
    println!("signature: {signature}");

    if &response[..4] == b"NOKU" {
        println!("device reported unsupported command");
        return;
    }

    if &response[..4] != b"NOKV" {
        println!("warning: expected NOKV response signature");
    }

    let app = response[5];
    println!("app type: {} ({})", app, app_type_name(app));

    if response.len() >= 10 {
        println!("protocol version: {}.{}", response[6], response[7]);
        println!("app version: {}.{}", response[8], response[9]);
    }

    match app {
        1 => print_bootmgr_subblocks(response),
        2 => print_flashapp_subblocks(response),
        3 => print_phone_info_subblocks(response),
        _ => {}
    }
}

fn print_raw_response(response: &[u8]) {
    println!("response length: {} bytes", response.len());
    println!("response hex: {}", hex_dump(response));
    println!("response ascii: {}", ascii_dump(response));
}

fn print_bootmgr_subblocks(response: &[u8]) {
    if response.len() < 11 {
        return;
    }

    let subblock_count = response[10];
    let mut offset = 11usize;
    println!("subblocks: {subblock_count}");

    for index in 0..subblock_count {
        if offset + 3 > response.len() {
            println!("subblock {index}: truncated header at offset {offset}");
            return;
        }

        let id = response[offset];
        let len = u16::from_be_bytes([response[offset + 1], response[offset + 2]]) as usize;
        let payload_offset = offset + 3;
        let next_offset = payload_offset + len;

        if next_offset > response.len() {
            println!("subblock {index}: id=0x{id:02x} truncated payload length={len}");
            return;
        }

        let payload = &response[payload_offset..next_offset];
        print!("subblock {index}: id=0x{id:02x} length={len}");

        match id {
            0x01 if payload.len() >= 4 => {
                let transfer_size =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                print!(" transfer_size={transfer_size}");
            }
            0x04 if payload.len() >= 4 => {
                print!(
                    " flash_protocol={}.{} flash_app={}.{}",
                    payload[0], payload[1], payload[2], payload[3]
                );
            }
            0x1f if !payload.is_empty() => {
                print!(" mmos_over_usb={}", payload[0] == 1);
            }
            0x20 => {
                print!(" crc_header_info");
            }
            _ => {}
        }

        println!();
        offset = next_offset;
    }
}

fn print_flashapp_subblocks(response: &[u8]) {
    if response.len() < 11 {
        return;
    }

    let subblock_count = response[10];
    let mut offset = 11usize;
    println!("subblocks: {subblock_count}");

    for index in 0..subblock_count {
        if offset + 3 > response.len() {
            println!("subblock {index}: truncated header at offset {offset}");
            return;
        }

        let id = response[offset];
        let len = u16::from_be_bytes([response[offset + 1], response[offset + 2]]) as usize;
        let payload_offset = offset + 3;
        let next_offset = payload_offset + len;

        if next_offset > response.len() {
            println!("subblock {index}: id=0x{id:02x} truncated payload length={len}");
            return;
        }

        let payload = &response[payload_offset..next_offset];
        print!("subblock {index}: id=0x{id:02x} length={len}");

        match id {
            0x01 if payload.len() >= 4 => {
                let transfer_size = be_u32_payload(payload);
                print!(" transfer_size={transfer_size}");
            }
            0x02 if payload.len() >= 4 => {
                let write_buffer_size = be_u32_payload(payload);
                print!(" write_buffer_size={write_buffer_size}");
            }
            0x03 if payload.len() >= 4 => {
                let emmc_sectors = be_u32_payload(payload);
                print!(" emmc_sectors={emmc_sectors}");
            }
            0x04 if payload.len() >= 4 => {
                let sd_sectors = be_u32_payload(payload);
                print!(" sd_sectors={sd_sectors}");
            }
            0x05 => {
                print!(
                    " platform_id={}",
                    ascii_lossy(payload).trim_matches([' ', '\0'])
                );
            }
            0x0d if payload.len() >= 2 => {
                print!(" async_support={}", payload[1] == 1);
            }
            0x0f if payload.len() >= 8 => {
                print!(
                    " security version={} platform_secure_boot={} secure_ffu={} jtag_disabled={} rdc_present={} authenticated={} uefi_secure_boot={} secondary_hardware_key={}",
                    payload[0],
                    payload[1] == 1,
                    payload[2] == 1,
                    payload[3] == 1,
                    payload[4] == 1,
                    payload[5] == 1 || payload[5] == 2,
                    payload[6] == 1,
                    payload[7] == 1
                );
            }
            0x10 if payload.len() >= 3 => {
                let mask = u16::from_be_bytes([payload[1], payload[2]]);
                print!(
                    " secure_ffu_protocol version={} mask=0x{mask:04x}",
                    payload[0]
                );
            }
            0x1f if !payload.is_empty() => {
                print!(" mmos_over_usb={}", payload[0] == 1);
            }
            0x20 => {
                print!(" crc_header_info");
            }
            _ => {}
        }

        println!();
        offset = next_offset;
    }
}

fn be_u32_payload(payload: &[u8]) -> u32 {
    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
}

fn print_phone_info_subblocks(response: &[u8]) {
    if response.len() < 11 {
        return;
    }

    let subblock_count = response[10];
    let mut offset = 11usize;
    println!("subblocks: {subblock_count}");

    for index in 0..subblock_count {
        if offset + 3 > response.len() {
            println!("subblock {index}: truncated header at offset {offset}");
            return;
        }

        let id = response[offset];
        let len = u16::from_be_bytes([response[offset + 1], response[offset + 2]]) as usize;
        let payload_offset = offset + 3;
        let next_offset = payload_offset + len;

        if next_offset > response.len() {
            println!("subblock {index}: id=0x{id:02x} truncated payload length={len}");
            return;
        }

        print!("subblock {index}: id=0x{id:02x} length={len}");
        if id == 0x20 {
            print!(" crc_header_info");
        }
        println!();

        offset = next_offset;
    }
}

fn print_gpt(gpt: &[u8]) -> Result<()> {
    let layout = GptLayout::parse(gpt)?;
    let parsed = ParsedGpt::parse(gpt)?;

    println!("GPT header");
    println!("  header offset: {}", layout.header_offset);
    println!("  revision: 0x{:08x}", layout.revision);
    println!("  header size: {}", layout.header_size);
    println!("  current lba: {}", layout.current_lba);
    println!("  backup lba: {}", layout.backup_lba);
    println!("  first usable lba: {}", layout.first_usable_lba);
    println!("  last usable lba: {}", layout.last_usable_lba);
    println!("  disk guid: {}", layout.disk_guid);
    println!("  partition entries lba: {}", layout.partition_entries_lba);
    println!("  partition entry count: {}", layout.partition_entry_count);
    println!("  partition entry size: {}", layout.entry_size);

    println!();
    println!("Partitions");

    for partition in &parsed.partitions {
        let sectors = partition
            .last_lba
            .saturating_sub(partition.first_lba)
            .saturating_add(1);

        println!(
            "  {:>3}: {:<36} first={} last={} sectors={} attrs=0x{:016x}",
            partition.index,
            partition.name,
            partition.first_lba,
            partition.last_lba,
            sectors,
            partition.attrs
        );
        println!("       type:   {}", partition.type_guid);
        println!("       unique: {}", partition.unique_guid);
    }

    if parsed.partitions.is_empty() {
        println!("  no populated partition entries found");
    }

    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let bytes = bytes
        .get(offset..offset + 4)
        .with_context(|| format!("missing u32 at offset {offset}"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let bytes = bytes
        .get(offset..offset + 2)
        .with_context(|| format!("missing u16 at offset {offset}"))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let bytes = bytes
        .get(offset..offset + 8)
        .with_context(|| format!("missing u64 at offset {offset}"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn format_guid(bytes: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn decode_utf16_name(bytes: &[u8]) -> String {
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();

    String::from_utf16_lossy(&words)
}

fn parse_u16(value: &str) -> Result<u16, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        value.parse::<u16>().map_err(|err| err.to_string())
    }
}

fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        value.parse::<u32>().map_err(|err| err.to_string())
    }
}

fn app_type_name(app: u8) -> &'static str {
    match app {
        1 => "BootManager",
        2 => "FlashApp",
        3 => "PhoneInfoApp",
        _ => "unknown",
    }
}

fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex_dump_compact(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    ensure!(value.len().is_multiple_of(2), "hex string has odd length");

    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .with_context(|| format!("invalid hex byte at offset {index}"))
        })
        .collect()
}

fn ascii_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn ascii_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

struct Endpoints {
    interface: u8,
    in_addr: u8,
    out_addr: u8,
}
