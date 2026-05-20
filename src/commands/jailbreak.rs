use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    edl::{self, EdlMode},
    ffu::FfuMetadata,
    flash::{
        read_flash_app_info, read_flash_param, soft_brick_with_ffu, validate_ffu_against_flash_app,
    },
    jailbreak::{JailbreakArtifacts, build_jailbreak_artifacts, print_write_plan},
    lumiadb::{
        cached_emergency_path, cached_ffu_path, cached_jailbreak_artifact_dir, cached_sbl3_path,
        download_file, fetch_lumiadb_database, make_exact_lumiadb_plan, print_lumiadb_plan,
    },
    qcom::{
        QcomCandidate, QualcommImage, contains_utf16le, extract_root_key_hash,
        matching_armprg_loaders, read_qcom_candidates,
    },
    uefi::{
        LumiaApp, ascii_param_value, identify_app, make_phone_info_read_request,
        parse_phone_info_response, require_app, send_raw_command,
        send_raw_command_allow_disconnect, switch_to_flash_app, switch_to_phone_info_app,
        with_device, with_device_allow_release_disconnect,
    },
    util::hex_dump_compact,
};

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const SECTOR_SIZE: u64 = 0x200;
const EDL_LOADER_ADDRESS: u32 = 0x2a000000;
const DETECT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Serialize, Deserialize)]
struct JailbreakManifest {
    schema_version: u32,
    product_type: String,
    product_code: String,
    masked_imei: String,
    rrkh: String,
    ffu: ManifestFile,
    emergency: ManifestFile,
    engineering_sbl3: ManifestFile,
    artifact_dir: String,
    loaders: Vec<ManifestLoader>,
    writes: Vec<ManifestWrite>,
    armprg: ArmprgQuirks,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestFile {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestLoader {
    name: String,
    format: String,
    size: usize,
    sha256: String,
    root_key_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestWrite {
    name: String,
    start_sector: u64,
    byte_len: u64,
    source_offset: u64,
    source: ManifestFile,
    operation: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ArmprgQuirks {
    partition: u8,
    chunk_size: u32,
    loader_address: u32,
    gpt_write_len: u64,
    winsecapp_limit: u64,
}

enum DetectedMode {
    Lumia(LumiaApp),
    Edl(EdlMode),
}

struct PhoneIdentity {
    product_type: String,
    product_code: String,
    imei: String,
}

pub(crate) fn prepare(vid: u16, pid: u16, wait: bool, manifest_path: &Path) -> Result<()> {
    let manifest_path = absolute_path(manifest_path)?;
    ensure_parent(&manifest_path)?;

    switch_to_phone_info_app(vid, pid, wait).context("failed to switch to PhoneInfoApp")?;
    let phone = read_phone_identity(vid, pid)?;
    println!("phone type: {}", phone.product_type);
    println!("product code: {}", phone.product_code);
    println!("imei: {}", mask_imei(&phone.imei));

    println!("fetching LumiaDB metadata");
    let database = fetch_lumiadb_database()?;
    let plan = make_exact_lumiadb_plan(&database, &phone.product_type, &phone.product_code)?;
    print_lumiadb_plan(&plan);

    let ffu_path = cached_ffu_path(&plan)?;
    let emergency_path = cached_emergency_path(&plan)?;
    let sbl3_path = cached_sbl3_path(&plan)?;
    ensure_parent(&ffu_path)?;
    ensure_parent(&emergency_path)?;
    ensure_parent(&sbl3_path)?;

    let runtime = tokio::runtime::Runtime::new().context("failed to create download runtime")?;
    runtime.block_on(download_file(&plan.ffu_url, &ffu_path))?;
    runtime.block_on(download_file(&plan.emergency_url, &emergency_path))?;
    runtime.block_on(download_file(&plan.sbl3_url, &sbl3_path))?;

    let ffu = FfuMetadata::open(&ffu_path)
        .with_context(|| format!("failed to parse FFU {}", ffu_path.display()))?;
    println!("ffu path: {}", ffu_path.display());
    println!("emergency path: {}", emergency_path.display());
    println!("engineering SBL3 path: {}", sbl3_path.display());
    println!("ffu platform: {}", ffu.platform_id);
    println!("ffu chunk size: {}", ffu.chunk_size);
    println!("ffu chunks: {}", ffu.total_chunk_count);

    switch_to_flash_app(vid, pid, false).context("failed to switch to FlashApp")?;
    let (flash_info, phone_rrkh, flash_version, security_status) =
        with_device(vid, pid, false, |handle, endpoints| {
            let flash_info = read_flash_app_info(handle, endpoints)?;
            let phone_rrkh = read_flash_param(handle, endpoints, "RRKH")?;
            let flash_version = read_flash_param(handle, endpoints, "FAI")?;
            let security_status = read_flash_param(handle, endpoints, "SS")?;
            Ok((flash_info, phone_rrkh, flash_version, security_status))
        })?;

    validate_flash_version(&flash_version)?;
    validate_security_status(&security_status)?;
    validate_ffu_against_flash_app(&ffu, &flash_info)?;
    validate_rrkh(&ffu_path, &ffu, &phone_rrkh)?;

    let loader_records = build_loader_records(&emergency_path, &phone_rrkh)
        .with_context(|| format!("failed to scan loaders in {}", emergency_path.display()))?;
    ensure!(
        !loader_records.is_empty(),
        "no matching QHSUSB_ARMPRG loaders found for phone RRKH"
    );
    println!("matching emergency loaders: {}", loader_records.len());
    for loader in &loader_records {
        println!(
            "  {} format={} size={} rkh={}",
            loader.name, loader.format, loader.size, loader.root_key_hash
        );
    }

    let artifacts = build_jailbreak_artifacts(&ffu_path, &ffu, &sbl3_path)?;
    let artifact_dir =
        cached_jailbreak_artifact_dir(&phone.product_type, &phone.product_code, &phone.imei)?;
    fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("failed to create {}", artifact_dir.display()))?;
    let writes = write_artifacts(&artifact_dir, &ffu_path, &ffu, &artifacts)?;

    println!("patched artifacts:");
    println!("  directory: {}", artifact_dir.display());
    println!("  GPT: {} bytes", artifacts.patched_gpt.len());
    println!("  HACK: {} bytes", artifacts.hack_sector.len());
    println!("  SBL2: {} bytes", artifacts.patched_sbl2.len());
    println!("  SBL3: {} bytes", artifacts.patched_sbl3.len());
    println!("  UEFI: {} bytes", artifacts.patched_uefi.len());
    print_write_plan(&artifacts.write_plan);

    let manifest = JailbreakManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        product_type: phone.product_type,
        product_code: phone.product_code,
        masked_imei: mask_imei(&phone.imei),
        rrkh: hex_dump_compact(&phone_rrkh),
        ffu: file_record(&ffu_path)?,
        emergency: file_record(&emergency_path)?,
        engineering_sbl3: file_record(&sbl3_path)?,
        artifact_dir: artifact_dir.display().to_string(),
        loaders: loader_records,
        writes,
        armprg: ArmprgQuirks {
            partition: 0x21,
            chunk_size: 0x400,
            loader_address: EDL_LOADER_ADDRESS,
            gpt_write_len: 0x41ff,
            winsecapp_limit: 0x1e7fe00,
        },
    };

    write_manifest(&manifest_path, &manifest)?;
    println!("wrote jailbreak manifest: {}", manifest_path.display());
    println!(
        "run `lp-externals jailbreak {}` to execute it",
        manifest_path.display()
    );

    Ok(())
}

pub(crate) fn run(
    lumia_vid: u16,
    lumia_pid: u16,
    edl_vid: u16,
    edl_pid: u16,
    wait: bool,
    manifest_path: &Path,
) -> Result<()> {
    let manifest_path = absolute_path(manifest_path)?;
    let manifest = read_manifest(&manifest_path)?;
    validate_manifest(&manifest)?;

    println!("manifest: {}", manifest_path.display());
    println!("phone type: {}", manifest.product_type);
    println!("product code: {}", manifest.product_code);
    println!("imei: {}", manifest.masked_imei);
    println!("rrkh: {}", manifest.rrkh);
    print_manifest_write_plan(&manifest);

    match detect_mode(lumia_vid, lumia_pid, edl_vid, edl_pid, wait)? {
        DetectedMode::Lumia(app) => {
            println!("detected Lumia mode: {}", app.name());
            validate_lumia_against_manifest(lumia_vid, lumia_pid, &manifest)?;
            soft_brick_from_manifest(lumia_vid, lumia_pid, &manifest)?;
            wait_for_edl_mode(edl_vid, edl_pid, EdlMode::Download)?;
            upload_loader_from_manifest(edl_vid, edl_pid, &manifest)?;
            wait_for_edl_mode(edl_vid, edl_pid, EdlMode::Armprg)?;
            flash_manifest(edl_vid, edl_pid, &manifest)?;
        }
        DetectedMode::Edl(EdlMode::Download) => {
            println!("detected EDL mode: QHSUSB_DLOAD");
            upload_loader_from_manifest(edl_vid, edl_pid, &manifest)?;
            wait_for_edl_mode(edl_vid, edl_pid, EdlMode::Armprg)?;
            flash_manifest(edl_vid, edl_pid, &manifest)?;
        }
        DetectedMode::Edl(EdlMode::Armprg) => {
            println!("detected EDL mode: QHSUSB_ARMPRG");
            flash_manifest(edl_vid, edl_pid, &manifest)?;
        }
        DetectedMode::Edl(mode) => bail!("unsupported EDL mode: {}", mode.name()),
    }

    Ok(())
}

fn validate_lumia_against_manifest(vid: u16, pid: u16, manifest: &JailbreakManifest) -> Result<()> {
    switch_to_phone_info_app(vid, pid, false).context("failed to switch to PhoneInfoApp")?;
    let phone = read_phone_identity(vid, pid)?;
    ensure!(
        phone.product_type == manifest.product_type,
        "manifest product type {} does not match phone {}",
        manifest.product_type,
        phone.product_type
    );
    ensure!(
        phone.product_code == manifest.product_code,
        "manifest product code {} does not match phone {}",
        manifest.product_code,
        phone.product_code
    );
    println!(
        "validated Lumia identity: {} {}",
        phone.product_type, phone.product_code
    );

    switch_to_flash_app(vid, pid, false).context("failed to switch to FlashApp")?;
    let rrkh = with_device(vid, pid, false, |handle, endpoints| {
        read_flash_param(handle, endpoints, "RRKH")
    })?;
    ensure!(
        hex_dump_compact(&rrkh) == manifest.rrkh,
        "manifest RRKH {} does not match phone RRKH {}",
        manifest.rrkh,
        hex_dump_compact(&rrkh)
    );
    println!("validated Lumia RRKH");

    Ok(())
}

fn soft_brick_from_manifest(vid: u16, pid: u16, manifest: &JailbreakManifest) -> Result<()> {
    let ffu_path = PathBuf::from(&manifest.ffu.path);
    let ffu = FfuMetadata::open(&ffu_path)
        .with_context(|| format!("failed to parse FFU {}", ffu_path.display()))?;

    println!("starting destructive jailbreak soft-brick stage");
    let reset_ack_read =
        with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
            let app = identify_app(handle, endpoints)?;
            require_app(app, LumiaApp::FlashApp, "jailbreak soft-brick")?;
            soft_brick_with_ffu(handle, endpoints, &ffu_path, &ffu)?;
            send_raw_command_allow_disconnect(
                handle,
                endpoints.out_addr,
                endpoints.in_addr,
                b"NOKR",
            )
            .context("failed to send reset command after soft-brick payload")
        })?;

    println!("sent jailbreak soft-brick sequence");
    println!("sent reset command (NOKR)");
    if reset_ack_read {
        println!("received NOKR response; device may not have reset yet");
    }
    Ok(())
}

fn upload_loader_from_manifest(vid: u16, pid: u16, manifest: &JailbreakManifest) -> Result<()> {
    let rrkh = edl::with_device(vid, pid, false, |handle, endpoints| {
        edl::dload_read_rkh(handle, endpoints)
    })?;
    let rrkh_hex = hex_dump_compact(&rrkh);
    ensure!(
        rrkh_hex == manifest.rrkh,
        "manifest RRKH {} does not match DLOAD RRKH {}",
        manifest.rrkh,
        rrkh_hex
    );
    println!("validated DLOAD RRKH: {rrkh_hex}");

    let loaders = matching_loader_candidates(Path::new(&manifest.emergency.path), &rrkh)?;
    ensure!(
        !loaders.is_empty(),
        "no matching QHSUSB_ARMPRG loaders found in {}",
        manifest.emergency.path
    );

    let allowed_loader_hashes = manifest
        .loaders
        .iter()
        .map(|loader| loader.sha256.as_str())
        .collect::<Vec<_>>();
    let mut last_error = None;
    for (index, loader) in loaders.into_iter().enumerate() {
        let hash = sha256_hex(&loader.bytes);
        if !allowed_loader_hashes.contains(&hash.as_str()) {
            continue;
        }
        println!(
            "loader attempt {}: {} format={} size={} address=0x{:08x}",
            index + 1,
            loader.name,
            loader.format,
            loader.bytes.len(),
            manifest.armprg.loader_address
        );
        let result =
            edl::with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
                edl::dload_send_to_memory(
                    handle,
                    endpoints,
                    manifest.armprg.loader_address,
                    &loader.bytes,
                )?;
                edl::dload_start_bootloader(handle, endpoints, manifest.armprg.loader_address)
            });
        match result {
            Ok(()) => {
                println!("loader started");
                return Ok(());
            }
            Err(err) => {
                if edl::probe(vid, pid, false).is_ok_and(|info| info.mode == EdlMode::Armprg) {
                    println!("device reports QHSUSB_ARMPRG after loader start");
                    return Ok(());
                }
                println!("loader attempt failed: {err:#}");
                last_error = Some(err);
            }
        }
    }

    if let Some(err) = last_error {
        Err(err).context("all matching loader attempts failed")
    } else {
        bail!("manifest matching loaders were not found in emergency package")
    }
}

fn flash_manifest(vid: u16, pid: u16, manifest: &JailbreakManifest) -> Result<()> {
    println!("starting ARMPRG boot-chain flash");
    edl::with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
        edl::armprg_hello(handle, endpoints)?;
        edl::armprg_set_security_mode(handle, endpoints, 0)?;
        edl::armprg_open_partition(handle, endpoints, manifest.armprg.partition)?;

        let mut flash_error = None;
        for write in &manifest.writes {
            println!(
                "flashing {:<9} start_sector={} bytes={} source={}",
                write.name, write.start_sector, write.byte_len, write.source.path
            );
            let source = fs::read(&write.source.path)
                .with_context(|| format!("failed to read {}", write.source.path))?;
            ensure!(
                sha256_hex(&source) == write.source.sha256,
                "source hash mismatch for {}",
                write.source.path
            );
            let source_start = usize::try_from(write.source_offset)
                .context("source offset does not fit in usize")?;
            let source_len =
                usize::try_from(write.byte_len).context("write length does not fit in usize")?;
            let source_end = source_start
                .checked_add(source_len)
                .context("source slice range overflow")?;
            let data = source
                .get(source_start..source_end)
                .with_context(|| format!("source slice exceeds {}", write.source.path))?;
            let start_byte = write
                .start_sector
                .checked_mul(SECTOR_SIZE)
                .context("write byte offset overflow")?;
            let start_byte = u32::try_from(start_byte)
                .context("ARMPRG write byte offset does not fit in u32")?;

            if let Err(err) = edl::armprg_flash(handle, endpoints, start_byte, data) {
                flash_error = Some(err);
                break;
            }
        }

        let close_result = edl::armprg_close_partition(handle, endpoints);
        if let Some(err) = flash_error {
            return Err(err);
        }
        close_result?;
        edl::armprg_reboot(handle, endpoints)
    })?;
    println!("ARMPRG boot-chain flash complete; reboot sent");
    Ok(())
}

fn write_artifacts(
    artifact_dir: &Path,
    ffu_path: &Path,
    ffu: &FfuMetadata,
    artifacts: &JailbreakArtifacts,
) -> Result<Vec<ManifestWrite>> {
    let mut writes = Vec::new();
    for entry in &artifacts.write_plan {
        let bytes = artifact_bytes(entry.name, ffu_path, ffu, artifacts)?;
        let file_name = format!("{}.bin", entry.name.to_ascii_lowercase());
        let path = artifact_dir.join(file_name);
        write_bytes(&path, &bytes)?;
        writes.push(ManifestWrite {
            name: entry.name.to_string(),
            start_sector: entry.start_sector,
            byte_len: entry.byte_len,
            source_offset: 0,
            source: file_record(&path)?,
            operation: entry.operation.to_string(),
        });
    }
    let text_plan = render_manifest_write_plan(&writes);
    write_bytes(&artifact_dir.join("write-plan.txt"), text_plan.as_bytes())?;
    Ok(writes)
}

fn artifact_bytes(
    name: &str,
    ffu_path: &Path,
    ffu: &FfuMetadata,
    artifacts: &JailbreakArtifacts,
) -> Result<Vec<u8>> {
    match name {
        "MBR" => ffu.get_sectors(ffu_path, 0, 1),
        "GPT" => Ok(artifacts.patched_gpt.clone()),
        "HACK" => Ok(artifacts.hack_sector.clone()),
        "SBL2" => Ok(artifacts.patched_sbl2.clone()),
        "SBL3" => Ok(artifacts.patched_sbl3.clone()),
        "UEFI" => Ok(artifacts.patched_uefi.clone()),
        "SBL1" => ffu.get_partition(ffu_path, "SBL1"),
        "TZ" => ffu.get_partition(ffu_path, "TZ"),
        "RPM" => ffu.get_partition(ffu_path, "RPM"),
        "WINSECAPP" => ffu.get_partition(ffu_path, "WINSECAPP"),
        _ => bail!("unknown write-plan artifact {name}"),
    }
}

fn build_loader_records(path: &Path, rrkh: &[u8]) -> Result<Vec<ManifestLoader>> {
    let matches = matching_armprg_loaders(path, rrkh)?;
    let candidates = read_qcom_candidates(path)?;
    let mut records = Vec::new();

    for loader in matches {
        let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.name == loader.name)
        else {
            continue;
        };
        records.push(ManifestLoader {
            name: loader.name,
            format: loader.format.to_string(),
            size: loader.size,
            sha256: sha256_hex(&candidate.bytes),
            root_key_hash: hex_dump_compact(&loader.root_key_hash),
        });
    }

    Ok(records)
}

fn matching_loader_candidates(path: &Path, rrkh: &[u8]) -> Result<Vec<QcomCandidate>> {
    ensure!(
        rrkh.len() == 0x20,
        "RKH must be 32 bytes, got {}",
        rrkh.len()
    );
    let candidates = read_qcom_candidates(path)?;
    let rkh_is_blank = rrkh.iter().all(|byte| *byte == 0);
    let mut matches = Vec::new();

    for candidate in candidates {
        if candidate.bytes.len() > 0x80000 {
            continue;
        }
        if !contains_utf16le(&candidate.bytes, "QHSUSB_ARMPRG") {
            continue;
        }
        if !rkh_is_blank {
            let image = match QualcommImage::parse(&candidate.bytes, 0) {
                Ok(image) => image,
                Err(_) => continue,
            };
            if image.root_key_hash.as_deref() != Some(rrkh) {
                continue;
            }
        }
        matches.push(candidate);
    }

    Ok(matches)
}

fn validate_manifest(manifest: &JailbreakManifest) -> Result<()> {
    ensure!(
        manifest.schema_version == MANIFEST_SCHEMA_VERSION,
        "unsupported jailbreak manifest schema {}",
        manifest.schema_version
    );
    ensure!(!manifest.writes.is_empty(), "manifest has no write entries");
    validate_file_record(&manifest.ffu)?;
    validate_file_record(&manifest.emergency)?;
    validate_file_record(&manifest.engineering_sbl3)?;
    for write in &manifest.writes {
        validate_file_record(&write.source)?;
        ensure!(write.byte_len != 0, "{} write length is zero", write.name);
        ensure!(
            write.start_sector.checked_mul(SECTOR_SIZE).is_some(),
            "{} write byte offset overflows",
            write.name
        );
        let source_len = fs::metadata(&write.source.path)
            .with_context(|| format!("failed to stat {}", write.source.path))?
            .len();
        let source_end = write
            .source_offset
            .checked_add(write.byte_len)
            .with_context(|| format!("{} source range overflows", write.name))?;
        ensure!(
            source_end <= source_len,
            "{} write exceeds source file",
            write.name
        );
        if write.name == "GPT" {
            ensure!(
                write.start_sector == 1 && write.byte_len == manifest.armprg.gpt_write_len,
                "GPT write must use ARMPRG-safe sector 1 length {}",
                manifest.armprg.gpt_write_len
            );
        }
        if write.name == "WINSECAPP" {
            let start = write
                .start_sector
                .checked_mul(SECTOR_SIZE)
                .context("WINSECAPP byte offset overflow")?;
            let end = start
                .checked_add(write.byte_len)
                .context("WINSECAPP byte end overflow")?;
            ensure!(
                end <= manifest.armprg.winsecapp_limit,
                "WINSECAPP write exceeds ARMPRG limit"
            );
        }
    }
    Ok(())
}

fn validate_file_record(record: &ManifestFile) -> Result<()> {
    let actual = sha256_file(Path::new(&record.path))?;
    ensure!(
        actual == record.sha256,
        "hash mismatch for {}: manifest {}, actual {}",
        record.path,
        record.sha256,
        actual
    );
    Ok(())
}

fn read_manifest(path: &Path) -> Result<JailbreakManifest> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_manifest(path: &Path, manifest: &JailbreakManifest) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest).context("failed to serialize manifest")?;
    write_bytes(path, &bytes)
}

fn detect_mode(
    lumia_vid: u16,
    lumia_pid: u16,
    edl_vid: u16,
    edl_pid: u16,
    wait: bool,
) -> Result<DetectedMode> {
    loop {
        if let Ok(info) = edl::probe(edl_vid, edl_pid, false) {
            return Ok(DetectedMode::Edl(info.mode));
        }
        if let Ok(app) = with_device(lumia_vid, lumia_pid, false, |handle, endpoints| {
            identify_app(handle, endpoints)
        }) {
            return Ok(DetectedMode::Lumia(app));
        }
        if !wait {
            bail!("neither Lumia USB nor Qualcomm EDL USB device is present");
        }
        std::thread::sleep(DETECT_POLL_INTERVAL);
    }
}

fn wait_for_edl_mode(vid: u16, pid: u16, expected: EdlMode) -> Result<()> {
    println!("waiting for {}", expected.name());
    loop {
        if let Ok(info) = edl::probe(vid, pid, false) {
            if info.mode == expected {
                return Ok(());
            }
        }
        std::thread::sleep(DETECT_POLL_INTERVAL);
    }
}

fn read_phone_identity(vid: u16, pid: u16) -> Result<PhoneIdentity> {
    with_device(vid, pid, false, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(app, LumiaApp::PhoneInfoApp, "jailbreak phone identity read")?;
        Ok(PhoneIdentity {
            product_type: read_phone_info_ascii(handle, endpoints, "TYPE")?,
            product_code: read_phone_info_ascii(handle, endpoints, "CTR")?,
            imei: read_phone_info_ascii(handle, endpoints, "IMEI")?,
        })
    })
}

fn read_phone_info_ascii(
    handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
    endpoints: &crate::uefi::Endpoints,
    name: &str,
) -> Result<String> {
    let request = make_phone_info_read_request(name);
    let response = send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, &request)?;
    let value = parse_phone_info_response(&response)?;
    let text = ascii_param_value(value)
        .with_context(|| format!("PhoneInfoApp {name} is not printable ASCII"))?;
    ensure!(!text.is_empty(), "PhoneInfoApp returned an empty {name}");
    Ok(text)
}

fn validate_flash_version(value: &[u8]) -> Result<()> {
    ensure!(
        value.len() >= 5,
        "FlashApp FAI parameter is too short: {} bytes",
        value.len()
    );
    let major = value[3];
    let minor = value[4];
    ensure!(
        major > 1 || (major == 1 && minor >= 28),
        "FlashApp version {major}.{minor} is too old for Spec A jailbreak"
    );
    println!("flash app version: {major}.{minor}");
    Ok(())
}

fn validate_security_status(value: &[u8]) -> Result<()> {
    ensure!(
        value.len() >= 8,
        "FlashApp SS parameter is too short: {} bytes",
        value.len()
    );
    println!("platform secure boot: {}", value[1] != 0);
    println!("secure FFU efuse: {}", value[2] != 0);
    println!("RDC: {}", value[4] != 0);
    println!("authenticated: {}", value[5] != 0);
    println!("UEFI secure boot: {}", value[6] != 0);
    ensure!(
        value[1] != 0,
        "platform secure boot is not enabled; unexpected state"
    );
    ensure!(
        value[2] != 0,
        "secure FFU efuse is not enabled; unexpected state"
    );
    ensure!(
        value[4] == 0,
        "RDC is already present; refusing first-pass jailbreak"
    );
    ensure!(
        value[5] == 0,
        "FlashApp is already authenticated; refusing first-pass jailbreak"
    );
    Ok(())
}

fn validate_rrkh(ffu_path: &Path, ffu: &FfuMetadata, phone_rrkh: &[u8]) -> Result<()> {
    ensure!(
        phone_rrkh.len() == 32,
        "phone RRKH has unexpected length: {} bytes",
        phone_rrkh.len()
    );
    let sbl1 = ffu
        .get_partition(ffu_path, "SBL1")
        .context("failed to extract SBL1 from stock FFU for RRKH validation")?;
    let ffu_rrkh = extract_root_key_hash(&sbl1).context("failed to extract RRKH from FFU SBL1")?;
    let all_zero = phone_rrkh.iter().all(|byte| *byte == 0);
    ensure!(
        all_zero || phone_rrkh == ffu_rrkh.as_slice(),
        "FFU SBL1 RRKH {} does not match phone RRKH {}",
        hex_dump_compact(&ffu_rrkh),
        hex_dump_compact(phone_rrkh)
    );
    println!("phone RRKH: {}", hex_dump_compact(phone_rrkh));
    println!("ffu SBL1 RRKH: {}", hex_dump_compact(&ffu_rrkh));
    Ok(())
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_parent(path)?;
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

fn file_record(path: &Path) -> Result<ManifestFile> {
    Ok(ManifestFile {
        path: path.display().to_string(),
        sha256: sha256_file(path)?,
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_dump_compact(&Sha256::digest(bytes))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("failed to read current directory")?
            .join(path))
    }
}

fn mask_imei(imei: &str) -> String {
    let suffix_len = imei.len().min(4);
    let prefix_len = imei.len().saturating_sub(suffix_len);
    format!("{}{}", "*".repeat(prefix_len), &imei[prefix_len..])
}

fn print_manifest_write_plan(manifest: &JailbreakManifest) {
    println!("write plan:");
    for write in &manifest.writes {
        println!(
            "  {:<9} start_sector={} bytes={} op={} source={}",
            write.name, write.start_sector, write.byte_len, write.operation, write.source.path
        );
    }
}

fn render_manifest_write_plan(writes: &[ManifestWrite]) -> String {
    let mut result = String::new();
    for write in writes {
        result.push_str(&format!(
            "{} start_sector={} bytes={} op={} source={}\n",
            write.name, write.start_sector, write.byte_len, write.operation, write.source.path
        ));
    }
    result
}
