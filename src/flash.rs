use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use rusb::{DeviceHandle, GlobalContext};

use crate::{
    ffu::FfuMetadata,
    uefi::{
        Endpoints, LumiaApp, identify_app, make_read_param_request, parse_param_response,
        require_app, send_raw_command,
    },
    util::{ascii_dump, ascii_lossy, hex_dump},
};

const SECURE_FLASH_SIGNATURE: &[u8; 6] = b"NOKXFS";
const PROTOCOL_SYNC_V1: u16 = 1;
const PROTOCOL_SYNC_V2: u16 = 4;
const SUBBLOCK_FFU_HEADER_V1: u32 = 0x0000000b;
const SUBBLOCK_PAYLOAD_V1: u32 = 0x0000000c;
const SUBBLOCK_PAYLOAD_V2: u32 = 0x0000001b;
const FLASH_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub(crate) struct FlashAppInfo {
    pub(crate) transfer_size: Option<u32>,
    pub(crate) write_buffer_size: Option<u32>,
    pub(crate) emmc_sectors: Option<u32>,
    pub(crate) platform_id: Option<String>,
    pub(crate) secure_ffu_protocol_mask: Option<u16>,
}

impl FlashAppInfo {
    pub(crate) fn preferred_protocol(&self) -> Result<SecureFfuProtocol> {
        let mask = self
            .secure_ffu_protocol_mask
            .context("FlashApp did not report a secure FFU protocol mask")?;

        if mask & PROTOCOL_SYNC_V2 != 0 {
            let write_buffer_size = self
                .write_buffer_size
                .context("FlashApp supports FFU sync v2 but did not report write buffer size")?;
            ensure!(
                write_buffer_size != 0,
                "FlashApp reported zero write buffer size"
            );
            return Ok(SecureFfuProtocol::SyncV2 { write_buffer_size });
        }

        if mask & PROTOCOL_SYNC_V1 != 0 {
            return Ok(SecureFfuProtocol::SyncV1);
        }

        bail!("FlashApp does not report support for secure FFU sync v1 or sync v2")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecureFfuProtocol {
    SyncV1,
    SyncV2 { write_buffer_size: u32 },
}

pub(crate) fn read_flash_app_info(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
) -> Result<FlashAppInfo> {
    let response = send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
    let app = identify_app_from_response(&response)?;
    require_app(app, LumiaApp::FlashApp, "FlashApp info read")?;

    parse_flash_app_info(&response)
}

pub(crate) fn read_flash_param(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
    name: &str,
) -> Result<Vec<u8>> {
    let app = identify_app(handle, endpoints)?;
    require_app(app, LumiaApp::FlashApp, "FlashApp parameter read")?;

    let request = make_read_param_request(name);
    let response = send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, &request)?;
    Ok(parse_param_response(&response)?.to_vec())
}

pub(crate) fn flash_signed_ffu(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
    ffu_path: &Path,
    ffu: &FfuMetadata,
    info: &FlashAppInfo,
) -> Result<()> {
    let protocol = info.preferred_protocol()?;
    let mut file =
        File::open(ffu_path).with_context(|| format!("failed to open {}", ffu_path.display()))?;
    let header = ffu.read_header(ffu_path)?;

    println!("sending FFU header ({} bytes)", header.len());
    send_ffu_header_v1(handle, endpoints, &header, 0).context("failed to send FFU header")?;

    file.seek(SeekFrom::Start(ffu.header_size as u64))
        .with_context(|| format!("failed to seek {} to FFU payload", ffu_path.display()))?;

    match protocol {
        SecureFfuProtocol::SyncV1 => {
            println!("streaming FFU payload with secure FFU sync v1");
            stream_payload_v1(handle, endpoints, &mut file, ffu)
        }
        SecureFfuProtocol::SyncV2 { write_buffer_size } => {
            println!(
                "streaming FFU payload with secure FFU sync v2 (write buffer {} bytes)",
                write_buffer_size
            );
            stream_payload_v2(
                handle,
                endpoints,
                &mut file,
                ffu,
                write_buffer_size as usize,
            )
        }
    }
}

pub(crate) fn validate_ffu_against_flash_app(ffu: &FfuMetadata, info: &FlashAppInfo) -> Result<()> {
    if let Some(platform_id) = &info.platform_id {
        ensure!(
            platforms_compatible(platform_id, &ffu.platform_id),
            "FFU platform {} does not match phone platform {}",
            ffu.platform_id,
            platform_id
        );
    }

    if let Some(emmc_sectors) = info.emmc_sectors {
        let sectors_per_chunk = ffu.chunk_size / 0x200;
        ensure!(sectors_per_chunk != 0, "invalid FFU sectors per chunk");
        let required_sectors = ffu.chunk_indexes.len() as u64 * sectors_per_chunk as u64;
        ensure!(
            required_sectors <= emmc_sectors as u64,
            "FFU requires {required_sectors} sectors, but FlashApp reports {emmc_sectors} eMMC sectors"
        );
    }

    Ok(())
}

fn parse_flash_app_info(response: &[u8]) -> Result<FlashAppInfo> {
    ensure!(response.len() >= 11, "FlashApp NOKV response too short");

    let mut info = FlashAppInfo {
        transfer_size: None,
        write_buffer_size: None,
        emmc_sectors: None,
        platform_id: None,
        secure_ffu_protocol_mask: None,
    };
    let subblock_count = response[10];
    let mut offset = 11usize;

    for _ in 0..subblock_count {
        ensure!(
            offset + 3 <= response.len(),
            "FlashApp NOKV subblock header truncated at offset {offset}"
        );
        let id = response[offset];
        let len = u16::from_be_bytes([response[offset + 1], response[offset + 2]]) as usize;
        let payload_offset = offset + 3;
        let next_offset = payload_offset + len;
        ensure!(
            next_offset <= response.len(),
            "FlashApp NOKV subblock 0x{id:02x} payload truncated"
        );
        let payload = &response[payload_offset..next_offset];

        match id {
            0x01 if payload.len() >= 4 => info.transfer_size = Some(be_u32(payload)),
            0x02 if payload.len() >= 4 => info.write_buffer_size = Some(be_u32(payload)),
            0x03 if payload.len() >= 4 => info.emmc_sectors = Some(be_u32(payload)),
            0x05 => {
                info.platform_id = Some(ascii_lossy(payload).trim_matches([' ', '\0']).to_string())
            }
            0x10 if payload.len() >= 3 => {
                info.secure_ffu_protocol_mask = Some(u16::from_be_bytes([payload[1], payload[2]]))
            }
            _ => {}
        }

        offset = next_offset;
    }

    Ok(info)
}

fn identify_app_from_response(response: &[u8]) -> Result<LumiaApp> {
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
    Ok(LumiaApp::from_app_type(response[5]))
}

fn stream_payload_v1(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
    file: &mut File,
    ffu: &FfuMetadata,
) -> Result<()> {
    let mut buffer = vec![0; ffu.chunk_size];
    let mut chunks_sent = 0u64;
    let mut last_percent = None;

    while chunks_sent < ffu.total_chunk_count {
        file.read_exact(&mut buffer)
            .context("failed to read FFU payload chunk")?;
        chunks_sent += 1;
        let progress = progress_percent(chunks_sent, ffu.total_chunk_count);
        send_ffu_payload_v1(handle, endpoints, &buffer, progress, 0)
            .with_context(|| format!("failed to send FFU payload chunk {chunks_sent}"))?;
        report_progress(chunks_sent, ffu.total_chunk_count, &mut last_percent);
    }

    Ok(())
}

fn stream_payload_v2(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
    file: &mut File,
    ffu: &FfuMetadata,
    write_buffer_size: usize,
) -> Result<()> {
    ensure!(write_buffer_size != 0, "invalid zero write buffer size");
    ensure!(
        write_buffer_size.is_multiple_of(ffu.chunk_size),
        "FlashApp write buffer size {write_buffer_size} is not a multiple of FFU chunk size {}",
        ffu.chunk_size
    );

    let mut chunks_sent = 0u64;
    let mut bytes_remaining = ffu.payload_size;
    let mut last_percent = None;

    while bytes_remaining > 0 {
        let payload_size = write_buffer_size.min(bytes_remaining as usize);
        ensure!(
            payload_size.is_multiple_of(ffu.chunk_size),
            "final FFU payload block is not chunk-aligned"
        );
        let mut buffer = vec![0; payload_size];
        file.read_exact(&mut buffer)
            .context("failed to read FFU payload block")?;
        let payload_chunks = (payload_size / ffu.chunk_size) as u64;
        chunks_sent += payload_chunks;
        let progress = progress_percent(chunks_sent, ffu.total_chunk_count);
        send_ffu_payload_v2(handle, endpoints, &buffer, progress, 0).with_context(|| {
            format!("failed to send FFU payload block ending at chunk {chunks_sent}")
        })?;
        bytes_remaining -= payload_size as u64;
        report_progress(chunks_sent, ffu.total_chunk_count, &mut last_percent);
    }

    Ok(())
}

fn send_ffu_header_v1(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
    header: &[u8],
    options: u8,
) -> Result<()> {
    let header_len = u32::try_from(header.len()).context("FFU header too large")?;
    let mut request = vec![0; header.len() + 0x20];
    request[..6].copy_from_slice(SECURE_FLASH_SIGNATURE);
    request[0x06..0x08].copy_from_slice(&PROTOCOL_SYNC_V1.to_be_bytes());
    request[0x08] = 0;
    request[0x0b] = 1;
    request[0x0c..0x10].copy_from_slice(&SUBBLOCK_FFU_HEADER_V1.to_be_bytes());
    request[0x10..0x14].copy_from_slice(&(header_len + 0x0c).to_be_bytes());
    request[0x14..0x18].copy_from_slice(&0u32.to_be_bytes());
    request[0x18..0x1c].copy_from_slice(&header_len.to_be_bytes());
    request[0x1c] = options;
    request[0x20..].copy_from_slice(header);

    send_secure_flash_request(handle, endpoints, &request)
}

fn send_ffu_payload_v1(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
    payload: &[u8],
    progress: u8,
    options: u8,
) -> Result<()> {
    let payload_len = u32::try_from(payload.len()).context("FFU payload block too large")?;
    let mut request = vec![0; payload.len() + 0x1c];
    request[..6].copy_from_slice(SECURE_FLASH_SIGNATURE);
    request[0x06..0x08].copy_from_slice(&PROTOCOL_SYNC_V1.to_be_bytes());
    request[0x08] = progress;
    request[0x0b] = 1;
    request[0x0c..0x10].copy_from_slice(&SUBBLOCK_PAYLOAD_V1.to_be_bytes());
    request[0x10..0x14].copy_from_slice(&(payload_len + 0x08).to_be_bytes());
    request[0x14..0x18].copy_from_slice(&payload_len.to_be_bytes());
    request[0x18] = options;
    request[0x1c..].copy_from_slice(payload);

    send_secure_flash_request(handle, endpoints, &request)
}

fn send_ffu_payload_v2(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
    payload: &[u8],
    progress: u8,
    options: u8,
) -> Result<()> {
    let payload_len = u32::try_from(payload.len()).context("FFU payload block too large")?;
    let mut request = vec![0; payload.len() + 0x20];
    request[..6].copy_from_slice(SECURE_FLASH_SIGNATURE);
    request[0x06..0x08].copy_from_slice(&PROTOCOL_SYNC_V2.to_be_bytes());
    request[0x08] = progress;
    request[0x0b] = 1;
    request[0x0c..0x10].copy_from_slice(&SUBBLOCK_PAYLOAD_V2.to_be_bytes());
    request[0x10..0x14].copy_from_slice(&(payload_len + 0x0c).to_be_bytes());
    request[0x14..0x18].copy_from_slice(&payload_len.to_be_bytes());
    request[0x18] = options;
    request[0x20..].copy_from_slice(payload);

    send_secure_flash_request(handle, endpoints, &request)
}

fn send_secure_flash_request(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &Endpoints,
    request: &[u8],
) -> Result<()> {
    let written = handle
        .write_bulk(endpoints.out_addr, request, FLASH_TIMEOUT)
        .with_context(|| {
            format!(
                "failed to write to bulk OUT endpoint 0x{:02x}",
                endpoints.out_addr
            )
        })?;
    ensure!(
        written == request.len(),
        "short USB write: wrote {written} of {} bytes",
        request.len()
    );

    let mut response = vec![0; 0x8000];
    let read = handle
        .read_bulk(endpoints.in_addr, &mut response, FLASH_TIMEOUT)
        .with_context(|| {
            format!(
                "failed to read from bulk IN endpoint 0x{:02x}",
                endpoints.in_addr
            )
        })?;
    response.truncate(read);
    validate_secure_flash_response(&response)
}

fn validate_secure_flash_response(response: &[u8]) -> Result<()> {
    ensure!(
        response.len() >= 4,
        "secure FFU response too short: {} bytes",
        response.len()
    );

    if &response[..4] == b"NOKU" {
        bail!("device reported NOKXFS as unsupported");
    }

    ensure!(
        response.len() >= 8,
        "secure FFU response too short for status: {} bytes ({})",
        response.len(),
        hex_dump(response)
    );
    ensure!(
        response.get(..6) == Some(SECURE_FLASH_SIGNATURE.as_slice()),
        "unexpected secure FFU response signature: {}",
        ascii_dump(&response[..response.len().min(6)])
    );

    let status = u16::from_be_bytes([response[6], response[7]]);
    if status != 0 {
        bail!(
            "secure FFU failed with status 0x{status:04x}: {}",
            flash_error_message(status)
        );
    }

    Ok(())
}

fn progress_percent(done: u64, total: u64) -> u8 {
    ((done * 100 / total).min(100)) as u8
}

fn report_progress(done: u64, total: u64, last_percent: &mut Option<u64>) {
    let percent = done * 100 / total;
    if *last_percent != Some(percent) {
        *last_percent = Some(percent);
        println!("  {percent}% ({done}/{total} chunks)");
    }
}

fn platforms_compatible(phone: &str, ffu: &str) -> bool {
    phone == ffu
        || phone
            .strip_prefix(ffu)
            .is_some_and(|suffix| suffix.starts_with('.'))
        || ffu
            .strip_prefix(phone)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn be_u32(payload: &[u8]) -> u32 {
    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
}

fn flash_error_message(status: u16) -> &'static str {
    match status {
        0x0008 => "Unsupported protocol / Invalid options",
        0x000f => "Invalid sub block count",
        0x0010 => "Invalid sub block length",
        0x0012 => "Authentication required",
        0x000e => "Invalid sub block type",
        0x0013 => "Failed async message",
        0x1000 => "Invalid header type",
        0x1001 => "FFU header contains unknown extra data",
        0x0001 => "Couldn't allocate memory",
        0x1106 => "Security header validation failed",
        0x1105 => "Invalid hash table size",
        0x1104 => "Invalid catalog size",
        0x1103 => "Invalid chunk size",
        0x1102 => "Unsupported algorithm",
        0x1101 => "Invalid struct size",
        0x1100 => "Invalid signature",
        0x1202 => "Invalid struct size",
        0x1203 => "Unsupported algorithm",
        0x1204 => "Invalid chunk size",
        0x1005 => "Data not aligned correctly",
        0x0009 => "Locate protocol failed",
        0x1003 => "Hash mismatch",
        0x1006 => "Couldn't find hash from security header for index",
        0x1004 => "Security header import missing / All FFU headers have not been imported",
        0x1304 => "Invalid platform ID",
        0x1307 => "Invalid write descriptor info",
        0x1306 => "Invalid write descriptor info",
        0x1305 => "Invalid block size",
        0x1303 => "Unsupported FFU version",
        0x1302 => "Unsupported struct version",
        0x1301 => "Invalid update type",
        0x100b => "Too much payload data, all data has already been written",
        0x1008 => "Internal error",
        0x1007 => "Payload data does not contain all data",
        0x0004 => "Flash write failed",
        0x000d => "Flash verify failed",
        0x0002 => "Flash read failed",
        _ => "Unknown error",
    }
}
