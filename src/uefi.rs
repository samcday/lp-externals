use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType, UsbContext};

use crate::util::{ascii_dump, ascii_lossy, hex_dump};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub(crate) const RESET_RETRY_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Endpoints {
    pub(crate) interface: u8,
    pub(crate) in_addr: u8,
    pub(crate) out_addr: u8,
}

pub(crate) fn app_type_name(app: u8) -> &'static str {
    match app {
        1 => "BootManager",
        2 => "FlashApp",
        3 => "PhoneInfoApp",
        _ => "unknown",
    }
}

pub(crate) fn with_device<T>(
    vid: u16,
    pid: u16,
    wait: bool,
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &Endpoints) -> Result<T>,
) -> Result<T> {
    with_device_release_policy(vid, pid, wait, false, f)
}

pub(crate) fn with_device_allow_release_disconnect<T>(
    vid: u16,
    pid: u16,
    wait: bool,
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &Endpoints) -> Result<T>,
) -> Result<T> {
    with_device_release_policy(vid, pid, wait, true, f)
}

pub(crate) fn with_device_release_policy<T>(
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

pub(crate) fn send_raw_command(
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

pub(crate) fn send_raw_void_command(
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

pub(crate) fn send_raw_command_expect_echo(
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

pub(crate) fn send_raw_command_allow_disconnect(
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

pub(crate) fn make_read_param_request(name: &str) -> Vec<u8> {
    let mut request = vec![0; 0x0b];
    request[..6].copy_from_slice(b"NOKXFR");
    request[7..7 + name.len()].copy_from_slice(name.as_bytes());
    request
}

pub(crate) fn parse_param_response(response: &[u8]) -> Result<&[u8]> {
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

pub(crate) fn make_phone_info_read_request(name: &str) -> Vec<u8> {
    let mut request = vec![0; 16];
    request[..6].copy_from_slice(b"NOKXPH");
    request[6..6 + name.len()].copy_from_slice(name.as_bytes());
    request[6 + name.len()] = 0;
    request
}

pub(crate) fn parse_phone_info_response(response: &[u8]) -> Result<&[u8]> {
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

pub(crate) fn ensure_active_app(
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

pub(crate) fn ensure_reset_supported_app(app: u8) -> Result<()> {
    ensure!(
        matches!(app, 1 | 2),
        "reset requires BootManager or FlashApp after PhoneInfoApp escape, but NOKV reports app type {} ({})",
        app,
        app_type_name(app)
    );

    Ok(())
}

pub(crate) fn ensure_shutdown_supported_app(app: u8) -> Result<()> {
    ensure!(
        matches!(app, 1 | 2),
        "shutdown requires BootManager or FlashApp after PhoneInfoApp escape, but NOKV reports app type {} ({})",
        app,
        app_type_name(app)
    );

    Ok(())
}

pub(crate) fn parse_nokv_app_type(response: &[u8]) -> Result<u8> {
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

pub(crate) fn ascii_param_value(value: &[u8]) -> Option<String> {
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

pub(crate) fn print_known_param_decode(name: &str, value: &[u8]) {
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

pub(crate) fn print_identification(response: &[u8], debug: bool) {
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

pub(crate) fn print_raw_response(response: &[u8]) {
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
