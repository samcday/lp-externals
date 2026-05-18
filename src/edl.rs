use anyhow::{Context, Result, anyhow, bail, ensure};
use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType, UsbContext};

use crate::util::hex_dump;

const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const DEVICE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

pub(crate) const DEFAULT_VID: u16 = 0x05c6;
pub(crate) const DEFAULT_PID: u16 = 0x9008;

pub(crate) struct EdlEndpoints {
    pub(crate) interface: u8,
    pub(crate) in_addr: u8,
    pub(crate) out_addr: u8,
}

pub(crate) struct EdlDeviceInfo {
    pub(crate) bus: u8,
    pub(crate) address: u8,
    pub(crate) manufacturer: Option<String>,
    pub(crate) product: Option<String>,
    pub(crate) mode: EdlMode,
    pub(crate) endpoints: EdlEndpoints,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EdlMode {
    Download,
    Armprg,
    Bulk,
    Unknown(String),
}

impl EdlMode {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Download => "QHSUSB_DLOAD",
            Self::Armprg => "QHSUSB_ARMPRG",
            Self::Bulk => "QHSUSB__BULK",
            Self::Unknown(name) => name,
        }
    }
}

pub(crate) fn probe(vid: u16, pid: u16, wait: bool) -> Result<EdlDeviceInfo> {
    let (device, handle) = open_device(vid, pid, wait)?;
    let descriptor = device
        .device_descriptor()
        .context("failed to read USB device descriptor")?;
    let endpoints = find_bulk_endpoints(&device)?;
    let manufacturer = handle
        .read_manufacturer_string_ascii(&descriptor)
        .ok()
        .filter(|value| !value.is_empty());
    let product = handle
        .read_product_string_ascii(&descriptor)
        .ok()
        .filter(|value| !value.is_empty());
    let mode = classify_mode(product.as_deref());

    Ok(EdlDeviceInfo {
        bus: device.bus_number(),
        address: device.address(),
        manufacturer,
        product,
        mode,
        endpoints,
    })
}

pub(crate) fn with_device<T>(
    vid: u16,
    pid: u16,
    wait: bool,
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &EdlEndpoints) -> Result<T>,
) -> Result<T> {
    with_device_release_policy(vid, pid, wait, false, f)
}

pub(crate) fn with_device_allow_release_disconnect<T>(
    vid: u16,
    pid: u16,
    wait: bool,
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &EdlEndpoints) -> Result<T>,
) -> Result<T> {
    with_device_release_policy(vid, pid, wait, true, f)
}

fn with_device_release_policy<T>(
    vid: u16,
    pid: u16,
    wait: bool,
    allow_release_disconnect: bool,
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &EdlEndpoints) -> Result<T>,
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

pub(crate) fn dload_ping(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
) -> Result<()> {
    let response = send_dload_command(handle, endpoints, &[0x06])?;
    ensure!(
        response == [0x02],
        "unexpected DLOAD ping response: {}",
        hex_dump(&response)
    );
    Ok(())
}

pub(crate) fn dload_read_rkh(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
) -> Result<Vec<u8>> {
    let response = send_dload_command(handle, endpoints, &[0x18])?;
    ensure!(
        response.len() >= 0x23,
        "DLOAD RKH response is too short: {} bytes",
        response.len()
    );
    ensure!(
        response.get(0..3) == Some(&[0x18, 0x01, 0x00]),
        "unexpected DLOAD RKH response prefix: {}",
        hex_dump(&response[..response.len().min(3)])
    );
    Ok(response[3..0x23].to_vec())
}

pub(crate) fn dload_send_to_memory(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
    address: u32,
    data: &[u8],
) -> Result<()> {
    let mut current_address = address;
    let mut offset = 0usize;

    while offset < data.len() {
        let current_len = (data.len() - offset).min(0x100);
        let mut command = Vec::with_capacity(7 + current_len);
        command.push(0x0f);
        command.extend_from_slice(&current_address.to_be_bytes());
        command.extend_from_slice(&(current_len as u16).to_be_bytes());
        command.extend_from_slice(&data[offset..offset + current_len]);
        expect_dload_ack(handle, endpoints, &command).with_context(|| {
            format!("failed to upload DLOAD memory chunk at 0x{current_address:08x}")
        })?;

        current_address = current_address
            .checked_add(current_len as u32)
            .context("DLOAD upload address overflow")?;
        offset += current_len;
    }

    Ok(())
}

pub(crate) fn dload_start_bootloader(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
    address: u32,
) -> Result<()> {
    let mut command = Vec::with_capacity(5);
    command.push(0x05);
    command.extend_from_slice(&address.to_be_bytes());
    expect_dload_ack(handle, endpoints, &command)
}

pub(crate) fn armprg_hello(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
) -> Result<()> {
    let mut command = Vec::with_capacity(36);
    command.push(0x01);
    command.extend_from_slice(b"QCOM fast download protocol host");
    command.extend_from_slice(&[0x02, 0x02, 0x01]);
    let response = send_armprg_command(handle, endpoints, &command)?;
    ensure!(
        response.first() == Some(&0x02),
        "unexpected ARMPRG hello response: {}",
        hex_dump(&response)
    );
    Ok(())
}

pub(crate) fn armprg_set_security_mode(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
    mode: u8,
) -> Result<()> {
    let response = send_armprg_command(handle, endpoints, &[0x17, mode])?;
    ensure!(
        response.first() == Some(&0x18),
        "unexpected ARMPRG set-security response: {}",
        hex_dump(&response)
    );
    Ok(())
}

pub(crate) fn armprg_open_partition(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
    partition: u8,
) -> Result<()> {
    let response = send_armprg_command(handle, endpoints, &[0x1b, partition])?;
    ensure!(
        response.first() == Some(&0x1c),
        "unexpected ARMPRG open-partition response: {}",
        hex_dump(&response)
    );
    Ok(())
}

fn send_armprg_command(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
    command: &[u8],
) -> Result<Vec<u8>> {
    write_bulk_all(handle, endpoints.out_addr, command)?;
    read_dload_frame(handle, endpoints.in_addr)
}

fn expect_dload_ack(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
    command: &[u8],
) -> Result<()> {
    let response = send_dload_command(handle, endpoints, command)?;
    ensure!(
        response == [0x02],
        "unexpected DLOAD ACK response: {}",
        hex_dump(&response)
    );
    Ok(())
}

fn send_dload_command(
    handle: &mut DeviceHandle<GlobalContext>,
    endpoints: &EdlEndpoints,
    command: &[u8],
) -> Result<Vec<u8>> {
    let packet = encode_dload_frame(command);
    write_bulk_all(handle, endpoints.out_addr, &packet)?;
    read_dload_frame(handle, endpoints.in_addr)
}

fn write_bulk_all(
    handle: &mut DeviceHandle<GlobalContext>,
    out_addr: u8,
    mut bytes: &[u8],
) -> Result<()> {
    while !bytes.is_empty() {
        let written = handle
            .write_bulk(out_addr, bytes, DEFAULT_TIMEOUT)
            .with_context(|| format!("failed to write to bulk OUT endpoint 0x{out_addr:02x}"))?;
        ensure!(written != 0, "short USB write: wrote 0 bytes");
        bytes = &bytes[written..];
    }

    Ok(())
}

fn read_dload_frame(handle: &mut DeviceHandle<GlobalContext>, in_addr: u8) -> Result<Vec<u8>> {
    let mut raw = Vec::new();

    for _ in 0..8 {
        let mut buffer = vec![0; 0x4000];
        let read = handle
            .read_bulk(in_addr, &mut buffer, DEFAULT_TIMEOUT)
            .with_context(|| format!("failed to read from bulk IN endpoint 0x{in_addr:02x}"))?;
        ensure!(read != 0, "read zero bytes from bulk IN endpoint");
        raw.extend_from_slice(&buffer[..read]);

        if let Some(frame) = try_decode_dload_frame(&raw)? {
            return Ok(frame);
        }
    }

    bail!("DLOAD response did not contain a complete frame");
}

fn encode_dload_frame(payload: &[u8]) -> Vec<u8> {
    let checksum = crc16_x25(payload);
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.push(0x7e);
    push_escaped(&mut frame, payload);
    push_escaped(&mut frame, &checksum.to_le_bytes());
    frame.push(0x7e);
    frame
}

fn push_escaped(frame: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        if matches!(*byte, 0x7d | 0x7e) {
            frame.push(0x7d);
            frame.push(*byte ^ 0x20);
        } else {
            frame.push(*byte);
        }
    }
}

fn try_decode_dload_frame(raw: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some(start) = raw.iter().position(|byte| *byte == 0x7e) else {
        return Ok(None);
    };
    let Some(end) = raw[start + 1..]
        .iter()
        .position(|byte| *byte == 0x7e)
        .map(|offset| start + 1 + offset)
    else {
        return Ok(None);
    };

    let mut decoded = Vec::with_capacity(end - start);
    let mut index = start + 1;
    while index < end {
        let byte = raw[index];
        if byte == 0x7d {
            index += 1;
            ensure!(index < end, "DLOAD response frame has dangling escape byte");
            decoded.push(raw[index] ^ 0x20);
        } else {
            decoded.push(byte);
        }
        index += 1;
    }

    ensure!(decoded.len() >= 3, "DLOAD response frame is too short");
    let payload_len = decoded.len() - 2;
    let payload = &decoded[..payload_len];
    let expected = crc16_x25(payload);
    let actual = u16::from_le_bytes([decoded[payload_len], decoded[payload_len + 1]]);
    ensure!(
        actual == expected,
        "DLOAD response CRC mismatch: expected {expected:04x}, got {actual:04x}"
    );

    Ok(Some(payload.to_vec()))
}

fn crc16_x25(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for byte in bytes {
        crc ^= *byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn classify_mode(product: Option<&str>) -> EdlMode {
    match product.unwrap_or_default() {
        "QHSUSB_DLOAD" => EdlMode::Download,
        "QHSUSB_ARMPRG" => EdlMode::Armprg,
        "QHSUSB__BULK" => EdlMode::Bulk,
        other => EdlMode::Unknown(other.to_string()),
    }
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

fn find_bulk_endpoints<T: UsbContext>(device: &Device<T>) -> Result<EdlEndpoints> {
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
                return Ok(EdlEndpoints {
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
