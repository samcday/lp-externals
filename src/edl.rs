use anyhow::{Context, Result, anyhow, bail};
use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType, UsbContext};

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
