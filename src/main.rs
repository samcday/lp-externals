use std::{fmt, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType, UsbContext};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Parser)]
#[command(name = "lp-externals")]
#[command(about = "LPexternals: portable Lumia/Nokia phone pokery")]
struct Cli {
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

    /// Reboot the phone with the write-only NOKR command.
    Reset {
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

    /// GPT-related commands.
    Gpt {
        #[command(subcommand)]
        command: GptCommand,
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
        Command::Identify { vid, pid } => identify(vid, pid),
        Command::Raw { vid, pid, commands } => raw(vid, pid, &commands),
        Command::Reset { vid, pid } => reset(vid, pid),
        Command::Switch { command } => match command {
            SwitchCommand::Flash { vid, pid } => switch_flash(vid, pid),
        },
        Command::Gpt { command } => match command {
            GptCommand::Dump { vid, pid, format } => gpt_dump(vid, pid, format),
        },
    }
}

fn identify(vid: u16, pid: u16) -> Result<()> {
    let response = with_device(vid, pid, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")
    })?;
    print_identification(&response);

    Ok(())
}

fn raw(vid: u16, pid: u16, commands: &[String]) -> Result<()> {
    let responses = with_device(vid, pid, |handle, endpoints| {
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

fn reset(vid: u16, pid: u16) -> Result<()> {
    with_device(vid, pid, |handle, endpoints| {
        send_raw_void_command(handle, endpoints.out_addr, b"NOKR")
    })?;

    println!("sent reset command (NOKR)");

    Ok(())
}

fn switch_flash(vid: u16, pid: u16) -> Result<()> {
    with_device(vid, pid, |handle, endpoints| {
        send_raw_void_command(handle, endpoints.out_addr, b"NOKS")
    })?;

    println!("sent switch-to-FlashApp command (NOKS)");

    Ok(())
}

fn gpt_dump(vid: u16, pid: u16, format: GptDumpFormat) -> Result<()> {
    let response = with_device(vid, pid, |handle, endpoints| {
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
    f: impl FnOnce(&mut DeviceHandle<GlobalContext>, &Endpoints) -> Result<T>,
) -> Result<T> {
    let (device, mut handle) = open_device(vid, pid)?;
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

    handle
        .release_interface(endpoints.interface)
        .with_context(|| format!("failed to release interface {}", endpoints.interface))?;

    result
}

fn open_device(vid: u16, pid: u16) -> Result<(Device<GlobalContext>, DeviceHandle<GlobalContext>)> {
    let devices = rusb::devices().context("failed to list USB devices")?;

    for device in devices.iter() {
        let descriptor = device
            .device_descriptor()
            .context("failed to read USB device descriptor")?;
        if descriptor.vendor_id() == vid && descriptor.product_id() == pid {
            let handle = device
                .open()
                .with_context(|| format!("failed to open USB device {vid:04x}:{pid:04x}"))?;
            return Ok((device, handle));
        }
    }

    bail!("USB device {vid:04x}:{pid:04x} not found")
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

fn print_identification(response: &[u8]) {
    print_raw_response(response);

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

    if app == 1 {
        print_bootmgr_subblocks(response);
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

fn print_gpt(gpt: &[u8]) -> Result<()> {
    ensure!(
        gpt.len() >= 0x600,
        "GPT payload too short: {} bytes",
        gpt.len()
    );

    let header_offset = 0x200;
    let header = gpt
        .get(header_offset..)
        .context("GPT payload missing primary header")?;

    ensure!(header.len() >= 92, "GPT header too short");
    ensure!(&header[..8] == b"EFI PART", "missing GPT header signature");

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

    println!("GPT header");
    println!("  revision: 0x{revision:08x}");
    println!("  header size: {header_size}");
    println!("  current lba: {current_lba}");
    println!("  backup lba: {backup_lba}");
    println!("  first usable lba: {first_usable_lba}");
    println!("  last usable lba: {last_usable_lba}");
    println!("  disk guid: {disk_guid}");
    println!("  partition entries lba: {partition_entries_lba}");
    println!("  partition entry count: {partition_entry_count}");
    println!("  partition entry size: {partition_entry_size}");

    let entries_offset = usize::try_from(partition_entries_lba)
        .context("partition entries LBA does not fit in usize")?
        .checked_mul(512)
        .context("partition entries offset overflow")?;
    let entry_size = usize::try_from(partition_entry_size)
        .context("partition entry size does not fit in usize")?;
    ensure!(
        entry_size >= 128,
        "unsupported GPT entry size: {entry_size}"
    );

    println!();
    println!("Partitions");

    let mut printed = 0usize;
    for index in 0..partition_entry_count {
        let offset = entries_offset
            .checked_add(
                usize::try_from(index)
                    .context("partition index does not fit in usize")?
                    .checked_mul(entry_size)
                    .context("partition entry offset overflow")?,
            )
            .context("partition entry offset overflow")?;
        let entry = match gpt.get(offset..offset + entry_size) {
            Some(entry) => entry,
            None => break,
        };

        if entry[..16].iter().all(|byte| *byte == 0) {
            continue;
        }

        let type_guid = format_guid(&entry[0..16]);
        let unique_guid = format_guid(&entry[16..32]);
        let first_lba = le_u64(entry, 32)?;
        let last_lba = le_u64(entry, 40)?;
        let attrs = le_u64(entry, 48)?;
        let name = decode_utf16_name(&entry[56..128]);
        let sectors = last_lba.saturating_sub(first_lba).saturating_add(1);

        println!(
            "  {:>3}: {:<36} first={} last={} sectors={} attrs=0x{:016x}",
            index + 1,
            name,
            first_lba,
            last_lba,
            sectors,
            attrs
        );
        println!("       type:   {type_guid}");
        println!("       unique: {unique_guid}");

        printed += 1;
    }

    if printed == 0 {
        println!("  no populated partition entries found");
    }

    Ok(())
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let bytes = bytes
        .get(offset..offset + 4)
        .with_context(|| format!("missing u32 at offset {offset}"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
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
