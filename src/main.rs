mod commands;
mod edl;
mod ffu;
mod flash;
mod gpt;
mod jailbreak;
mod lumiadb;
mod qcom;
mod secure_boot;
mod uefi;
mod util;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{
    commands::gpt::DumpFormat as GptDumpFormat,
    edl::{DEFAULT_PID as DEFAULT_EDL_PID, DEFAULT_VID as DEFAULT_EDL_VID},
    util::{parse_u16, parse_u32},
};

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

    /// Reboot the phone with NOKR.
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

    /// Run the FlashApp factory-reset command after confirming the phone IMEI.
    FactoryReset {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Exact phone IMEI required before sending the destructive NOKG command.
        #[arg(long)]
        confirm_imei: String,
    },

    /// Trigger the FlashApp signed-FFU soft-brick primitive after confirming the phone IMEI.
    SoftBrick {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Stock signed FFU whose header will be accepted by FlashApp.
        #[arg(long)]
        ffu: PathBuf,

        /// Exact phone IMEI required before sending the destructive soft-brick sequence.
        #[arg(long)]
        confirm_imei: String,
    },

    /// Build a first-class jailbreak manifest and artifacts without writing phone state.
    PrepareJailbreak {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Output manifest path.
        manifest: PathBuf,
    },

    /// Execute or resume a prepared Lumia Spec A jailbreak manifest.
    Jailbreak {
        /// Lumia UEFI USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        lumia_vid: u16,

        /// Lumia UEFI USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        lumia_pid: u16,

        /// Qualcomm EDL USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        edl_vid: u16,

        /// Qualcomm EDL USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        edl_pid: u16,

        /// Prepared jailbreak manifest path.
        manifest: PathBuf,
    },

    /// Restore the exact LumiaDB stock FFU after confirming the phone IMEI.
    StockRestore {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Exact phone IMEI required before writing the destructive stock FFU restore.
        #[arg(long)]
        confirm_imei: Option<String>,

        /// Resolve/download/validate only; do not write FFU data.
        #[arg(long)]
        dry_run: bool,

        /// Do not reset the phone after a successful restore.
        #[arg(long)]
        no_reset: bool,
    },

    /// Patch EFIESP/BCD and write Spec A secure-boot-disable NV state after IMEI confirmation.
    DisableSecureBoot {
        /// USB vendor ID.
        #[arg(long, default_value = "0x0421", value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value = "0x066e", value_parser = parse_u16)]
        pid: u16,

        /// Exact phone IMEI required before writing destructive raw sectors.
        #[arg(long)]
        confirm_imei: Option<String>,

        /// Resolve/download/build/validate only; do not write sectors.
        #[arg(long)]
        dry_run: bool,

        /// Do not reset the phone after successful writes.
        #[arg(long)]
        no_reset: bool,
    },

    /// Mode switching commands.
    Switch {
        #[command(subcommand)]
        command: SwitchCommand,
    },

    /// FlashApp commands.
    Flash {
        #[command(subcommand)]
        command: FlashCommand,
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

    /// Live Qualcomm emergency download / ARMPRG commands.
    Edl {
        #[command(subcommand)]
        command: EdlCommand,
    },
}

#[derive(Debug, Subcommand)]
enum EdlCommand {
    /// Detect the live Qualcomm emergency USB interface and endpoints.
    Probe {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,
    },

    /// Qualcomm emergency download protocol commands.
    Dload {
        #[command(subcommand)]
        command: EdlDloadCommand,
    },

    /// ARMPRG emergency flash protocol commands.
    Armprg {
        #[command(subcommand)]
        command: EdlArmprgCommand,
    },
}

#[derive(Debug, Subcommand)]
enum EdlDloadCommand {
    /// Check whether DLOAD is alive.
    Ping {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,
    },

    /// Read the Root Key Hash from DLOAD.
    Rkh {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,
    },

    /// Upload and start a matching signed ARMPRG loader from DLOAD.
    Load {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,

        /// Emergency loader file, directory, or zip.
        #[arg(long)]
        loader: PathBuf,

        /// Memory address where the ARMPRG loader will be uploaded and started.
        #[arg(long, default_value = "0x2a000000", value_parser = parse_u32)]
        address: u32,
    },
}

#[derive(Debug, Subcommand)]
enum EdlArmprgCommand {
    /// Check whether the loaded ARMPRG programmer is alive.
    Hello {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,
    },

    /// Open an ARMPRG raw flash partition.
    Open {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,

        /// Raw flash partition ID. Lumia eMMC uses 0x21.
        #[arg(long, default_value = "0x21", value_parser = parse_u16)]
        partition: u16,
    },

    /// Close the currently open ARMPRG raw flash partition.
    Close {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,
    },

    /// Write a file to raw flash through ARMPRG.
    Write {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,

        /// Raw flash partition ID. Lumia eMMC uses 0x21.
        #[arg(long, default_value = "0x21", value_parser = parse_u16)]
        partition: u16,

        /// Sector where the file write starts.
        #[arg(long, value_parser = parse_u32)]
        start_sector: u32,

        /// File to write.
        #[arg(long)]
        file: PathBuf,

        /// Required guard for destructive raw flash writes.
        #[arg(long)]
        confirm_raw_write: bool,
    },

    /// Reboot from ARMPRG mode.
    Reboot {
        /// USB vendor ID.
        #[arg(long, default_value_t = DEFAULT_EDL_VID, value_parser = parse_u16)]
        vid: u16,

        /// USB product ID.
        #[arg(long, default_value_t = DEFAULT_EDL_PID, value_parser = parse_u16)]
        pid: u16,
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

        /// Expected Root Key Hash as hex, for example from `flash param read RRKH`.
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

    /// Extract a raw sector range from an FFU.
    ExtractSectors {
        /// FFU path.
        path: PathBuf,

        /// First disk sector to extract.
        #[arg(value_parser = parse_u32)]
        start_sector: u32,

        /// Number of sectors to extract.
        #[arg(value_parser = parse_u32)]
        sector_count: u32,

        /// Output path for raw sector bytes.
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
enum FlashCommand {
    /// FlashApp parameter commands.
    Param {
        #[command(subcommand)]
        command: ParamCommand,
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Identify { vid, pid } => commands::identify::run(vid, pid, cli.wait, cli.debug),
        Command::Raw { vid, pid, commands } => commands::raw::run(vid, pid, cli.wait, &commands),
        Command::StayAwake { vid, pid } => commands::stay_awake::run(vid, pid, cli.wait),
        Command::Reset { vid, pid } => commands::reset::run(vid, pid, cli.wait),
        Command::Shutdown { vid, pid } => commands::shutdown::run(vid, pid, cli.wait),
        Command::FactoryReset {
            vid,
            pid,
            confirm_imei,
        } => commands::factory_reset::run(vid, pid, cli.wait, &confirm_imei),
        Command::SoftBrick {
            vid,
            pid,
            ffu,
            confirm_imei,
        } => commands::soft_brick::run(vid, pid, cli.wait, &ffu, &confirm_imei),
        Command::PrepareJailbreak { vid, pid, manifest } => {
            commands::jailbreak::prepare(vid, pid, cli.wait, &manifest)
        }
        Command::Jailbreak {
            lumia_vid,
            lumia_pid,
            edl_vid,
            edl_pid,
            manifest,
        } => commands::jailbreak::run(lumia_vid, lumia_pid, edl_vid, edl_pid, cli.wait, &manifest),
        Command::StockRestore {
            vid,
            pid,
            confirm_imei,
            dry_run,
            no_reset,
        } => commands::stock_restore::run(
            vid,
            pid,
            cli.wait,
            confirm_imei.as_deref(),
            dry_run,
            no_reset,
        ),
        Command::DisableSecureBoot {
            vid,
            pid,
            confirm_imei,
            dry_run,
            no_reset,
        } => commands::disable_secure_boot::run(
            vid,
            pid,
            cli.wait,
            confirm_imei.as_deref(),
            dry_run,
            no_reset,
        ),
        Command::Switch { command } => match command {
            SwitchCommand::Flash { vid, pid } => commands::switch::flash(vid, pid, cli.wait),
            SwitchCommand::PhoneInfo { vid, pid } => {
                commands::switch::phone_info(vid, pid, cli.wait)
            }
        },
        Command::Flash { command } => match command {
            FlashCommand::Param { command } => match command {
                ParamCommand::Read { vid, pid, name } => {
                    commands::param::read(vid, pid, cli.wait, cli.debug, &name)
                }
            },
        },
        Command::PhoneInfo { command } => match command {
            PhoneInfoCommand::Read { vid, pid, name } => {
                commands::phone_info::read(vid, pid, cli.wait, cli.debug, &name)
            }
        },
        Command::Gpt { command } => match command {
            GptCommand::Dump { vid, pid, format } => {
                commands::gpt::dump(vid, pid, cli.wait, format)
            }
        },
        Command::Lumiadb { command } => match command {
            LumiaDbCommand::Search { query } => commands::lumiadb::search(&query),
            LumiaDbCommand::Plan {
                model,
                product_code,
            } => commands::lumiadb::plan(&model, product_code.as_deref()),
            LumiaDbCommand::Check {
                model,
                product_code,
            } => commands::lumiadb::check(&model, product_code.as_deref()),
            LumiaDbCommand::Download {
                model,
                product_code,
                output,
            } => commands::lumiadb::download(&model, product_code.as_deref(), &output),
        },
        Command::Ffu { command } => match command {
            FfuCommand::Info { path } => commands::ffu::info(&path),
            FfuCommand::Partitions { path } => commands::ffu::partitions(&path),
            FfuCommand::Extract {
                path,
                partition,
                output,
            } => commands::ffu::extract(&path, &partition, &output),
            FfuCommand::ExtractSectors {
                path,
                start_sector,
                sector_count,
                output,
            } => commands::ffu::extract_sectors(&path, start_sector, sector_count, &output),
        },
        Command::Qcom { command } => match command {
            QcomCommand::ImageInfo { path, offset } => commands::qcom::image_info(&path, offset),
            QcomCommand::ScanLoaders { path, rrkh } => {
                commands::qcom::scan_loaders(&path, rrkh.as_deref())
            }
        },
        Command::Edl { command } => match command {
            EdlCommand::Probe { vid, pid } => commands::edl::probe(vid, pid, cli.wait),
            EdlCommand::Dload { command } => match command {
                EdlDloadCommand::Ping { vid, pid } => commands::edl::dload_ping(vid, pid, cli.wait),
                EdlDloadCommand::Rkh { vid, pid } => commands::edl::dload_rkh(vid, pid, cli.wait),
                EdlDloadCommand::Load {
                    vid,
                    pid,
                    loader,
                    address,
                } => commands::edl::dload_load(vid, pid, cli.wait, &loader, address),
            },
            EdlCommand::Armprg { command } => match command {
                EdlArmprgCommand::Hello { vid, pid } => {
                    commands::edl::armprg_hello(vid, pid, cli.wait)
                }
                EdlArmprgCommand::Open {
                    vid,
                    pid,
                    partition,
                } => commands::edl::armprg_open(vid, pid, cli.wait, partition),
                EdlArmprgCommand::Close { vid, pid } => {
                    commands::edl::armprg_close(vid, pid, cli.wait)
                }
                EdlArmprgCommand::Write {
                    vid,
                    pid,
                    partition,
                    start_sector,
                    file,
                    confirm_raw_write,
                } => commands::edl::armprg_write(
                    vid,
                    pid,
                    cli.wait,
                    partition,
                    start_sector,
                    &file,
                    confirm_raw_write,
                ),
                EdlArmprgCommand::Reboot { vid, pid } => {
                    commands::edl::armprg_reboot(vid, pid, cli.wait)
                }
            },
        },
    }
}
