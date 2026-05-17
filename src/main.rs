mod commands;
mod ffu;
mod gpt;
mod lumiadb;
mod qcom;
mod uefi;
mod util;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{
    commands::gpt::DumpFormat as GptDumpFormat,
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Identify { vid, pid } => commands::identify::run(vid, pid, cli.wait, cli.debug),
        Command::Raw { vid, pid, commands } => commands::raw::run(vid, pid, cli.wait, &commands),
        Command::StayAwake { vid, pid } => commands::stay_awake::run(vid, pid, cli.wait),
        Command::Reset { vid, pid } => commands::reset::run(vid, pid, cli.wait),
        Command::Shutdown { vid, pid } => commands::shutdown::run(vid, pid, cli.wait),
        Command::Switch { command } => match command {
            SwitchCommand::Flash { vid, pid } => commands::switch::flash(vid, pid, cli.wait),
            SwitchCommand::PhoneInfo { vid, pid } => {
                commands::switch::phone_info(vid, pid, cli.wait)
            }
        },
        Command::Param { command } => match command {
            ParamCommand::Read { vid, pid, name } => {
                commands::param::read(vid, pid, cli.wait, cli.debug, &name)
            }
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
        },
        Command::Qcom { command } => match command {
            QcomCommand::ImageInfo { path, offset } => commands::qcom::image_info(&path, offset),
            QcomCommand::ScanLoaders { path, rrkh } => {
                commands::qcom::scan_loaders(&path, rrkh.as_deref())
            }
        },
    }
}
