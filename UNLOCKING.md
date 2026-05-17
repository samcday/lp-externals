# Unlocking Notes

Target: Lumia 520 / `fame`, a Spec A device in WPinternals terminology.

This project is not ready to unlock yet. The current goal is to collect the facts and files needed to port the WPinternals Spec A flow safely.

## Current Safe Commands

Use these to identify the device and gather unlock-relevant facts:

```sh
cargo run -- stay-awake
cargo run -- identify
cargo run -- gpt dump
cargo run -- switch flash
cargo run -- identify
cargo run -- param read RRKH
cargo run -- param read FAI
cargo run -- param read SS
cargo run -- param read FCS
cargo run -- param read DPI
cargo run -- param read FVER
cargo run -- switch phone-info
cargo run -- phone-info read TYPE
cargo run -- phone-info read CTR
```

`switch flash` and `switch phone-info` are mode-changing. The others above are read-only except `stay-awake`, which disables the BootMgr reboot timeout.

Observed values for this phone:

| Fact | Value |
| --- | --- |
| Product type | `RM-914` |
| Product code | `059S083` |
| Platform ID | `Nokia.MSM8227.P6036.1.2` |
| Root Key Hash | `f771e62af89994064f77cd3bc16829503bdf9a3d506d3facecaef3f808c868fd` |
| Flash app | `1.28` |

## LumiaDB Blob Planning

LumiaDB can provide the exact FFU, the model emergency package, and the shared engineering SBL3 file:

```sh
cargo run -- lumiadb plan --model RM-914 --product-code 059S083
cargo run -- lumiadb check --model RM-914 --product-code 059S083
cargo run -- lumiadb download --model RM-914 --product-code 059S083
```

Current LumiaDB plan:

| Blob | URL |
| --- | --- |
| FFU | `https://api.lumiadb.com/RM-914/RM914_3058.50000.1425.0001_RETAIL_eu_euro2_218_01_452872_prd_signed.ffu` |
| Emergency package | `https://api.lumiadb.com/RM-914/RM-914.zip` |
| Engineering SBL3 | `https://api.lumiadb.com/SBL3/Engineering-SBL3-Lumia-520-620-625-720-1320.bin` |

`lumiadb download` writes under `blobs/<model>/<product-code>/` and creates a `manifest.json`.

After downloading the FFU, inspect it offline:

```sh
cargo run -- ffu info blobs/RM-914/059S083/RM914_3058.50000.1425.0001_RETAIL_eu_euro2_218_01_452872_prd_signed.ffu
cargo run -- ffu partitions blobs/RM-914/059S083/RM914_3058.50000.1425.0001_RETAIL_eu_euro2_218_01_452872_prd_signed.ffu
```

## Required Files

WPinternals' `LumiaV1UnlockFirmware()` path needs:

| Resource | Why it matters |
| --- | --- |
| Stock FFU for the phone | Source for partition images and SBL1 Root Key Hash. Prefer exact RM/product variant. |
| Loaders folder | Contains Qualcomm emergency loaders. Must include one matching the phone Root Key Hash. |
| SBL3 / `.slb3` emergency file | Optional in the code path, but community Spec A guides commonly require the matching emergency SBL3. |
| Donor/supported FFU | Needed if the phone FFU OS version is not supported by WPinternals' `SecureBootHack-V1.1-EFIESP` patch definition. |

## Required Facts From Phone

Collect these before attempting any destructive step:

| Fact | Command | Use |
| --- | --- | --- |
| Root Key Hash | `param read RRKH` | Match emergency loader and verify FFU SBL1 RKH. |
| Flash app version | `param read FAI` and `identify` in FlashApp | WPinternals wants FlashApp `>= 1.28` for V1 unlock. |
| Security status | `param read SS` | Tells whether bootloader is already effectively unlocked/authenticated/RDC. |
| Security flags | `param read FCS` | Extra fuse/security detail. |
| Platform ID | `param read DPI` or FlashApp `identify` | Useful for matching resources and sanity checks. |
| Firmware version | `param read FVER` | Helps locate correct FFU and donor FFU. |
| Product type | `phone-info read TYPE` | Exact RM model for LumiaDB lookup. |
| Product code | `phone-info read CTR` | Exact firmware variant for LumiaDB lookup. |
| GPT layout | `gpt dump` | Confirms partition names and sector ranges before any patch/flash logic. |

## WPinternals Spec A Flow Summary

The high-level `LumiaV1UnlockFirmware()` sequence is:

1. Parse stock FFU.
2. Read or derive GPT.
3. Patch GPT for the bootloader hack partitions/flags.
4. Parse and patch `SBL2`, `SBL3`, and `UEFI`.
5. Read phone Root Key Hash and compare it with FFU `SBL1` Root Key Hash.
6. Find a matching Qualcomm emergency loader.
7. If locked, switch into Qualcomm emergency download/flash.
8. Flash patched bootloader partitions.
9. Reboot to Lumia Flash/BootMgr.
10. Run the UEFI secure boot unlock stage.

Do not start steps 7-10 until FFU parsing, RKH matching, and patched image generation are implemented and reviewable offline.
