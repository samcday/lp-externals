# Unlocking Notes

Target: Lumia 520 / `fame`, a Spec A device in WPinternals terminology.

This project is not ready to unlock yet. The current goal is to collect the facts and files needed to port the WPinternals Spec A flow safely.

## Current Safe Commands

Use these to identify the device and gather unlock-relevant facts:

```sh
cargo run -- raw NOKD
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
```

`switch flash` is mode-changing. The others above are read-only except `NOKD`, which disables the BootMgr reboot timeout.

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
