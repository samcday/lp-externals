# Unlocking Notes

Target: Lumia 520 / `fame`, a Spec A device in WPinternals terminology.

This project is not ready to unlock yet. The current goal is to collect facts, download the correct blobs, validate them offline, and port the WPinternals Spec A flow safely before any destructive flashing exists in `lp-externals`.

## Current Device Facts

Observed values for this phone:

| Fact | Value |
| --- | --- |
| Product type | `RM-914` |
| Product code | `059S083` |
| Platform ID | `Nokia.MSM8227.P6036.1.2` |
| Root Key Hash | `f771e62af89994064f77cd3bc16829503bdf9a3d506d3facecaef3f808c868fd` |
| BootMgr app | `1.16` |
| FlashApp protocol/app | `1.15` / `1.28` |
| PhoneInfo variables | `TYPE=RM-914`, `CTR=059S083` |

Current FlashApp security status from `param read SS`:

| Field | Value |
| --- | --- |
| platform secure boot | true |
| secure FFU | true |
| RDC | false |
| authenticated | false |
| UEFI secure boot | true |

That means the device is still locked in the normal retail sense.

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

`switch flash`, `switch phone-info`, and `reset` are mode-changing. The other commands above are read-only except `stay-awake`, which disables the BootMgr timeout watchdog.

## Blob Types

### Stock FFU

FFU means Full Flash Update. Treat it as a full signed Lumia flash image container, not an incremental OTA. It is closer to a full Odin firmware package than a small over-the-air delta.

The FFU contains:

| Content | Purpose |
| --- | --- |
| security header / catalog / hash table | signed metadata and integrity material |
| image header | image-level metadata |
| store header | target platform, write descriptors, validate descriptors |
| GPT and partition payload chunks | raw contents for partitions such as `SBL1`, `SBL2`, `SBL3`, `UEFI`, `TZ`, `RPM`, `WINSECAPP`, `EFIESP`, `MainOS` |

The exact stock FFU matters because WPinternals checks that the phone Root Key Hash matches the FFU `SBL1` Root Key Hash.

### LumiaDB

LumiaDB is a curated archive/index of stock Lumia firmware and related recovery blobs. It is analogous to third-party firmware index sites for other phone ecosystems.

For this phone, LumiaDB resolves from `TYPE + CTR`:

```text
TYPE = RM-914
CTR  = 059S083
```

Current LumiaDB plan:

| Blob | URL |
| --- | --- |
| Stock FFU | `https://api.lumiadb.com/RM-914/RM914_3058.50000.1425.0001_RETAIL_eu_euro2_218_01_452872_prd_signed.ffu` |
| Emergency package | `https://api.lumiadb.com/RM-914/RM-914.zip` |
| Engineering SBL3 | `https://api.lumiadb.com/SBL3/Engineering-SBL3-Lumia-520-620-625-720-1320.bin` |

Current check results:

| Blob | Size |
| --- | --- |
| FFU | `1674575872` bytes |
| Emergency package | `1469102` bytes |
| Engineering SBL3 | `350080` bytes |

### Emergency Package And Loaders

The LumiaDB emergency package for `RM-914` contains:

```text
FAST8930_RM914.hex
RM914_msimage_v1.0.mbn
RM914_prg_v1.0.hex
```

These are service/recovery artifacts. Some were public through recovery/service tooling, and some likely came from OEM/service-center or grey-market archives. The important practical point is that they are signed Qualcomm/Nokia emergency loader material.

WPinternals V1 scans a loaders folder and looks for files that:

| Check | Reason |
| --- | --- |
| are `<= 0x80000` bytes | filters out large non-loader blobs |
| parse as Intel HEX or raw Qualcomm partition image | supports `.hex` emergency loaders |
| contain a certificate chain whose root hash matches phone `RRKH` | device will accept only matching signed loaders |
| contain Unicode `QHSUSB_ARMPRG` | identifies the older V1 ARMPRG-style emergency loader |

This is related to bkerler/edl's signed programmer collections, but not identical. bkerler/edl mostly curates Firehose programmers for Sahara/Firehose flows. WPinternals Spec A uses the older Qualcomm emergency download / ARMPRG-style path.

### Engineering SBL3

Engineering SBL3 is not the same as a donor FFU.

Engineering SBL3 is an alternate `SBL3` image. WPinternals can use it instead of the `SBL3` from the stock FFU, as long as it fits in the target `SBL3` partition. It still gets patched before flashing.

Engineering SBL3 is useful because it exposes engineering behavior, especially mass-storage related behavior, that retail SBL3 usually does not expose.

Likely provenance: internal engineering/service-lab artifacts or grey-market leaks, not normal customer firmware.

### Donor / Supported FFU

Donor FFU is a separate concept from engineering SBL3.

WPinternals calls this `SupportedFFUPath`. It is used when the target FFU's EFIESP OS version does not match known patch definitions such as `SecureBootHack-V1.1-EFIESP`.

The donor FFU provides a compatible `mobilestartup.efi` from its `EFIESP`. WPinternals copies that into the target EFIESP and then applies the known patch.

So:

| Resource | Meaning |
| --- | --- |
| stock FFU | exact phone firmware and partition source |
| emergency package | signed emergency loader material |
| engineering SBL3 | alternate SBL3 with engineering features |
| donor/supported FFU | source of patch-compatible EFIESP boot files |

## Why Qualcomm Emergency Mode Is Needed

Locked Lumia FlashApp enforces secure FFU rules. It will not normally raw-write locally patched `SBL2`, `SBL3`, `UEFI`, GPT, or arbitrary sectors.

The locked Spec A flow therefore uses emergency recovery:

1. Use FlashApp enough to induce a recoverable boot failure.
2. Device appears as Qualcomm Emergency Download.
3. Send a matching signed emergency loader.
4. Loader exposes a lower-level emergency flashing protocol.
5. Use that protocol to raw-write the patched boot chain.

For this device family, call it Qualcomm emergency download / DLOAD / ARMPRG rather than assuming newer Sahara/Firehose. Newer WPinternals V2 paths use Sahara to load a programmer and Firehose afterward, but the V1 path uses `QualcommDownload` and `QualcommFlasher` style code.

## The Empty FFU Chunk Trick

WPinternals' `PerformSoftBrick()` path does not send a whole FFU.

It does this:

1. Read and send the complete header region from a valid signed stock FFU.
2. Send one all-zero payload chunk of `0x20000` bytes.
3. Reset the phone.

The FFU header region includes signed metadata, catalog, hash table, image header, store header, write descriptors, and validate descriptors. The one all-zero chunk is not independently signed by us.

The important FlashApp behavior is that it accepts the signed FFU metadata first, then accepts streamed payload chunks afterward. In the WPinternals V1 send path, payload `Options` is `0`; the comment says `1 = verify`. The tool intentionally does not complete the FFU transaction. It writes one bogus payload chunk according to the FFU write descriptors and immediately resets.

This appears to corrupt enough critical boot data that the next boot falls into Qualcomm emergency recovery.

This is not arbitrary code execution in FlashApp. It is abuse of a legitimate signed FFU streaming path to trigger a recoverable emergency state.

## Exploit Boundaries

The Spec A flow is a chain of trust-boundary crossings rather than one magic exploit.

| Boundary | What happens |
| --- | --- |
| FlashApp soft brick | valid signed FFU headers plus one bogus streamed chunk trigger emergency recovery |
| Emergency loader acceptance | device accepts only a signed loader with matching Root Key Hash |
| Raw emergency flashing | accepted loader exposes low-level flashing outside normal secure FFU policy |
| GPT/SBL/UEFI patching | raw writer installs a modified boot chain |
| EFIESP/BCD patching | UEFI/OS boot policy is modified for unlocked/test-signing behavior |

Emergency mode itself is a recovery feature. The unlock abuses recovery architecture and service loaders to gain a raw writer, then installs patched boot-chain pieces.

## WPinternals Spec A Flow Summary

High-level `LumiaV1UnlockFirmware()` sequence:

1. Parse stock FFU.
2. Decide whether the current FFU EFIESP is directly patchable or whether a donor/supported FFU is needed.
3. Read or derive GPT.
4. Restore backup boot partitions into low sectors if needed, because the V1 emergency flasher has hardcoded address limits.
5. Patch GPT for the Spec A bootloader hack.
6. Parse stock `SBL1` and extract its Root Key Hash.
7. Read phone Root Key Hash and compare it with stock FFU `SBL1` Root Key Hash.
8. Parse and patch `SBL2`.
9. Generate the one-sector `HACK` shim using data from stock `SBL1`.
10. Parse external engineering `SBL3` if supplied, otherwise stock `SBL3`.
11. Patch `SBL3`.
12. Parse and patch `UEFI`.
13. Find a matching Qualcomm emergency loader.
14. If already unlocked, flash patched pieces from FlashApp.
15. If locked, soft-brick into Qualcomm Emergency Download.
16. Send the matching emergency loader.
17. Use emergency flash protocol to write the patched boot chain.
18. Reboot back to Lumia Flash/BootMgr.
19. Run the UEFI/EFIESP secure boot unlock stage.
20. Continue boot to normal OS.

Do not implement destructive steps until offline patch generation, RKH matching, loader matching, and dry-run reporting are implemented and reviewable.

## GPT Hack Details

The Spec A GPT hack is implemented by `GPT.InsertHack()` in WPinternals.

It finds `SBL1` and `SBL2`, then creates a one-sector partition named `HACK`.

Before:

```text
SBL1: sectors A..B
SBL2: sectors C..D, normal SBL2 type/guid
```

After:

```text
SBL1: sectors A..B-1
HACK: sector B, carries SBL2's original type/guid
SBL2: sectors C..D, type/guid changed to 0x74747474747474747474747474747474
```

WPinternals also rebuilds the GPT CRCs.

The effect is that stock `SBL1` can be tricked into loading the `HACK` sector as if it were `SBL2`, because the `HACK` partition now wears `SBL2`'s old GPT identity.

## The HACK Sector

`SBL1.GenerateExtraSector()` creates the one-sector shim written into the `HACK` partition.

It uses patterns found in stock `SBL1` to discover:

| Item | Use |
| --- | --- |
| partition-loader table offset | copied and modified into the shim |
| shared memory / global security flag address | target for disabling security state |
| return address into SBL1 flow | branch back into normal loader execution |

The generated sector contains ARM code and a copied chunk of the partition-loader table. Conceptually it:

1. Disables a global security-enabled state.
2. Rewrites enough partition-loader metadata that the real `SBL2` can be located under its fake GUID.
3. Returns into the normal `SBL1` loader path.

This is why the GPT patch and the HACK sector must be flashed together.

## SBL2 Patch

`SBL2.Patch()` searches for an ARM instruction pattern and replaces one instruction with:

```text
00 00 A0 E3
```

That is ARM `MOV R0, #0`.

Conceptually, it forces a security-check helper to return zero, weakening early boot enforcement.

## SBL3 Patch

`SBL3.Patch()` performs the same class of patch:

```text
find a security-check pattern
replace return value load with MOV R0, #0
```

If engineering SBL3 is supplied, WPinternals patches that image. Otherwise it patches stock `SBL3` from the FFU.

## UEFI Patch

`UEFI.Patch()` opens the UEFI firmware volume and modifies DXE modules:

```text
SecurityDxe
SecurityServicesDxe
```

For `SecurityDxe`, it replaces the matched function body with:

```text
00 00 A0 E3 1E FF 2F E1
```

That is roughly:

```text
MOV R0, #0
BX LR
```

For `SecurityServicesDxe`, it changes conditional branch behavior to bypass image/authentication failure paths.

Conceptually:

```text
SBL2/SBL3 patches weaken early boot-chain enforcement.
UEFI patches weaken UEFI secure boot/image authentication enforcement.
EFIESP patches later make the OS boot path usable under the unlocked policy.
```

## Qualcomm Emergency Flash Stage

After the soft-brick, WPinternals expects the phone to appear as Qualcomm Emergency Download.

It then:

1. Finds possible loaders for the phone Root Key Hash.
2. Sends a loader to phone memory.
3. Starts that loader.
4. Waits for Qualcomm Emergency Flash mode.
5. Opens the raw flash partition.
6. Writes the patched payload.

The V1 emergency flasher writes:

| Item | Source |
| --- | --- |
| MBR | stock FFU |
| GPT | rebuilt patched GPT |
| HACK sector | generated from stock `SBL1` and real `SBL2` header |
| SBL2 | patched stock `SBL2` |
| SBL3 | patched engineering or stock `SBL3` |
| UEFI | patched stock `UEFI` |
| SBL1 | stock FFU `SBL1`, partial range |
| TZ | stock FFU `TZ` |
| RPM | stock FFU `RPM` |
| WINSECAPP | stock FFU `WINSECAPP`, with a flasher bounds workaround |

## EFIESP / UEFI Unlock Stage

After the boot-chain flash, WPinternals runs `LumiaUnlockUEFI()`.

This stage assumes the phone is in Flash mode and works on `EFIESP`/BCD state.

It:

1. Parses profile/stock FFU.
2. Confirms platform ID compatibility if the bootloader is still secure.
3. Chooses `SecureBootHack-V1.1-EFIESP` for Spec A.
4. Patches `EFIESP` files.
5. If the target `mobilestartup.efi` is unsupported, copies `mobilestartup.efi` from a donor/supported FFU and patches again.
6. Edits BCD to set no-integrity/test-signing style boot elements.
7. Adds or rearranges marker/backup partitions such as `BACKUP_BS_NV`, `BACKUP_EFIESP`, and `IS_UNLOCKED` as needed.

## Required Facts From Phone

Collect these before attempting any destructive step:

| Fact | Command | Use |
| --- | --- | --- |
| Root Key Hash | `param read RRKH` | Match emergency loader and verify FFU `SBL1` RKH |
| Flash app version | `param read FAI` and `identify` in FlashApp | WPinternals wants FlashApp `>= 1.28` for V1 unlock |
| Security status | `param read SS` | Detect already unlocked/authenticated/RDC/secure-FFU-disabled cases |
| Security flags | `param read FCS` | Extra fuse/security detail |
| Platform ID | `param read DPI` or FlashApp `identify` | Match FFU/platform profile |
| Firmware version | `param read FVER` | Helps locate FFU and donor FFU, if available |
| Product type | `phone-info read TYPE` | Exact RM model for LumiaDB lookup |
| Product code | `phone-info read CTR` | Exact firmware variant for LumiaDB lookup |
| GPT layout | `gpt dump` | Confirms partition names and sector ranges |

## Offline Validation Needed Before Unlock

Implement these before any destructive `unlock` command:

1. Parse FFU headers and GPT.
2. Extract partitions from FFU by name.
3. Parse Qualcomm partition headers for `SBL1` and emergency loaders.
4. Extract FFU `SBL1` Root Key Hash.
5. Compare phone `RRKH` to FFU `SBL1` Root Key Hash.
6. Unpack emergency package and find matching loader.
7. Confirm loader contains `QHSUSB_ARMPRG` and matching RKH.
8. Confirm engineering SBL3 fits target `SBL3` partition.
9. Dry-run `SBL2`, `SBL3`, and `UEFI` patch pattern searches.
10. Dry-run GPT `HACK` insertion and verify CRC rebuild.
11. Report all sector ranges that would be written.
12. Refuse to continue if any ambiguity or mismatch exists.

## `prepare-unlock` Scope

The planned porcelain command is documented in `plans/lp-externals-prepare-unlock.md`.

Intended shape:

```sh
lp-externals prepare-unlock <manifest>
```

It should:

1. Switch to PhoneInfoApp if needed.
2. Read `TYPE` and `CTR`.
3. Resolve exactly one LumiaDB stock FFU entry.
4. Cache blobs under XDG cache directories.
5. Validate FFU/emergency/SBL3 basics.
6. Write an authoritative manifest for a later `unlock <manifest>` command.

It should not flash, patch, or enter Qualcomm emergency mode.

## Destructive Work Not Yet Implemented

Do not implement or run these until all offline checks above exist:

- `NOKXFS` / secure flash writes beyond controlled read-only experiments
- FFU soft-brick trigger
- Qualcomm emergency loader upload
- Qualcomm emergency raw flashing
- GPT patch flashing
- SBL2/SBL3/UEFI patch flashing
- EFIESP/BCD patch writes

The immediate safe path is still: identify, download, parse, extract, validate, and generate reviewable dry-run artifacts.
