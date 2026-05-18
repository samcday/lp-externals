# `jailbreak` Porcelain Plan

## Goal

`prepare-jailbreak` is the non-destructive manifest/artifact generator for the Lumia Spec A unlock path. `jailbreak <manifest>` is the destructive/resumable executor for that prepared manifest.

## CLI Shape

```sh
lp-externals prepare-jailbreak <manifest>
lp-externals jailbreak <manifest>
```

`prepare-jailbreak` performs all read-only/device-query work and all local binary artifact generation, but must not write persistent phone state.

`jailbreak <manifest>` treats the manifest as the explicit user confirmation and resumes from Lumia, DLOAD, or ARMPRG mode where possible.

Do not expose model, product-code, FFU path, emergency-loader path, SBL3 path, or donor FFU flags in the first porcelain version. The happy path should be determined from the attached phone.

## Internal Stages

1. Switch to PhoneInfoApp and read `TYPE`, `CTR`, and `IMEI`.
2. Resolve exactly one LumiaDB stock FFU from `TYPE + CTR`.
3. Cache required blobs under XDG cache directories.
4. Parse and validate the stock FFU.
5. Switch to FlashApp and read FlashApp facts.
6. Validate platform, eMMC size, flash app version, security status, and RRKH.
7. Match emergency loaders from the LumiaDB emergency package.
8. Generate all offline jailbreak artifacts.
9. Report the complete sector write plan.
10. Write a machine-readable manifest with blob/artifact hashes and ARMPRG write quirks.

## Required Cached Inputs

Cache layout should remain compatible with `stock-restore`:

```text
$XDG_CACHE_HOME/lp-externals/lumiadb/<TYPE>/<CTR>/
```

Fallback when `XDG_CACHE_HOME` is unset:

```text
~/.cache/lp-externals/lumiadb/<TYPE>/<CTR>/
```

Required inputs for `RM-914` / `059S083`:

```text
RM914_3058.50000.1425.0001_RETAIL_eu_euro2_218_01_452872_prd_signed.ffu
RM-914.zip
Engineering-SBL3-Lumia-520-620-625-720-1320.bin
```

## Preflight Gates

Before any destructive operation, `jailbreak` must prove:

- Phone identity is unambiguous: `TYPE`, `CTR`, `IMEI` are present and non-empty.
- LumiaDB exact match count for `TYPE + CTR` is exactly one.
- Stock FFU parses and exposes GPT, platform ID, chunks, headers, and required partitions.
- Emergency ZIP opens and contains at least one candidate loader.
- Engineering SBL3 exists, is nonzero, parses as SBL3, and fits the target SBL3 partition.
- FlashApp protocol/app version is compatible with WPinternals Spec A requirements; for Lumia 520 this means FlashApp `>= 1.28`.
- FlashApp platform is compatible with the stock FFU platform.
- FFU mapped disk size fits the reported eMMC size.
- Phone `RRKH` is 32 bytes.
- Stock FFU `SBL1` root key hash matches phone `RRKH`, unless RRKH is all zero on an engineering device.
- At least one emergency loader contains UTF-16 `QHSUSB_ARMPRG` and has matching root key hash.
- All patch patterns match exactly as expected.
- All patched artifacts fit their target partitions.
- The sector write plan is valid, aligned, and limited to the intended ranges.

## Offline Artifact Generation

The prepare path must build the same artifacts the later destructive EDL phase will need:

| Artifact | Source | Operation |
| --- | --- | --- |
| MBR | stock FFU sectors | copy sector 0 |
| GPT | stock/current GPT | insert Spec A `HACK` partition and rebuild CRCs |
| HACK sector | stock `SBL1` + patched `SBL2` header | generate one-sector shim |
| SBL2 | stock FFU `SBL2` | patch security-check pattern |
| SBL3 | engineering SBL3, fallback stock `SBL3` later | patch security-check pattern |
| UEFI | stock FFU `UEFI` | patch `SecurityDxe` and `SecurityServicesDxe` |
| SBL1 | stock FFU `SBL1` | write partial range excluding stolen HACK sector |
| TZ | stock FFU `TZ` | copy |
| RPM | stock FFU `RPM` | copy |
| WINSECAPP | stock FFU `WINSECAPP` | copy with ARMPRG bounds workaround |

The manifest output includes byte sizes, sector ranges, source artifact hashes, and whether each blob is copied or patched.

## Destructive Executor

`jailbreak <manifest>` detects the current mode and resumes accordingly:

1. In Lumia mode, validate `TYPE`/`CTR`/`RRKH`, then soft-brick to DLOAD.
2. In DLOAD mode, read RKH, compare with the manifest, upload the matching ARMPRG loader to `0x2A000000`, and start it.
3. In ARMPRG mode, verify all manifest hashes, open partition `0x21`, flash the prepared boot-chain write plan, close the partition, and reboot.

The soft-brick primitive should intentionally use secure FFU sync v1 for the zero chunk, matching WPinternals `PerformSoftBrick()`, even when FlashApp reports sync v2 support.

The ARMPRG write plan must encode known loader quirks: GPT starts at sector `1` with length `0x41ff`, and `WINSECAPP` writes are capped at `0x1e7fe00`.

## Plumbing Split

Add a separate `soft-brick` plumbing command before full `jailbreak`:

```sh
lp-externals soft-brick --ffu <stock.ffu> --confirm-imei <IMEI>
```

`soft-brick` should only do the destructive-operation guard and FlashApp primitive:

1. Switch to PhoneInfoApp.
2. Read and validate IMEI.
3. Parse the provided FFU.
4. Switch to FlashApp.
5. Send FFU header v1.
6. Send one zero FFU payload chunk v1.
7. Reset.

It must not perform LumiaDB lookup, emergency-loader validation, GPT patching, SBL patching, UEFI patching, or EDL protocol work.

## EFIESP Stage

Full WPinternals-equivalent jailbreak also needs the EFIESP/UEFI unlock stage. Initial Spec A plumbing is implemented as `disable-secure-boot`:

1. Patch `EFIESP` FAT contents, especially `mobilestartup.efi`.
2. Use donor/supported FFU `mobilestartup.efi` if the stock FFU version is unsupported.
3. Edit BCD to set the no-integrity/test-signing element.
4. Split `UEFI_BS_NV` into `BACKUP_BS_NV` plus a new `UEFI_BS_NV` when needed.
5. Flash the `SBA` NV payload, changed GPT, and WPinternals-style split EFIESP payload through FlashApp `NOKF`.

The current stock RM-914 FFU is Windows Phone 8.1, while WPinternals `SecureBootHack-V1.1-EFIESP` targets Windows 10 Mobile `mobilestartup.efi` versions. The implementation uses the LumiaDB RM-1085 donor FFU when the stock hash is unsupported.

## Failure Policy

Fail closed. Do not guess when:

- PhoneInfoApp cannot be reached.
- Phone identity cannot be read during prepare.
- LumiaDB resolution is missing or ambiguous.
- Any required blob is unavailable or invalid.
- RRKH validation fails.
- No matching ARMPRG loader exists.
- Any patch pattern is missing or ambiguous.
- Any patched artifact would exceed its target partition.
- The write plan contains unexpected overlaps or out-of-range writes.

If a failure occurs before destructive work, leave the phone in the current app and print the recovery command, usually `lp-externals reset`.
