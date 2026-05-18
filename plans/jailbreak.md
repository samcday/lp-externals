# `jailbreak` Porcelain Plan

## Goal

`jailbreak` is the all-in-one user-facing command for the Lumia Spec A unlock path. It should absorb the old `prepare-unlock` idea internally: detect the attached phone, resolve/cache the exact LumiaDB inputs, validate and patch all local artifacts, report the planned writes, and only then cross into destructive operations.

The command should eventually eat the whole elephant. The first shipped milestone should be narrower: prove the complete local dry-run path, then transition the phone into Qualcomm emergency download mode. EDL loader upload and ARMPRG flashing can be implemented independently afterward.

## CLI Shape

```sh
lp-externals jailbreak --dry-run
lp-externals jailbreak --confirm-imei <IMEI>
```

`--dry-run` must perform all read-only/device-query work and all local binary artifact generation, but must not write persistent phone state.

`--confirm-imei` is required before any destructive operation. The confirmation must exactly match the IMEI read from PhoneInfoApp.

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
10. If not `--dry-run`, require IMEI confirmation and start the destructive stage.

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

The dry-run path must build the same artifacts the later destructive EDL phase will need:

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

The dry-run output should include byte sizes, sector ranges, source partition names, and whether each blob is copied or patched.

## First Destructive Milestone

The first destructive `jailbreak` implementation should stop after entering Qualcomm emergency download mode. It should not upload a loader or flash raw sectors yet.

After all preflight gates pass and `--confirm-imei` matches:

1. Switch to FlashApp.
2. Send the complete signed FFU header through `NOKXFS` header v1.
3. Send exactly one zero-filled FFU chunk through `NOKXFS` payload v1.
4. Reset the phone.
5. Report that the phone should now enumerate in Qualcomm emergency download mode.

The soft-brick primitive should intentionally use secure FFU sync v1 for the zero chunk, matching WPinternals `PerformSoftBrick()`, even when FlashApp reports sync v2 support.

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

## Later EDL Stage

Once a separate EDL worker exists, `jailbreak` can continue from Qualcomm emergency download mode:

1. Detect DLOAD / ARMPRG USB transport.
2. Optionally read RKH from DLOAD and compare with the already validated RRKH.
3. Upload a matching signed ARMPRG loader to `0x2A000000`.
4. Start the loader.
5. Enter Qualcomm emergency flash mode.
6. Open partition `0x21`.
7. Flash the prepared boot-chain write plan.
8. Reboot to Lumia BootMgr/FlashApp.

## Later EFIESP Stage

Full WPinternals-equivalent jailbreak also needs the EFIESP/UEFI unlock stage:

1. Patch `EFIESP` FAT contents, especially `mobilestartup.efi`.
2. Use donor/supported FFU `mobilestartup.efi` if the stock FFU version is unsupported.
3. Edit BCD to set the no-integrity/test-signing element.
4. Handle `BACKUP_BS_NV`, `UEFI_BS_NV`, `BACKUP_EFIESP`, and unlock marker partition layout.
5. Flash EFIESP/NV/GPT changes through the now-unlocked FlashApp path.

The current stock RM-914 FFU is Windows Phone 8.1, while WPinternals `SecureBootHack-V1.1-EFIESP` targets Windows 10 Mobile `mobilestartup.efi` versions. That donor requirement must be resolved before claiming full jailbreak completion.

## Failure Policy

Fail closed. Do not guess when:

- PhoneInfoApp cannot be reached.
- IMEI cannot be read or confirmation does not match.
- LumiaDB resolution is missing or ambiguous.
- Any required blob is unavailable or invalid.
- RRKH validation fails.
- No matching ARMPRG loader exists.
- Any patch pattern is missing or ambiguous.
- Any patched artifact would exceed its target partition.
- The write plan contains unexpected overlaps or out-of-range writes.

If a failure occurs before destructive work, leave the phone in the current app and print the recovery command, usually `lp-externals reset`.
