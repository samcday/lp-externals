# `prepare-unlock` Porcelain Plan

## Goal

Add an opinionated happy-path command that prepares all local inputs needed by a future `unlock` porcelain command.

```sh
lp-externals prepare-unlock <manifest>
```

This command should wrap existing plumbing instead of exposing every lower-level choice again. It should detect the attached phone, resolve the correct LumiaDB blobs, cache them according to XDG guidelines, validate the prepared inputs, and write an authoritative manifest consumed later by `lp-externals unlock <manifest>`.

It must not patch, flash, boot loaders, or write persistent phone state. Temporary UEFI app switching is acceptable when needed to read PhoneInfo.

## CLI Shape

```sh
lp-externals prepare-unlock <manifest>
```

No `--model`, `--product-code`, `--output`, `--skip-check`, or similar plumbing flags for the first version.

The single positional `manifest` path is the handoff artifact. The command should be idempotent and write the manifest atomically:

```text
<manifest>.tmp -> rename to <manifest>
```

## XDG Cache Layout

Downloaded blobs and cached LumiaDB metadata should live under:

```text
$XDG_CACHE_HOME/lp-externals/
```

Fallback when `XDG_CACHE_HOME` is unset:

```text
~/.cache/lp-externals/
```

Tentative layout:

```text
~/.cache/lp-externals/
  lumiadb/
    database.json
    RM-914/
      059S083/
        RM914_3058.50000.1425.0001_RETAIL_eu_euro2_218_01_452872_prd_signed.ffu
        RM-914.zip
        Engineering-SBL3-Lumia-520-620-625-720-1320.bin
```

The manifest should use absolute blob paths so a later `unlock <manifest>` works from any current directory.

## Detection Flow

1. Open the current Lumia UEFI USB interface.
2. Send `NOKV` and parse the active app type.
3. If BootMgr:
   - send `NOKD` to disable the timeout
   - send `NOKP` to switch to PhoneInfoApp
   - tolerate expected USB disconnect/re-enumeration
   - wait/retry until PhoneInfoApp is active
4. If FlashApp:
   - send `NOKP` to switch to PhoneInfoApp
   - tolerate expected USB disconnect/re-enumeration
   - wait/retry until PhoneInfoApp is active
5. If PhoneInfoApp:
   - continue directly
6. Verify `NOKV` reports PhoneInfoApp.
7. Read PhoneInfo variables with `NOKXPH`:
   - `TYPE`, for example `RM-914`
   - `CTR`, for example `059S083`

`TYPE` and `CTR` are required. If either is missing or empty, fail.

Do not automatically reset the phone afterward. Print a clear note that the phone is left in PhoneInfoApp and `lp-externals reset` can be used if desired.

## LumiaDB Resolution

Use detected `TYPE` and `CTR` as the authoritative lookup key.

Resolution rule:

```text
LumiaDB exact match count for (hardware_model == TYPE, product_code == CTR) must equal 1.
```

If zero matches, fail and print the detected values.

If multiple matches, fail and print candidate firmware rows. Do not guess.

For the normal Lumia 520/RM-914 case this should resolve to one FFU, the model emergency package, and the known engineering SBL3 blob.

## Blob Checks And Downloads

For the resolved plan:

1. Build expected URLs:
   - FFU from LumiaDB firmware filename
   - emergency package from model zip URL
   - SBL3 from the known family mapping
2. `HEAD` each URL and require success.
3. Download missing blobs into the XDG cache using the current `gosh-dl` downloader.
4. Existing files may be reused if they pass local validation.

There are no authoritative LumiaDB checksums currently known. Treat size and parse validation as sanity checks, not cryptographic verification.

## Local Validation

Before writing the manifest, validate prepared inputs:

- FFU exists and is nonzero.
- FFU parses with the existing `ParsedFfu` code.
- FFU platform ID is present.
- FFU GPT can be parsed.
- Emergency package exists and is nonzero.
- SBL3 exists and is nonzero.

Future validation can add:

- emergency package structure checks
- FFU Root Key Hash extraction
- RKH comparison against phone RRKH
- loader/SBL matching checks
- SBL3 compatibility checks

## Manifest Schema

Tentative JSON shape:

```json
{
  "schema": 1,
  "tool": "lp-externals",
  "purpose": "lumia-unlock-preparation",
  "detected": {
    "model": "RM-914",
    "productCode": "059S083"
  },
  "lumiadb": {
    "phone": "Lumia 520",
    "variant": "Global",
    "firmware": "3058.50000.1425.0001",
    "os": "Windows Phone 8.1 - 8.10.12393"
  },
  "blobs": {
    "ffu": {
      "url": "https://api.lumiadb.com/RM-914/RM914_3058.50000.1425.0001_RETAIL_eu_euro2_218_01_452872_prd_signed.ffu",
      "path": "/home/user/.cache/lp-externals/lumiadb/RM-914/059S083/RM914_3058.50000.1425.0001_RETAIL_eu_euro2_218_01_452872_prd_signed.ffu",
      "size": 1674575872
    },
    "emergency": {
      "url": "https://api.lumiadb.com/RM-914/RM-914.zip",
      "path": "/home/user/.cache/lp-externals/lumiadb/RM-914/059S083/RM-914.zip",
      "size": 1469102
    },
    "sbl3": {
      "url": "https://api.lumiadb.com/SBL3/Engineering-SBL3-Lumia-520-620-625-720-1320.bin",
      "path": "/home/user/.cache/lp-externals/lumiadb/RM-914/059S083/Engineering-SBL3-Lumia-520-620-625-720-1320.bin",
      "size": 350080
    }
  },
  "ffu": {
    "platformId": "Nokia.MSM8227.P6036.1.2",
    "chunkSize": 131072,
    "totalChunks": 12776
  }
}
```

The manifest is the authoritative input to future unlock porcelain. It should contain enough detail for `unlock` to avoid repeating LumiaDB resolution and blob discovery.

## User Output

Target output style:

```text
active app: BootManager
disabled reboot timeout (NOKD)
switching to PhoneInfoApp (NOKP)
active app: PhoneInfoApp

detected:
  model: RM-914
  product code: 059S083

LumiaDB match:
  phone: Lumia 520
  variant: Global
  firmware: 3058.50000.1425.0001
  os: Windows Phone 8.1 - 8.10.12393

checking:
  ffu: 200 OK size=1674575872
  emergency: 200 OK size=1469102
  sbl3: 200 OK size=350080

cache directory: /home/user/.cache/lp-externals/lumiadb/RM-914/059S083
prepared unlock manifest: ./unlock-manifest.json

phone is currently in PhoneInfoApp; run `lp-externals reset` if desired
```

## Failure Policy

Fail instead of guessing when:

- PhoneInfoApp cannot be reached.
- `TYPE` is missing or empty.
- `CTR` is missing or empty.
- LumiaDB exact match count is not exactly one.
- Any planned blob URL is unavailable.
- Any download fails.
- FFU parse or GPT parse fails.
- Any required blob is zero bytes.

Errors should include the detected model/product code and the stage that failed.

## Future Unlock Porcelain

The future command should consume only the prepared manifest:

```sh
lp-externals unlock <manifest>
```

`unlock` should trust the manifest as the selected input set, then perform deeper safety checks before any destructive operation:

- parse FFU security metadata
- extract FFU Root Key Hash
- compare against phone RRKH
- match emergency loader material
- verify SBL3 suitability
- only then proceed toward actual unlock steps
