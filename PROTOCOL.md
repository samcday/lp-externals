# Lumia UEFI USB Protocol Notes

These notes describe the `0421:066e` `NOKIA BOOTMGR` interface observed on a Nokia Lumia 520 / `fame` and cross-checked against WPinternals.

## Transport

- USB vendor/product: `0421:066e` in the observed BootMgr state.
- Interface: vendor-specific bulk IN + bulk OUT endpoints.
- Framing: raw bytes, no wrapper seen so far.
- Most simple commands are 4 ASCII bytes beginning with `NOK`.
- Responses usually begin with the same 4-byte command signature.
- `NOKU` appears to mean unsupported command.

Example:

```sh
cargo run -- raw NOKV
```

By default, `lp-externals` waits for the target USB device to appear before opening it. Disable this with `--wait=false` if immediate failure is preferred.

BootMgr has a short reboot/watchdog window. Send `NOKD` soon after enumeration to keep the app alive:

```sh
cargo run -- stay-awake
```

## Known Commands

| Command | Name in WPinternals | Notes |
| --- | --- | --- |
| `NOKD` | `DisableTimeoutsSignature` / `DisableRebootTimeOut()` | Disables the boot/reboot timeout watchdog. Used by `stay-awake`. On this Lumia 520 BootMgr it replies with just `NOKD`. |
| `NOKI` | `HelloSignature` | Hello/ping command. WPinternals expects a `NOKI` response. |
| `NOKV` | `InfoQuerySignature` | Read-only info query. Used by `identify`. |
| `NOKT` | `GetGPTSignature` | Read-only GPT query. Used by `gpt dump`. |
| `NOKS` | `RebootToFlashAppSignature` | Switch/reboot to FlashApp mode. Mode-changing. Used by `switch flash`. |
| `NOKP` | `RebootToPhoneInfoAppSignature` | Switch/reboot to PhoneInfoApp mode. Mode-changing. Used by `switch phone-info`. |
| `NOKR` | `RebootSignature` | Reboot. WPinternals sends this as write-only and does not wait for a response. Used by `reset`. |
| `NOKA` | `ContinueBootSignature` | Continue normal boot where supported. |
| `NOKM` | `RebootToMassStorageSignature` | Switch/reboot to mass storage where supported. Mode-changing. |
| `NOKZ` | `ShutdownSignature` | Shutdown. |
| `NOKXFR` | `ReadParamSignature` | FlashApp parameter read. Used by `param read`. |
| `NOKXPH` | `GetVariableSignature` | PhoneInfoApp variable read. Used by `phone-info read`. |

## `NOKV` Response

Observed response:

```text
4e 4f 4b 56 00 01 01 01 01 10 02 01 00 04 00 24 10 00 04 00 04 01 0f 01 1c
```

Decoded:

```text
signature: NOKV
app type: 1 (BootManager)
protocol version: 1.1
app version: 1.16
subblocks: 2
subblock 0: id=0x01 length=4 transfer_size=2363392
subblock 1: id=0x04 length=4 flash_protocol=1.15 flash_app=1.28
```

WPinternals app type values:

| Value | App |
| --- | --- |
| `1` | BootManager |
| `2` | FlashApp |
| `3` | PhoneInfoApp |

When app type is `2`, the FlashApp subblocks decoded so far are:

| Subblock | Meaning |
| --- | --- |
| `0x01` | max transfer size |
| `0x02` | write buffer size |
| `0x03` | eMMC size in sectors |
| `0x04` | SD card size in sectors |
| `0x05` | platform ID |
| `0x0d` | async support |
| `0x0f` | security state bits |
| `0x10` | secure FFU protocol mask |
| `0x1f` | MMOS over USB support |
| `0x20` | CRC header info |

## `NOKD`

WPinternals names `NOKD` as `DisableTimeoutsSignature` and exposes it as `DisableRebootTimeOut()` on the common Lumia UEFI model.

The phone appears to reboot itself periodically while sitting in BootMgr. Sending `NOKD` returns:

```text
response length: 4 bytes
response hex: 4e 4f 4b 44
response ascii: NOKD
```

That simple echo is currently treated as success.

```sh
cargo run -- stay-awake
```

## `NOKR`

WPinternals names `NOKR` as `RebootSignature` and uses it for `ResetPhone()`.

Unlike read commands such as `NOKV`, WPinternals writes `NOKR` and does not read a response. The phone may disconnect immediately after the USB write.

```sh
cargo run -- reset
```

## `NOKS`

WPinternals names `NOKS` as `RebootToFlashAppSignature` and uses it for `ResetPhoneToFlashMode()` from BootMgr.

This is mode-changing. It writes `NOKS` and does not wait for a response.

```sh
cargo run -- switch flash
```

## `NOKP`

WPinternals names `NOKP` as `RebootToPhoneInfoAppSignature` and uses it to enter PhoneInfoApp mode from BootMgr or FlashApp.

This is mode-changing. It writes `NOKP` and does not wait for a response.

```sh
cargo run -- switch phone-info
```

## PhoneInfoApp Variables

WPinternals reads PhoneInfoApp variables with `NOKXPH`.

Request layout seen so far:

```text
offset  size  value
0x00    6     "NOKXPH"
0x06    5     ASCII variable name plus NUL terminator, for example "TYPE\0"
0x0b    5     zero padding
```

Response layout:

```text
offset  size  value
0x00    6     "NOKXPH"
0x06    2     big-endian value length
0x08    n     ASCII value
```

Useful variables:

| Variable | Meaning |
| --- | --- |
| `TYPE` | product type, usually exact `RM-xxxx` |
| `CTR` | public product code |
| `IMEI` | device IMEI |

Examples:

```sh
cargo run -- phone-info read TYPE
cargo run -- phone-info read CTR
```

## FlashApp Parameters

WPinternals reads FlashApp parameters with `NOKXFR`.

Request layout seen so far:

```text
offset  size  value
0x00    6     "NOKXFR"
0x06    1     padding / zero
0x07    4     ASCII parameter name, NUL padded if shorter
```

WPinternals extracts the returned value length from response byte `0x10`, then copies bytes from `0x11`.

Useful parameters for the unlock path:

| Param | Meaning |
| --- | --- |
| `RRKH` | Root Key Hash, used to match Qualcomm emergency loaders |
| `FAI` | Flash app/protocol version |
| `SS` | security status |
| `FCS` | security flags |
| `DPI` | platform ID |
| `FVER` | firmware version |

Examples:

```sh
cargo run -- param read RRKH
cargo run -- param read FAI
cargo run -- param read SS
cargo run -- param read DPI
```

## Current Quirks

- If `NOKD` is not sent shortly after the USB interface appears, the BootMgr watchdog can bite. The USB device may still appear present, but nothing responds on the bulk endpoints.
- The first USB transaction after plugging in or after a reboot may time out, especially on the tested AMD USB controller.
- Subsequent transactions often work reliably.
- Multi-command raw sessions avoid repeated open/claim/release cycles:

```sh
cargo run -- raw NOKV NOKD NOKV
```
