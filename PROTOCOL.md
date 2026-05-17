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

## Known Commands

| Command | Name in WPinternals | Notes |
| --- | --- | --- |
| `NOKD` | `DisableTimeoutsSignature` / `DisableRebootTimeOut()` | Disables the boot/reboot timeout watchdog. On this Lumia 520 BootMgr it replies with just `NOKD`. |
| `NOKI` | `HelloSignature` | Hello/ping command. WPinternals expects a `NOKI` response. |
| `NOKV` | `InfoQuerySignature` | Read-only info query. Used by `identify`. |
| `NOKT` | `GetGPTSignature` | Read-only GPT query. Used by `gpt dump`. |
| `NOKS` | `RebootToFlashAppSignature` | Switch/reboot to FlashApp mode. Mode-changing. Not used by read-only commands. |
| `NOKP` | `RebootToPhoneInfoAppSignature` | Switch/reboot to PhoneInfoApp mode. Mode-changing. |
| `NOKR` | `RebootSignature` | Reboot. |
| `NOKA` | `ContinueBootSignature` | Continue normal boot where supported. |
| `NOKM` | `RebootToMassStorageSignature` | Switch/reboot to mass storage where supported. Mode-changing. |
| `NOKZ` | `ShutdownSignature` | Shutdown. |

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

## `NOKD`

WPinternals names `NOKD` as `DisableTimeoutsSignature` and exposes it as `DisableRebootTimeOut()` on the common Lumia UEFI model.

The phone appears to reboot itself periodically while sitting in BootMgr. Sending `NOKD` returns:

```text
response length: 4 bytes
response hex: 4e 4f 4b 44
response ascii: NOKD
```

That simple echo is currently treated as success.

## Current Quirks

- The first USB transaction after plugging in or after a reboot may time out, especially on the tested AMD USB controller.
- Subsequent transactions often work reliably.
- Multi-command raw sessions avoid repeated open/claim/release cycles:

```sh
cargo run -- raw NOKV NOKD NOKV
```
