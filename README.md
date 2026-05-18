# LPexternals

This is an experimental and incomplete rewrite of WPinternals in Rust.

Why do this? I wanted to unlock my Spec A Lumia. But I had no Windows environment available, and absolutely no inclination to do anything about that. I decided I'd rather spend a few days and some tokens producing this project instead.

## Usage

This is experimental software that does deeply disturbing things to your Lumia-shaped pocket computer. It may permanently brick or damage your device. You've been warned.

```sh
# reboot your device whilst connected to your host computer

# run this command to keep the device in the bootloader
lp-externals stay-awake

# get info about the bootloader
lp-externals identify

# switch to PhoneInfoApp and print ... well... info. about the phone.
lp-externals switch phone-info
lp-externals phone-info IMEI

# and more, dox TODO.
lp-externals --help
```
