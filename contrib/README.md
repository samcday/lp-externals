# LPexternals contrib

## udev rules

Install the rules with:

```sh
sudo install -m 0644 contrib/udev/50-lp-externals.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Then unplug and replug the phone.
