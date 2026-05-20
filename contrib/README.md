# LPexternals contrib

## udev rules

Install the rules with:

```sh
sudo install -m 0644 contrib/udev/50-lp-externals.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Then unplug and replug the phone.

The rules grant local-user access to Lumia USB modes and Qualcomm `05c6:9006` / `05c6:9008` emergency modes. For `05c6:9006`, the exposed raw eMMC block devices are also marked `UDISKS_IGNORE=1` to avoid desktop automount/probing of phone partitions.
