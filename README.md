# luci-app-frps-ext

LuCI support for `frps-ext` (server) in this fork.

This package is fully independent and can coexist with the upstream `frps` LuCI app:

- UCI config: `/etc/config/frps_ext`
- init service: `/etc/init.d/frps_ext`
- LuCI menu: `Services -> Frps (ext)`

## Install

```sh
opkg install luci-app-frps-ext_*.ipk
```

## Configure

1. Install `frps-ext` binary (from feed `frps-ext`) or upload `/usr/bin/frps-ext`.
2. Open LuCI: `Services -> Frps (ext)` and set `Client file` to `/usr/bin/frps-ext`.
3. Configure listen/auth/webServer/transport options and enable the instance.

## Notes

- This LuCI app generates a v1 TOML config at runtime under `/var/etc/frps_ext/`.
