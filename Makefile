#
# Copyright 2020 lwz322 <lwz322@qq.com>
# Licensed to the public under the MIT License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-frps-ext
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_MAINTAINER:=lwz322 <lwz322@qq.com>

LUCI_TITLE:=LuCI support for Frps (ext)
LUCI_DEPENDS:=+luci-base +frps-ext
LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/conffiles
/etc/config/frps_ext
endef

include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	if [ -f "/etc/uci-defaults/40_luci-frps_ext" ]; then
		. /etc/uci-defaults/40_luci-frps_ext
		rm -f /etc/uci-defaults/40_luci-frps_ext
	fi
fi

chmod 755 "$${IPKG_INSTROOT}/etc/init.d/frps_ext" >/dev/null 2>&1
ln -sf "../init.d/frps_ext" \
	"$${IPKG_INSTROOT}/etc/rc.d/S99frps_ext" >/dev/null 2>&1
exit 0
endef

# call BuildPackage - OpenWrt buildroot signature
