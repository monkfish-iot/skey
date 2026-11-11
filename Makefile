# Copyright 2026 MonkFish IoT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# OpenWrt package Makefile for skey
#
# 在 OpenWrt SDK 根目录执行:
#   make package/skey/compile V=s
#

include $(TOPDIR)/rules.mk

PKG_NAME:=skey
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/skey
  SECTION:=Monkfish
  CATEGORY:=Monkfish Softwares
  TITLE:=Device key and signing utility
  DEPENDS:=+libopenssl
  MAINTAINER:=monkfish
endef

define Package/skey/description
  Reads MAC from Factory/ART partition, derives AES key, generates UUID v4
  and RSA-2048 keypair, stores them AES-CBC encrypted with HMAC-SHA256 into
  product-uid and product-backup MTD partitions. Provides skey CLI and
  libskey.a static library for signing and device id queries.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

# 安装到 staging_dir，供 SDK 中其他 package 编译时找到 <skey.h> 和 -lskey
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/skey.h $(1)/usr/include/skey.h
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libskey.a $(1)/usr/lib/libskey.a
endef

define Package/skey/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/skey
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/skey $(1)/usr/bin/skey
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libskey.a $(1)/usr/lib/libskey.a
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/skey.h $(1)/usr/include/skey.h
	$(INSTALL_BIN) ./files/skey.init $(1)/etc/init.d/skey
	# 镜像内直接使能开机自启（postinst 的 enable 在镜像构建时不执行，
	# 必须在这里创建 rc.d 软链，否则首启不会自动 skey init）
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/skey $(1)/etc/rc.d/S99skey
	# CA 信任材料：若 files/ca.pem 存在（CA 证书或裸公钥 PEM），随固件安装
	[ -f ./files/ca.pem ] && $(INSTALL_DATA) ./files/ca.pem $(1)/etc/skey/ca.pem || true
endef

define Package/skey/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	/etc/init.d/skey enable
}
exit 0
endef

$(eval $(call BuildPackage,skey))
