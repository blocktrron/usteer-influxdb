include $(TOPDIR)/rules.mk

PKG_NAME:=usteer-influxdb
PKG_VERSION:=$(shell git show -s --format=%cd --date=short)
PKG_RELEASE:=1

PKG_BUILD_PARALLEL:=1

PKG_FILE_DEPENDS:=$(CURDIR)/../..

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -R $(CURDIR)/../../* $(PKG_BUILD_DIR)/
endef

define Package/usteer-influxdb
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libubox +libubus +libblobmsg-json +libuci +libuclient
  TITLE:=OpenWrt AP roaming assist daemon InfluxDB data exporter
endef

define Package/usteer-influxdb/conffiles
/etc/config/usteer-influxdb
endef

define Package/usteer-influxdb/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/config $(1)/etc/init.d
	$(CP) $(PKG_BUILD_DIR)/files/usteer-influxdb.config $(1)/etc/config/usteer-influxdb
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/usteer-influxdb.init $(1)/etc/init.d/usteer-influxdb
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usteer-influxdb $(1)/usr/bin
endef

$(eval $(call BuildPackage,usteer-influxdb))
