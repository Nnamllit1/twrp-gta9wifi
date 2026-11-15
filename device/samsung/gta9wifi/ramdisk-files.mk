# SPDX-License-Identifier: Apache-2.0
GTA9WIFI_RAMDISK_BASE := device/samsung/gta9wifi/prebuilt/ramdisk
GTA9WIFI_RAMDISK_FILES := $(sort $(patsubst $(GTA9WIFI_RAMDISK_BASE)/%,%,$(shell find $(GTA9WIFI_RAMDISK_BASE) -type f)))
