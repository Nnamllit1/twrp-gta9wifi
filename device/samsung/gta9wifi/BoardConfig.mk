# SPDX-License-Identifier: Apache-2.0
# SM-X110 CYE5 recovery port. Values come from the authenticated stock image.
DEVICE_PATH := device/samsung/gta9wifi
# Preserve the Android label on TEE files created while recovery is running.
BOARD_VENDOR_SEPOLICY_DIRS += $(DEVICE_PATH)/sepolicy
TARGET_ARCH := arm64
TARGET_ARCH_VARIANT := armv8-a
TARGET_CPU_ABI := arm64-v8a
TARGET_CPU_VARIANT := generic
TARGET_CPU_VARIANT_RUNTIME := cortex-a76
TARGET_USES_64_BIT_BINDER := true
TARGET_BOARD_PLATFORM := mt6789
TARGET_BOOTLOADER_BOARD_NAME := gta9wifi
TARGET_NO_BOOTLOADER := true
TARGET_NO_RADIOIMAGE := true

TARGET_PREBUILT_KERNEL := $(DEVICE_PATH)/prebuilt/kernel
TARGET_PREBUILT_DTB := $(DEVICE_PATH)/prebuilt/dtb.img
BOARD_PREBUILT_DTBOIMAGE := $(DEVICE_PATH)/prebuilt/dtbo.img
BOARD_KERNEL_IMAGE_NAME := Image.gz
BOARD_BOOT_HEADER_VERSION := 2
BOARD_HEADER_VERSION := 2
BOARD_NAME := SRPWF07A004
BOARD_KERNEL_BASE := 0x3fff8000
BOARD_KERNEL_PAGESIZE := 4096
BOARD_PAGE_SIZE := 4096
BOARD_KERNEL_OFFSET := 0x00008000
BOARD_RAMDISK_OFFSET := 0x26f08000
BOARD_TAGS_OFFSET := 0x07c88000
BOARD_DTB_OFFSET := 0x07c88000
BOARD_KERNEL_CMDLINE := bootopt=64S3,32N2,64N2 loop.max_part=7 androidboot.selinux=permissive
BOARD_MKBOOTIMG_ARGS := --header_version 2 --board $(BOARD_NAME) --pagesize $(BOARD_PAGE_SIZE) --kernel_offset $(BOARD_KERNEL_OFFSET) --ramdisk_offset $(BOARD_RAMDISK_OFFSET) --tags_offset $(BOARD_TAGS_OFFSET) --dtb $(TARGET_PREBUILT_DTB) --dtb_offset $(BOARD_DTB_OFFSET)
BOARD_INCLUDE_RECOVERY_DTBO := true
BOARD_CUSTOM_BOOTIMG_MK := $(DEVICE_PATH)/bootimg.mk
BOARD_RECOVERYIMAGE_PARTITION_SIZE := 83886080
BOARD_BOOTIMAGE_PARTITION_SIZE := 67108864
BOARD_FLASH_BLOCK_SIZE := 262144
BOARD_HAS_LARGE_FILESYSTEM := true
BOARD_SUPPRESS_SECURE_ERASE := true
TARGET_USERIMAGES_USE_EXT4 := true
TARGET_USERIMAGES_USE_F2FS := true
BOARD_USERDATAIMAGE_FILE_SYSTEM_TYPE := f2fs
TARGET_COPY_OUT_VENDOR := vendor
AB_OTA_UPDATER := false

# The original recovery reports Android 12 / April 2025 and AVB index/location 0.
# No future date or platform-patch timestamp is used as a rollback index.
PLATFORM_VERSION := 12.0.0
PLATFORM_SECURITY_PATCH := 2025-04-01
VENDOR_SECURITY_PATCH := 2025-04-01
BOARD_AVB_ENABLE := true
BOARD_AVB_ROLLBACK_INDEX := 0
BOARD_AVB_RECOVERY_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_RECOVERY_ALGORITHM := SHA256_RSA4096
BOARD_AVB_RECOVERY_ROLLBACK_INDEX := 0
BOARD_AVB_RECOVERY_ROLLBACK_INDEX_LOCATION := 0

# Android init/libfs_mgr requires five-column fstab syntax for recovery reboots.
# TWRP reads its separate UI/backup flags from /etc/twrp.fstab.
TARGET_RECOVERY_FSTAB := $(DEVICE_PATH)/recovery.fstab
# /cache must be a real directory, independent of encrypted /data/cache.
BOARD_ROOT_EXTRA_FOLDERS := cache metadata vendor_dlkm odm_dlkm system_dlkm system_ext efs optics prism linkerconfig
TW_THEME := portrait_hdpi
TARGET_SCREEN_DENSITY := 213
TARGET_RECOVERY_PIXEL_FORMAT := RGBX_8888
# The MTK LED node reports 2047, but direct 32/230 comparisons confirm that
# this panel's usable recovery control is the normal 8-bit range.
TW_BRIGHTNESS_PATH := /sys/class/leds/lcd-backlight/brightness
TW_MAX_BRIGHTNESS := 255
TW_DEFAULT_BRIGHTNESS := 128
RECOVERY_SDCARD_ON_DATA := true
TW_HAS_DOWNLOAD_MODE := true
TW_NO_REBOOT_BOOTLOADER := true
TW_EXCLUDE_DEFAULT_USB_INIT := true
TW_USE_NEW_MINADBD := true
TW_NO_BIND_SYSTEM := true
TWRP_INCLUDE_LOGCAT := true
TW_RECOVERY_ADDITIONAL_RELINK_BINARY_FILES += $(TARGET_OUT_EXECUTABLES)/service
TARGET_USES_LOGD := true
# The CYE5 kernel exposes a working standard battery power_supply interface.
# Recovery has no registered health HAL; avoid waiting in the battery monitor.
TW_USE_LEGACY_BATTERY_SERVICES := true
TW_INCLUDE_LPTOOLS := true
TW_INCLUDE_REPACKTOOLS := true
# Set this before TWRP evaluates its recovery dependencies. FBE also enables
# resetprop internally, but that late assignment did not stage the library.
TW_INCLUDE_LIBRESETPROP := true
TW_INCLUDE_NTFS_3G := true
TW_LOAD_VENDOR_BOOT_MODULES := true
TW_LOAD_VENDOR_MODULES := "soc_temp_lvts.ko touch_common.ko jdchipset.ko novatek.ko hxchipset.ko chipone.ko"

# Include the decryption implementation. Actual Samsung provider compatibility
# and unlocking existing CYE5 data require device validation; no format fallback.
TW_INCLUDE_CRYPTO := true
TW_INCLUDE_CRYPTO_FBE := true
TW_INCLUDE_FBE_METADATA_DECRYPT := true
# Use the built recovery crypto libraries with matched CYE5 providers. Loading
# Android15 system APEX libraries into this Android12.1 runtime is incompatible.
TW_EXCLUDE_APEX := true
TW_USE_FSCRYPT_POLICY := 2
BOARD_USES_METADATA_PARTITION := true
TW_DEVICE_VERSION := SM-X110 CYE5 development
