# SPDX-License-Identifier: Apache-2.0
LOCAL_DEVICE_PATH := device/samsung/gta9wifi
PRODUCT_USE_DYNAMIC_PARTITIONS := true
PRODUCT_COPY_FILES += $(call find-copy-subdir-files,*,$(LOCAL_DEVICE_PATH)/recovery/root,recovery/root)
include $(LOCAL_DEVICE_PATH)/ramdisk-files.mk
PRODUCT_PACKAGES += $(foreach file,$(GTA9WIFI_RAMDISK_FILES),gta9wifi_recovery_$(subst /,_,$(file)))
TARGET_SYSTEM_PROP += $(LOCAL_DEVICE_PATH)/system.prop
PRODUCT_PACKAGES += android.hardware.health@2.1-impl
# TWRP links against resetprop for FBE. Install its recovery variant explicitly.
PRODUCT_PACKAGES += libresetprop.recovery
PRODUCT_PACKAGES += resetprop
TARGET_RECOVERY_DEVICE_MODULES += service
