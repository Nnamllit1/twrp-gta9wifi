LOCAL_PATH := $(call my-dir)
ifeq ($(TARGET_DEVICE),gta9wifi)
include $(LOCAL_PATH)/ramdisk-files.mk
# Preserve authenticated modules, firmware and provider ELFs without rewriting.
# Provider executables need execute bits even on a Windows-hosted source tree.
define gta9wifi_recovery_data
include $$(CLEAR_VARS)
LOCAL_MODULE := gta9wifi_recovery_$(subst /,_,$(1))
LOCAL_MODULE_CLASS := $(if $(filter vendor/bin/%,$(1)),EXECUTABLES,ETC)
LOCAL_STRIP_MODULE := false
LOCAL_CHECK_ELF_FILES := false
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := prebuilt/ramdisk/$(1)
LOCAL_MODULE_STEM := $(notdir $(1))
LOCAL_MODULE_PATH := $$(TARGET_RECOVERY_ROOT_OUT)/$(patsubst %/,%,$(dir $(1)))
include $$(BUILD_PREBUILT)
endef
$(foreach file,$(GTA9WIFI_RAMDISK_FILES),$(eval $(call gta9wifi_recovery_data,$(file))))
endif
