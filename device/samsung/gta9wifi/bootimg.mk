# SPDX-License-Identifier: Apache-2.0
# Sign only the recovery image; preserve the original index and location.
$(INSTALLED_RECOVERYIMAGE_TARGET): $(MKBOOTIMG) $(recovery_ramdisk) $(recovery_kernel) $(RECOVERYIMAGE_EXTRA_DEPS) $(AVBTOOL) $(DEVICE_PATH)/prebuilt/samsung-signer.bin
	$(MKBOOTIMG) $(INTERNAL_RECOVERYIMAGE_ARGS) $(INTERNAL_MKBOOTIMG_VERSION_ARGS) $(BOARD_MKBOOTIMG_ARGS) --output $@
	printf SEANDROIDENFORCE >> $@
	cat $(DEVICE_PATH)/prebuilt/samsung-signer.bin >> $@
	$(call assert-max-image-size,$@,$(BOARD_RECOVERYIMAGE_PARTITION_SIZE),raw)
	$(AVBTOOL) add_hash_footer --image $@ --partition_size $(BOARD_RECOVERYIMAGE_PARTITION_SIZE) --partition_name recovery --algorithm $(BOARD_AVB_RECOVERY_ALGORITHM) --key $(BOARD_AVB_RECOVERY_KEY_PATH) --rollback_index 0 --rollback_index_location 0
