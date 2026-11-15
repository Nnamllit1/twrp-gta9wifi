// SPDX-License-Identifier: Apache-2.0
// Parse the port's init table using the exact Android libfs_mgr implementation.
// No block devices, mounts or bootloader messages are accessed.
#include <fstab/fstab.h>
#include <sys/mount.h>

#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: gta9wifi_fstab_check CONFIG_FILE\n";
        return 2;
    }
    android::fs_mgr::Fstab fstab;
    if (!android::fs_mgr::ReadFstabFromFile(argv[1], &fstab)) {
        std::cerr << "Android libfs_mgr rejected the table\n";
        return 1;
    }
    const auto* misc = android::fs_mgr::GetEntryForMountPoint(&fstab, "/misc");
    const auto* data = android::fs_mgr::GetEntryForMountPoint(&fstab, "/data");
    const auto* metadata = android::fs_mgr::GetEntryForMountPoint(&fstab, "/metadata");
    if (fstab.size() != 13 || !misc || !data || !metadata ||
        misc->blk_device != "/dev/block/by-name/misc" || misc->fs_type != "emmc" ||
        data->blk_device != "/dev/block/by-name/userdata" || data->fs_type != "f2fs" ||
        metadata->blk_device != "/dev/block/by-name/metadata" || metadata->fs_type != "ext4") {
        std::cerr << "Required SM-X110 mappings are missing or changed\n";
        return 1;
    }
    unsigned int erofs_count = 0;
    for (const auto& entry : fstab) {
        if (entry.fs_type == "erofs") {
            ++erofs_count;
            if (!(entry.flags & MS_RDONLY) || !entry.fs_mgr_flags.logical) {
                std::cerr << "EROFS partition is not read-only and logical\n";
                return 1;
            }
        }
    }
    if (erofs_count != 6) return 1;
    std::cout << "PASS: Android libfs_mgr parsed 13 entries, the exact misc mapping, "
                 "and six read-only logical EROFS entries\n";
    return 0;
}
