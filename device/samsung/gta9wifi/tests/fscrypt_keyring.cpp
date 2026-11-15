// SPDX-License-Identifier: Apache-2.0
// Create only the empty fscrypt container used by Android init. No secret keys.
#include <android-base/properties.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char** argv) {
    using android::base::GetProperty;
    if (getuid() != 0 || GetProperty("ro.product.model", "") != "SM-X110" ||
        GetProperty("ro.bootloader", "") != "X110XXU4CYE5" ||
        GetProperty("ro.twrp.boot", "") != "1") {
        std::fprintf(stderr, "Requires root SM-X110 CYE5 TWRP.\n");
        return 2;
    }
    if (argc != 2 || (std::strcmp(argv[1], "--check") && std::strcmp(argv[1], "--create"))) {
        std::fprintf(stderr, "Use --check or --create for the fixed fscrypt keyring.\n");
        return 2;
    }
    auto lookup = []() {
        return syscall(__NR_keyctl, KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING,
                       "keyring", "fscrypt", 0);
    };
    long ring = lookup();
    if (ring >= 0) {
        std::printf("Existing fscrypt session keyring: %ld\n", ring);
        return 0;
    }
    if (std::strcmp(argv[1], "--create") || errno != ENOKEY) {
        std::fprintf(stderr, "fscrypt session keyring unavailable: %s\n", std::strerror(errno));
        return 1;
    }
    ring = syscall(__NR_add_key, "keyring", "fscrypt", nullptr, 0, KEY_SPEC_SESSION_KEYRING);
    if (ring < 0 || lookup() != ring) {
        std::perror("Create empty fscrypt session keyring");
        return 1;
    }
    std::printf("Created empty fscrypt session keyring: %ld; no secrets generated or read.\n", ring);
    return 0;
}
