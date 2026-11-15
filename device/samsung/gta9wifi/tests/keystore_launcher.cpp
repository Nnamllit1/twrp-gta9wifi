// SPDX-License-Identifier: Apache-2.0
// Fixed-path launcher for the isolated original CYE5 Keystore diagnostic.
// No arbitrary executable/UID arguments; normal Android is never modified.
#include <android-base/properties.h>
#include <grp.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>

int main(int argc, char**) {
    using android::base::GetProperty;
    if (argc != 1 || getuid() != 0 || GetProperty("ro.twrp.boot", "") != "1" ||
        GetProperty("ro.product.model", "") != "SM-X110" ||
        GetProperty("ro.bootloader", "") != "X110XXU4CYE5") return 2;
    if (setgroups(0, nullptr) || setgid(1017) || setuid(1017) || getuid() != 1017) return 3;
    if (setenv("LD_LIBRARY_PATH", "/tmp/fwblp-stock-keystore/lib64:/system/lib64", 1)) return 4;
    execl("/tmp/fwblp-stock-keystore/keystore2", "keystore2",
          "/tmp/fwblp-stock-keystore/database", static_cast<char*>(nullptr));
    std::perror("CYE5 isolated Keystore exec");
    return 5;
}
