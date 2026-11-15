// SPDX-License-Identifier: Apache-2.0
// Authenticate an existing metadata blob through the original KeyMint service.
// No key creation, upgrade, deletion, plaintext export or filesystem writes.
#include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/IKeyMintOperation.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/IKeystoreOperation.h>
#include <aidl/android/system/keystore2/IKeystoreSecurityLevel.h>
#include <android/binder_manager.h>
#include <android/binder_parcel.h>
#include <android-base/properties.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <array>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <utility>
#include <vector>

namespace km = aidl::android::hardware::security::keymint;
namespace {
struct Secret {
    std::vector<uint8_t> bytes;
    ~Secret() { if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
bool readExisting(int dir, const char* name, size_t limit, Secret& out) {
    const int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st{};
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
              static_cast<uint64_t>(st.st_size) <= limit;
    if (ok) {
        out.bytes.resize(static_cast<size_t>(st.st_size));
        size_t done = 0;
        while (done < out.bytes.size()) {
            const ssize_t got = read(fd, out.bytes.data() + done, out.bytes.size() - done);
            if (got <= 0) { ok = false; break; }
            done += static_cast<size_t>(got);
        }
    }
    close(fd);
    return ok;
}
bool status(const char* label, const ndk::ScopedAStatus& result) {
    // Avoid exception strings or parameter/blob dumps.
    std::printf("%s: ok=%d exception=%d service_error=%d transaction=%d\n", label,
                result.isOk(), result.getExceptionCode(), result.getServiceSpecificError(),
                result.getStatus());
    return result.isOk();
}
// CYE5's authenticated vendor AIDL proxy maps the read-only getLastFailedRot
// getter to transaction 3 with an empty request and status + byte-array reply.
// Its provider only returns an already cached vector. Never print its contents.
void compareFailedRot() {
    const int dir = open("/metadata/vold/metadata_encryption/key",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    Secret saved, failed;
    const bool loaded = dir >= 0 && readExisting(dir, "rot", 64, saved);
    if (dir >= 0) close(dir);
    if (!loaded || saved.bytes.size() != 16) {
        std::puts("saved_rot_layout_unavailable=1");
        return;
    }
    auto binder = ndk::SpAIBinder(AServiceManager_checkService(
            "vendor.samsung.hardware.keymint.ISehKeyMintExtension/default"));
    if (!binder.get()) { std::puts("failed_rot_getter_unavailable=1"); return; }
    auto* clazz = AIBinder_Class_define(
            "vendor.samsung.hardware.keymint.ISehKeyMintExtension",
            [](void*) -> void* { return nullptr; }, [](void*) {},
            [](AIBinder*, transaction_code_t, const AParcel*, AParcel*) -> binder_status_t {
                return STATUS_UNKNOWN_TRANSACTION;
            });
    if (!clazz || !AIBinder_associateClass(binder.get(), clazz)) {
        std::puts("failed_rot_interface_mismatch=1");
        return;
    }
    AParcel* in = nullptr;
    AParcel* out = nullptr;
    binder_status_t code = AIBinder_prepareTransaction(binder.get(), &in);
    if (code == STATUS_OK) code = AIBinder_transact(binder.get(), 3, &in, &out, 0);
    AStatus* reply = nullptr;
    if (code == STATUS_OK) code = AParcel_readStatusHeader(out, &reply);
    if (code == STATUS_OK && reply && AStatus_isOk(reply)) {
        code = AParcel_readByteArray(out, &failed.bytes,
            [](void* array, int32_t size, int8_t** buffer) -> bool {
                if (size < 0 || size > 64) return false;
                auto& bytes = *static_cast<std::vector<uint8_t>*>(array);
                bytes.resize(static_cast<size_t>(size));
                *buffer = reinterpret_cast<int8_t*>(bytes.data());
                return true;
            });
        if (code == STATUS_OK && failed.bytes.size() == saved.bytes.size()) {
            std::printf("cached_failed_rot_matches_saved_rot=%d\n",
                        CRYPTO_memcmp(failed.bytes.data(), saved.bytes.data(), saved.bytes.size()) == 0);
            // Test the captured CYE5 log tuple hypothesis without exporting
            // opaque ROT bytes. This is not a general decoder for other builds.
            constexpr uint8_t stockTuple[] = {0x06, 0x00, 0x02};
            constexpr uint8_t recoveryTuple[] = {0x07, 0x00, 0x02};
            std::printf("saved_rot_starts_with_stock_integrity_tuple=%d\n",
                        CRYPTO_memcmp(saved.bytes.data(), stockTuple, sizeof(stockTuple)) == 0);
            std::printf("failed_rot_starts_with_recovery_integrity_tuple=%d\n",
                        CRYPTO_memcmp(failed.bytes.data(), recoveryTuple, sizeof(recoveryTuple)) == 0);
            std::printf("rot_bytes_after_tuple_match=%d\n",
                        CRYPTO_memcmp(failed.bytes.data() + 3, saved.bytes.data() + 3,
                                      saved.bytes.size() - 3) == 0);
            std::printf("rot_candidate_state_header_difference=%02x:%02x:%02x\n",
                        saved.bytes[0] ^ failed.bytes[0], saved.bytes[1] ^ failed.bytes[1],
                        saved.bytes[2] ^ failed.bytes[2]);
        } else {
            std::puts("failed_rot_layout_unavailable=1");
        }
    } else {
        std::printf("failed_rot_getter_error=%d\n", code);
    }
    if (reply) AStatus_delete(reply);
    if (in) AParcel_delete(in);
    if (out) AParcel_delete(out);
}
}
int main(int argc, char** argv) {
    const bool asKeystore = argc == 2 && std::strcmp(argv[1], "--as-keystore") == 0;
    const bool viaKeystore = argc == 2 && std::strcmp(argv[1], "--via-keystore") == 0;
    if (argc != 1 && !asKeystore && !viaKeystore) {
        std::fputs("usage: metadata_key_probe [--as-keystore|--via-keystore]\n", stderr);
        return 2;
    }
    using android::base::GetProperty;
    if (getuid() != 0 || GetProperty("ro.twrp.boot", "") != "1" ||
        GetProperty("ro.product.model", "") != "SM-X110" ||
        GetProperty("ro.bootloader", "") != "X110XXU4CYE5" ||
        GetProperty("ro.build.version.release", "") != "15" ||
        GetProperty("ro.build.version.security_patch", "") != "2025-04-01" ||
        GetProperty("vendor.tzts_daemon", "") != "Ready") {
        std::fputs("Refused: expected root SM-X110 CYE5 recovery crypto profile.\n", stderr);
        return 2;
    }
    const int dir = open("/metadata/vold/metadata_encryption/key",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return 3;
    Secret blob, discard, version, appId;
    const bool loaded = readExisting(dir, "version", 8, version) &&
                        version.bytes == std::vector<uint8_t>{'1'} &&
                        readExisting(dir, "keymaster_key_blob", 65536, blob) &&
                        readExisting(dir, "secdiscardable", 16384, discard) &&
                        discard.bytes.size() == 16384;
    close(dir);
    if (!loaded) { std::puts("Refused: existing key-file layout mismatch."); return 3; }
    constexpr char legacyMagic[] = "pKMblob";
    const bool prefixed = blob.bytes.size() > 8 &&
            std::memcmp(blob.bytes.data(), legacyMagic, sizeof(legacyMagic) - 1) == 0 &&
            blob.bytes[7] <= 1;
    std::printf("legacy_compat_wrapper=%d\n", prefixed);
    if (prefixed) {
        if (blob.bytes[7] != 0) {
            std::puts("Refused: software-origin blob is not an original hardware key.");
            return 3;
        }
        // AOSP's documented km_compat framing; remove only in this RAM copy.
        std::move(blob.bytes.begin() + 8, blob.bytes.end(), blob.bytes.begin());
        OPENSSL_cleanse(blob.bytes.data() + blob.bytes.size() - 8, 8);
        blob.bytes.resize(blob.bytes.size() - 8);
    }
    std::array<uint8_t, SHA512_CBLOCK> prefix{};
    constexpr char text[] = "Android secdiscardable SHA512";
    std::copy(text, text + sizeof(text) - 1, prefix.begin());
    appId.bytes.resize(SHA512_DIGEST_LENGTH);
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, prefix.data(), prefix.size());
    SHA512_Update(&ctx, discard.bytes.data(), discard.bytes.size());
    SHA512_Final(appId.bytes.data(), &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    // Normal Android's Keystore Binder caller is UID1017. Read the existing
    // files first, then permanently drop this diagnostic process's credentials
    // before opening Binder. No service identity or stored file is changed.
    if (asKeystore) {
        if (setgroups(0, nullptr) != 0 || setgid(1017) != 0 || setuid(1017) != 0 ||
            getuid() != 1017 || geteuid() != 1017) {
            std::fputs("Refused: unable to enter the stock Keystore caller UID.\n", stderr);
            return 7;
        }
    }
    std::printf("binder_caller_uid=%u\n", static_cast<unsigned>(getuid()));
    auto binder = ndk::SpAIBinder(AServiceManager_checkService(
            "android.hardware.security.keymint.IKeyMintDevice/default"));
    auto service = km::IKeyMintDevice::fromBinder(binder);
    if (!service) return 4;
    km::KeyMintHardwareInfo info;
    if (!status("hardware_info", service->getHardwareInfo(&info))) return 4;
    std::printf("KeyMint version=%d security_level=%d\n", info.versionNumber,
                static_cast<int>(info.securityLevel));
    std::vector<km::KeyCharacteristics> characteristics;
    status("existing_blob_characteristics", service->getKeyCharacteristics(
            blob.bytes, appId.bytes, {}, &characteristics));
    std::vector<km::KeyParameter> parameters;
    auto addBlob = [&](km::Tag tag, const std::vector<uint8_t>& bytes) {
        km::KeyParameter p;
        p.tag = tag;
        p.value = km::KeyParameterValue::make<km::KeyParameterValue::blob>(bytes);
        parameters.push_back(std::move(p));
    };
    addBlob(km::Tag::APPLICATION_ID, appId.bytes);
    km::KeyParameter mac;
    mac.tag = km::Tag::MAC_LENGTH;
    mac.value = km::KeyParameterValue::make<km::KeyParameterValue::integer>(128);
    parameters.push_back(mac);
    km::KeyParameter mode;
    mode.tag = km::Tag::BLOCK_MODE;
    mode.value = km::KeyParameterValue::make<km::KeyParameterValue::blockMode>(km::BlockMode::GCM);
    parameters.push_back(mode);
    km::KeyParameter padding;
    padding.tag = km::Tag::PADDING;
    padding.value = km::KeyParameterValue::make<km::KeyParameterValue::paddingMode>(km::PaddingMode::NONE);
    parameters.push_back(padding);
    km::KeyParameter rot;
    rot.tag = static_cast<km::Tag>(0x700008fd);
    rot.value = km::KeyParameterValue::make<km::KeyParameterValue::boolValue>(true);
    parameters.push_back(rot);
    // Fixed-size placeholder nonce: the operation is aborted before any update
    // or finish, so neither ciphertext nor plaintext is read or returned.
    addBlob(km::Tag::NONCE, std::vector<uint8_t>(12));
    if (viaKeystore) {
        namespace ks = aidl::android::system::keystore2;
        auto kb = ndk::SpAIBinder(AServiceManager_checkService(
                "android.system.keystore2.IKeystoreService/default"));
        auto keystore = ks::IKeystoreService::fromBinder(kb);
        if (!keystore) return 8;
        std::shared_ptr<ks::IKeystoreSecurityLevel> level;
        if (!status("keystore_security_level", keystore->getSecurityLevel(
                km::SecurityLevel::TRUSTED_ENVIRONMENT, &level)) || !level) return 8;
        ks::KeyDescriptor descriptor;
        descriptor.domain = ks::Domain::BLOB;
        descriptor.nspace = 100; // Exact VOLD_NAMESPACE used by this recovery.
        descriptor.blob = blob.bytes;
        auto purpose = km::KeyParameter{};
        purpose.tag = km::Tag::PURPOSE;
        purpose.value = km::KeyParameterValue::make<km::KeyParameterValue::keyPurpose>(km::KeyPurpose::DECRYPT);
        parameters.push_back(purpose);
        ks::CreateOperationResponse response;
        if (!status("keystore_existing_blob_begin", level->createOperation(
                descriptor, parameters, false, &response))) return 5;
        // A service may return an upgraded BLOB in RAM. Never save or commit it.
        if (response.upgradedBlob && !response.upgradedBlob->empty()) {
            OPENSSL_cleanse(response.upgradedBlob->data(), response.upgradedBlob->size());
        }
        if (!response.iOperation || !status("keystore_operation_abort", response.iOperation->abort())) return 6;
        std::puts("PASS: existing metadata blob accepted through Keystore; no decrypt/write performed.");
        return 0;
    }
    km::BeginResult result;
    if (!status("existing_blob_begin", service->begin(km::KeyPurpose::DECRYPT,
            blob.bytes, parameters, std::nullopt, &result))) {
        compareFailedRot();
        return 5;
    }
    if (!result.operation) return 6;
    if (!status("operation_abort", result.operation->abort())) return 6;
    std::puts("PASS: existing metadata blob accepted directly; no decrypt/write performed.");
    return 0;
}
