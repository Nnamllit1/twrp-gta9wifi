// SPDX-License-Identifier: Apache-2.0
// Disposable AES key self-test. No existing keys, paths, aliases or data files.
// No rollback-resistance request; the returned blob stays in RAM and is dropped.
#include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/IKeyMintOperation.h>
#include <android/binder_manager.h>
#include <android-base/properties.h>
#include <openssl/crypto.h>
#include <unistd.h>
#include <cstdio>
#include <optional>
#include <vector>

namespace km = aidl::android::hardware::security::keymint;
static bool show(const char* name, const ndk::ScopedAStatus& status) {
    std::printf("%s: ok=%d exception=%d service_error=%d transaction=%d\n", name,
                status.isOk(), status.getExceptionCode(), status.getServiceSpecificError(),
                status.getStatus());
    return status.isOk();
}
int main() {
    using android::base::GetProperty;
    if (getuid() != 0 || GetProperty("ro.product.model", "") != "SM-X110" ||
        GetProperty("ro.bootloader", "") != "X110XXU4CYE5" ||
        GetProperty("ro.twrp.boot", "") != "1" ||
        GetProperty("ro.build.version.release", "") != "15") return 2;
    auto binder = ndk::SpAIBinder(AServiceManager_checkService(
            "android.hardware.security.keymint.IKeyMintDevice/default"));
    auto service = km::IKeyMintDevice::fromBinder(binder);
    if (!service) return 3;
    std::vector<km::KeyParameter> params;
    auto add = [&](km::Tag tag, km::KeyParameterValue value) {
        km::KeyParameter p;
        p.tag = tag;
        p.value = std::move(value);
        params.push_back(std::move(p));
    };
    add(km::Tag::ALGORITHM, km::KeyParameterValue::make<km::KeyParameterValue::algorithm>(km::Algorithm::AES));
    add(km::Tag::KEY_SIZE, km::KeyParameterValue::make<km::KeyParameterValue::integer>(256));
    add(km::Tag::PURPOSE, km::KeyParameterValue::make<km::KeyParameterValue::keyPurpose>(km::KeyPurpose::DECRYPT));
    add(km::Tag::BLOCK_MODE, km::KeyParameterValue::make<km::KeyParameterValue::blockMode>(km::BlockMode::GCM));
    add(km::Tag::PADDING, km::KeyParameterValue::make<km::KeyParameterValue::paddingMode>(km::PaddingMode::NONE));
    add(km::Tag::MIN_MAC_LENGTH, km::KeyParameterValue::make<km::KeyParameterValue::integer>(128));
    add(km::Tag::NO_AUTH_REQUIRED, km::KeyParameterValue::make<km::KeyParameterValue::boolValue>(true));
    // Fixed public diagnostic application ID; no device-specific secret is used.
    const std::vector<uint8_t> appId(64, 0xa5);
    add(km::Tag::APPLICATION_ID, km::KeyParameterValue::make<km::KeyParameterValue::blob>(appId));
    km::KeyCreationResult created;
    if (!show("generate_disposable_key", service->generateKey(params, std::nullopt, &created))) return 4;
    struct Drop {
        std::shared_ptr<km::IKeyMintDevice> service;
        std::vector<uint8_t>& blob;
        ~Drop() {
            show("delete_only_disposable_key", service->deleteKey(blob));
            if (!blob.empty()) OPENSSL_cleanse(blob.data(), blob.size());
        }
    } drop{service, created.keyBlob};
    std::vector<km::KeyCharacteristics> chars;
    if (!show("reopen_disposable_key", service->getKeyCharacteristics(created.keyBlob, appId, {}, &chars))) return 5;
    params.clear();
    add(km::Tag::APPLICATION_ID, km::KeyParameterValue::make<km::KeyParameterValue::blob>(appId));
    add(km::Tag::BLOCK_MODE, km::KeyParameterValue::make<km::KeyParameterValue::blockMode>(km::BlockMode::GCM));
    add(km::Tag::PADDING, km::KeyParameterValue::make<km::KeyParameterValue::paddingMode>(km::PaddingMode::NONE));
    add(km::Tag::MAC_LENGTH, km::KeyParameterValue::make<km::KeyParameterValue::integer>(128));
    add(km::Tag::NONCE, km::KeyParameterValue::make<km::KeyParameterValue::blob>(std::vector<uint8_t>(12)));
    km::BeginResult op;
    if (!show("begin_disposable_key", service->begin(km::KeyPurpose::DECRYPT, created.keyBlob, params, std::nullopt, &op))) return 6;
    if (!op.operation || !show("abort_before_any_decrypt", op.operation->abort())) return 7;
    std::puts("PASS: disposable key generated and reopened; no ciphertext, plaintext or key blob exported.");
    return 0;
}
