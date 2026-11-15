// SPDX-License-Identifier: Apache-2.0
// Recovery-process tests only: no partitions, keys, mounts or HAL operations.
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <binder/Parcel.h>
#include <binder/Status.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {
void require(bool ok, const char* message) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}
struct Counts { std::atomic<int> died{0}; std::atomic<int> unlinked{0}; };
void onDied(void* cookie) { ++static_cast<Counts*>(cookie)->died; }
void onUnlinked(void* cookie) { ++static_cast<Counts*>(cookie)->unlinked; }
void awaitUnlinked(Counts& counts) {
    for (int attempt = 0; counts.unlinked.load() == 0 && attempt < 200; ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    require(counts.unlinked.load() == 1, "exactly one unlink callback");
    require(counts.died.load() == 0, "live HAL did not report death");
}
AIBinder_DeathRecipient* recipient() {
    auto* result = AIBinder_DeathRecipient_new(onDied);
    require(result != nullptr, "death-recipient allocation");
    AIBinder_DeathRecipient_setOnUnlinked(result, onUnlinked);
    return result;
}
void* onCreate(void* args) { return args; }
void onDestroy(void*) {}
binder_status_t onTransact(AIBinder*, transaction_code_t, const AParcel*, AParcel*) {
    return STATUS_UNKNOWN_TRANSACTION;
}
}

int main() {
    ABinderProcess_startThreadPool();
    using android::Parcel;
    using android::binder::Status;
    Parcel empty;
    require(empty.enforceNoDataAvail().isOk(), "empty parcel accepted");
    Parcel extra;
    require(extra.writeInt32(123) == android::OK, "parcel setup");
    extra.setDataPosition(0);
    require(extra.enforceNoDataAvail().exceptionCode() == Status::EX_BAD_PARCELABLE,
            "unconsumed parcel rejected");
    Parcel reply;
    require(reply.writeInt32(123456) == android::OK, "reply setup");
    auto expected = Status::fromExceptionCode(Status::EX_SECURITY);
    require(expected.writeOverParcel(&reply) == android::OK, "status overwrite");
    reply.setDataPosition(0);
    Status parsed;
    require(parsed.readFromParcel(reply) == android::OK, "status readback");
    require(parsed.exceptionCode() == Status::EX_SECURITY && reply.dataAvail() == 0,
            "replacement status preserved without stale reply data");
    std::puts("PASS: parcel validation and status overwrite");

    AIBinder* remote = AServiceManager_checkService(
            "android.hardware.security.keymint.IKeyMintDevice/default");
    require(remote != nullptr && AIBinder_isRemote(remote), "existing remote HAL lookup");
    Counts unlinked;
    auto* first = recipient();
    require(AIBinder_linkToDeath(remote, first, &unlinked) == STATUS_OK, "remote link");
    require(AIBinder_unlinkToDeath(remote, first, &unlinked) == STATUS_OK, "remote unlink");
    AIBinder_DeathRecipient_delete(first);
    awaitUnlinked(unlinked);
    std::puts("PASS: real remote unlink callback");

    Counts deleted;
    auto* second = recipient();
    require(AIBinder_linkToDeath(remote, second, &deleted) == STATUS_OK, "second remote link");
    AIBinder_DeathRecipient_delete(second);
    awaitUnlinked(deleted);
    AIBinder_decStrong(remote);
    std::puts("PASS: linked recipient deletion callback");

    AIBinder_Class* clazz = AIBinder_Class_define("gta9wifi.CompatFixture", onCreate, onDestroy,
                                               onTransact);
    require(clazz != nullptr, "local fixture class");
    AIBinder* local = AIBinder_new(clazz, nullptr);
    require(local != nullptr, "local fixture binder");
    Counts failed;
    auto* third = recipient();
    require(AIBinder_linkToDeath(local, third, &failed) == STATUS_INVALID_OPERATION,
            "local link failure reported");
    AIBinder_DeathRecipient_delete(third);
    awaitUnlinked(failed);
    AIBinder_decStrong(local);
    AIBinder_DeathRecipient_setOnUnlinked(nullptr, onUnlinked);
    std::puts("PASS: failed link cleanup and null recipient");
    return 0;
}
