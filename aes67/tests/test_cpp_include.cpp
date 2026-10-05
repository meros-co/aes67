// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Meros Inc.
//
// libaes67's headers first, the C++ standard library after: the order a C++
// consumer is most likely to write, and the one a header defining
// `atomic_store` or `_Atomic` as macros broke. If this compiles, include order
// does not matter. It also writes a ring from C++ and reads it back, so a ring
// declared on one side of the language boundary works on the other.

#include <aes67/rtp.h>
#include <aes67/rx.h>
#include <aes67/sdp.h>
#include <aes67/tx.h>

#include <atomic>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

int main()
{
    std::atomic<int> standard { 0 };
    standard.store(1);
    auto shared = std::make_shared<int>(2);
    std::atomic_store(&shared, std::make_shared<int>(3));   // the name a macro used to take

    auto ring = std::make_unique<aes67_ring_t>();
    aes67_ring_init(ring.get());
    for (uint32_t t = 0; t < 48; ++t)
        aes67_ring_write(ring.get(), 1000 + t, (int32_t) t * 10);
    int32_t out[48] = {};
    const int got = aes67_ring_read(ring.get(), 1000, out, 48);
    const bool ok = got == 48 && out[47] == 470 && aes67_ring_head(ring.get()) == 1048 && standard.load() == 1
                    && *std::atomic_load(&shared) == 3;
    std::printf("aes67 from C++: %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}
