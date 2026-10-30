/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 -- SSRCs and SAP message hashes that are never reused. See rtp.h.

   A process-wide key comes from the operating system's generator once; each
   identifier is a counter, offset by the key and run through a bijective
   mix, so two calls in one process never collide (until the counter wraps)
   while the values look random and differ from run to run. */

#include "aes67/rtp.h"

#include <stdint.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  include <pthread.h>
#  include <stdlib.h>
#  define AES67_HAVE_ARC4RANDOM 1
#else
#  include <fcntl.h>
#  include <pthread.h>
#  include <unistd.h>
#endif

static uint64_t g_key;
static aes67_atomic_u64 g_ssrc_count;
static aes67_atomic_u64 g_sap_count;

static void fill_random(void *buf, size_t len)
{
    bool ok = false;
#if defined(_WIN32)
    ok = BCryptGenRandom(NULL, (PUCHAR) buf, (ULONG) len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#elif defined(AES67_HAVE_ARC4RANDOM)
    arc4random_buf(buf, len);
    ok = true;
#else
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        size_t got = 0;
        while (got < len) {
            const ssize_t n = read(fd, (char *) buf + got, len - got);
            if (n <= 0)
                break;
            got += (size_t) n;
        }
        close(fd);
        ok = got == len;
    }
#endif
    if (!ok) {
        /* No generator (a sandbox without /dev/urandom): the clock and an
           address still make this run's key unlike the last one's. */
        uint64_t v = (uint64_t) time(NULL) * 0x9E3779B97F4A7C15ull ^ (uint64_t) (uintptr_t) buf;
        v ^= (uint64_t) clock() << 32;
        memset(buf, 0, len);
        memcpy(buf, &v, len < sizeof v ? len : sizeof v);
    }
}

static void init_key(void)
{
    fill_random(&g_key, sizeof g_key);
}

#if defined(_WIN32)
static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK init_key_once(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void) once;
    (void) param;
    (void) ctx;
    init_key();
    return TRUE;
}
static uint64_t key(void)
{
    InitOnceExecuteOnce(&g_once, init_key_once, NULL, NULL);
    return g_key;
}
#else
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static uint64_t key(void)
{
    pthread_once(&g_once, init_key);
    return g_key;
}
#endif

/* MurmurHash3's finalizer: xor-shifts and odd multiplies, each a bijection
   on 32 bits, so distinct inputs stay distinct. */
static uint32_t mix32(uint32_t x)
{
    x ^= x >> 16;
    x *= 0x85EBCA6Bu;
    x ^= x >> 13;
    x *= 0xC2B2AE35u;
    x ^= x >> 16;
    return x;
}

/* The same construction on 16 bits. */
static uint16_t mix16(uint16_t x)
{
    x = (uint16_t) (x ^ (x >> 8));
    x = (uint16_t) (x * 0x88B5u);
    x = (uint16_t) (x ^ (x >> 7));
    x = (uint16_t) (x * 0xDB2Du);
    x = (uint16_t) (x ^ (x >> 9));
    return x;
}

uint32_t aes67_new_ssrc(void)
{
    const uint64_t k = key();
    const uint32_t n = (uint32_t) aes67_atomic_fetch_add(&g_ssrc_count, 1, AES67_MO_RELAXED);
    return mix32(n + (uint32_t) k) ^ (uint32_t) (k >> 32);
}

uint16_t aes67_new_sap_hash(void)
{
    const uint64_t k = key();
    for (;;) {
        /* Of each 65536 counts exactly one maps to zero, which SAP reserves:
           skipped, so the period is 65535 nonzero hashes. */
        const uint16_t n = (uint16_t) aes67_atomic_fetch_add(&g_sap_count, 1, AES67_MO_RELAXED);
        const uint16_t h = mix16((uint16_t) (n + (uint16_t) (k >> 16))) ^ (uint16_t) (k >> 48);
        if (h != 0)
            return h;
    }
}
