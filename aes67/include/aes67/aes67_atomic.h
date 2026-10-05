/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef MEROS_AES67_ATOMIC_H
#define MEROS_AES67_ATOMIC_H

/* The atomics libaes67's rings and receivers use, under names of its own.
 *
 * Only what they need: 64-bit loads and stores with an order, fetch-add and
 * exchange. Everything is a 64-bit slot, so one struct layout serves every
 * compiler: a 32-bit timestamp in a 64-bit atomic costs nothing.
 *
 * Nothing here is spelled like the standard: no `atomic_store`, no
 * `memory_order`, no `_Atomic` macro. A header that defined those would break
 * C++ standard headers included after it (<atomic> and <memory> declare
 * functions of the same names), so the order of includes would matter. These
 * names are libaes67's and collide with nothing.
 *
 *  - C11 compilers with <stdatomic.h> (GCC, Clang): the real thing.
 *  - C++ on GCC/Clang, and C without <stdatomic.h>: the compiler's __atomic
 *    builtins, which give the same orders.
 *  - MSVC, C or C++: <stdatomic.h> there needs /experimental:c11atomics, so it
 *    is not used. x64 is TSO: a plain load is an acquire and a plain store a
 *    release once the compiler is kept from reordering them. ARM64 is not:
 *    loads use LDAR and stores STLR (`__ldar64`, `__stlr64`), because
 *    `volatile` alone orders nothing there (MSVC's ARM64 default is
 *    /volatile:iso). Read-modify-writes are Interlocked, a full barrier on
 *    both. */

#include <stdint.h>

/* The same numbers as GCC's __ATOMIC_* and C11's memory_order_*. */
#define AES67_MO_RELAXED 0
#define AES67_MO_ACQUIRE 2
#define AES67_MO_RELEASE 3
#define AES67_MO_SEQ_CST 5

#if !defined(_MSC_VER) && !defined(__cplusplus) && defined(__has_include)
#  if __has_include(<stdatomic.h>)
#    define AES67_ATOMIC_C11 1
#  endif
#elif !defined(_MSC_VER) && !defined(__cplusplus) && defined(__STDC_VERSION__) && !defined(__STDC_NO_ATOMICS__)
#  define AES67_ATOMIC_C11 1
#endif

#if defined(AES67_ATOMIC_C11) /* ---- C11 ------------------------------------- */

#include <stdatomic.h>

typedef _Atomic uint64_t aes67_atomic_u64;

#define aes67_atomic_load(p, mo)          atomic_load_explicit((p), (memory_order) (mo))
#define aes67_atomic_store(p, v, mo)      atomic_store_explicit((p), (uint64_t) (v), (memory_order) (mo))
#define aes67_atomic_fetch_add(p, v, mo)  atomic_fetch_add_explicit((p), (uint64_t) (v), (memory_order) (mo))
#define aes67_atomic_exchange(p, v)       atomic_exchange((p), (uint64_t) (v))

#elif defined(__GNUC__) || defined(__clang__) /* ---- __atomic builtins ------- */

/* Same size and alignment as C11's _Atomic uint64_t on every target these
   compilers serve, so a ring is one layout whichever side declares it. */
typedef volatile uint64_t aes67_atomic_u64;

#define aes67_atomic_load(p, mo)          __atomic_load_n((p), (mo))
#define aes67_atomic_store(p, v, mo)      __atomic_store_n((p), (uint64_t) (v), (mo))
#define aes67_atomic_fetch_add(p, v, mo)  __atomic_fetch_add((p), (uint64_t) (v), (mo))
#define aes67_atomic_exchange(p, v)       __atomic_exchange_n((p), (uint64_t) (v), __ATOMIC_SEQ_CST)

#elif defined(_MSC_VER) /* ---- MSVC -------------------------------------------- */

#include <intrin.h>

#if !defined(_M_X64) && !defined(_M_ARM64)
#  error "libaes67's MSVC atomics need x64 or ARM64"
#endif

typedef volatile long long aes67_atomic_u64;

static __forceinline uint64_t aes67__msvc_load(const volatile long long *p, int mo)
{
#if defined(_M_ARM64)
    if (mo == AES67_MO_RELAXED)
        return (uint64_t) __iso_volatile_load64((const volatile __int64 *) p);
    return (uint64_t) __ldar64((const volatile unsigned __int64 *) p);
#else
    long long v;
    (void) mo;
    v = *p;
    _ReadWriteBarrier();
    return (uint64_t) v;
#endif
}

static __forceinline void aes67__msvc_store(volatile long long *p, uint64_t v, int mo)
{
    if (mo == AES67_MO_SEQ_CST) {
        _InterlockedExchange64(p, (long long) v);   /* the store-load fence seq_cst needs */
        return;
    }
#if defined(_M_ARM64)
    if (mo == AES67_MO_RELAXED)
        __iso_volatile_store64((volatile __int64 *) p, (__int64) v);
    else
        __stlr64((volatile unsigned __int64 *) p, (unsigned __int64) v);
#else
    _ReadWriteBarrier();
    *p = (long long) v;
#endif
}

#define aes67_atomic_load(p, mo)          aes67__msvc_load((p), (mo))
#define aes67_atomic_store(p, v, mo)      aes67__msvc_store((p), (uint64_t) (v), (mo))
#define aes67_atomic_fetch_add(p, v, mo)  ((void) (mo), (uint64_t) _InterlockedExchangeAdd64((p), (long long) (v)))
#define aes67_atomic_exchange(p, v)       ((uint64_t) _InterlockedExchange64((p), (long long) (v)))

#else
#  error "libaes67 needs C11 atomics, GCC/Clang builtins or MSVC"
#endif

#endif /* MEROS_AES67_ATOMIC_H */
