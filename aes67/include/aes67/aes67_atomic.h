/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef MANIFOLD_AES67_ATOMIC_H
#define MANIFOLD_AES67_ATOMIC_H

/* Portable subset of C11 <stdatomic.h> for libaes67's playout rings.
 *
 * The same policy as librecord's rec_atomic.h, kept as its own copy rather
 * than a cross-library include: a platform library is consumed on its own by
 * device firmware, and a ring's atomics are not something to reach into
 * another library for.
 *
 *  - MSVC always takes the fallback. Newer MSVC ships <stdatomic.h> but it
 *    hard-errors without /experimental:c11atomics, so probing for the header
 *    is not a usable test there.
 *  - C++ never uses <stdatomic.h> either (`_Atomic` is not a C++ keyword);
 *    GCC/Clang in C++ mode get the compiler's own builtins.
 *  - Everywhere else, real C11 atomics.
 *
 * Only what the rings need: aligned 32/64-bit loads and stores, fetch-add and
 * exchange on counters and flags. */

#if !defined(_MSC_VER) && !defined(__cplusplus)
#  if defined(__has_include)
#    if __has_include(<stdatomic.h>)
#      define AES67_HAVE_STDATOMIC 1
#    endif
#  else
#    define AES67_HAVE_STDATOMIC 1
#  endif
#endif

#if defined(__cplusplus) && !defined(_MSC_VER)
#  define AES67_CPP_BUILTIN_ATOMICS 1
#endif

#if defined(AES67_HAVE_STDATOMIC)

#include <stdatomic.h>

#elif defined(MANIFOLD_RECORD_REC_ATOMIC_H) /* ---- librecord's shim is here first -- */

/* The same fallback, already defined by librecord's rec_atomic.h in this
   translation unit (the engine includes both). Two identical copies of a
   typedef are still two typedefs, so this one steps aside. */

#elif defined(AES67_CPP_BUILTIN_ATOMICS) /* ---- C++ on GCC/Clang ---------- */

#include <stddef.h>
#include <stdint.h>

#define _Atomic volatile

typedef enum {
    memory_order_relaxed = __ATOMIC_RELAXED,
    memory_order_consume = __ATOMIC_CONSUME,
    memory_order_acquire = __ATOMIC_ACQUIRE,
    memory_order_release = __ATOMIC_RELEASE,
    memory_order_acq_rel = __ATOMIC_ACQ_REL,
    memory_order_seq_cst = __ATOMIC_SEQ_CST
} memory_order;

#define atomic_store(p, v)                  __atomic_store_n((p), (v), __ATOMIC_SEQ_CST)
#define atomic_load(p)                      __atomic_load_n((p), __ATOMIC_SEQ_CST)
#define atomic_load_explicit(p, mo)         __atomic_load_n((p), (mo))
#define atomic_store_explicit(p, v, mo)     __atomic_store_n((p), (v), (mo))
#define atomic_fetch_add_explicit(p, v, mo) __atomic_fetch_add((p), (v), (mo))
#define atomic_exchange(p, v)               __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)

#else /* ---- MSVC fallback ------------------------------------------------ */

#include <intrin.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(_M_X64) && !defined(_M_ARM64)
#  error "libaes67's MSVC atomics fallback requires a 64-bit target"
#endif

/* No _Atomic qualifier on MSVC; volatile plus explicit barriers gives the
   ordering an SPSC ring needs on x64/arm64 under the MSVC memory model.
   Everything is widened to 64 bits: the ring's 32-bit timestamps and the
   running flag are stored in 64-bit slots for exactly this reason. */
#define _Atomic volatile

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

static __forceinline long long aes67__atomic_load64(volatile long long *p)
{
    long long v = *p;
    _ReadWriteBarrier();
    return v;
}

static __forceinline void aes67__atomic_store64(volatile long long *p, long long v)
{
    _ReadWriteBarrier();
    *p = v;
}

#define atomic_store(p, v)               aes67__atomic_store64((volatile long long *)(p), (long long)(v))
#define atomic_load(p)                   aes67__atomic_load64((volatile long long *)(p))
#define atomic_load_explicit(p, mo)      ((mo), aes67__atomic_load64((volatile long long *)(p)))
#define atomic_store_explicit(p, v, mo)  ((mo), aes67__atomic_store64((volatile long long *)(p), (long long)(v)))
#define atomic_fetch_add_explicit(p, v, mo) \
    ((mo), (unsigned long long) _InterlockedExchangeAdd64((volatile long long *)(p), (long long)(v)))
#define atomic_exchange(p, v) \
    ((unsigned long long) _InterlockedExchange64((volatile long long *)(p), (long long)(v)))

#endif

#if !defined(AES67_HAVE_STDATOMIC) && !defined(atomic_exchange)
#  if defined(_MSC_VER)
#    define atomic_exchange(p, v)         ((unsigned long long) _InterlockedExchange64((volatile long long *)(p), (long long)(v)))
#  else
#    define atomic_exchange(p, v) __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)
#  endif
#endif

/* The ring's atomics are declared through this so the MSVC fallback's 64-bit
   widening is the same on every platform: a 32-bit timestamp in a 64-bit
   atomic costs nothing and means one struct layout everywhere. */
#if defined(AES67_HAVE_STDATOMIC) || defined(AES67_CPP_BUILTIN_ATOMICS)
typedef _Atomic uint64_t aes67_atomic_u64;
#else
typedef volatile long long aes67_atomic_u64;
#endif

#endif /* MANIFOLD_AES67_ATOMIC_H */
