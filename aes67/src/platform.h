/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef AES67_SRC_PLATFORM_H
#define AES67_SRC_PLATFORM_H

/* What the receivers need from the platform, in one place: sockets, a thread,
 * a lock, a sleep and a monotonic clock. Private to the library. */

#include <stdbool.h>
#include <stdint.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <mswsock.h>
#  include <windows.h>
#  include <process.h>
   typedef SOCKET aes67_sock_t;
#  define AES67_BAD_SOCK INVALID_SOCKET
#  define aes67_closesock closesocket
#  define aes67_sockerr() WSAGetLastError()
   typedef HANDLE aes67_thread_t;
   typedef CRITICAL_SECTION aes67_mutex_t;
#  define AES67_THREAD_FN(name, arg) static unsigned __stdcall name(void *arg)
#  define AES67_THREAD_RETURN return 0
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <netinet/in.h>
#  include <pthread.h>
#  include <sys/socket.h>
#  include <time.h>
#  include <unistd.h>
   typedef int aes67_sock_t;
#  define AES67_BAD_SOCK (-1)
#  define aes67_closesock close
#  define aes67_sockerr() errno
   typedef pthread_t aes67_thread_t;
   typedef pthread_mutex_t aes67_mutex_t;
#  define AES67_THREAD_FN(name, arg) static void *name(void *arg)
#  define AES67_THREAD_RETURN return NULL
#endif

/* Monotonic nanoseconds: arrival stamps and inter-arrival gaps. */
static inline uint64_t aes67_now_ns(void)
{
#if defined(_WIN32)
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (uint64_t) ((double) c.QuadPart * 1e9 / (double) f.QuadPart);
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t) t.tv_sec * 1000000000ull + (uint64_t) t.tv_nsec;
#endif
}

static inline void aes67_sleep_ms(int ms)
{
#if defined(_WIN32)
    Sleep((DWORD) ms);
#else
    struct timespec t = { ms / 1000, (long) (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
#endif
}

static inline void aes67_mutex_init(aes67_mutex_t *m)
{
#if defined(_WIN32)
    InitializeCriticalSection(m);
#else
    pthread_mutex_init(m, NULL);
#endif
}

static inline void aes67_mutex_destroy(aes67_mutex_t *m)
{
#if defined(_WIN32)
    DeleteCriticalSection(m);
#else
    pthread_mutex_destroy(m);
#endif
}

static inline void aes67_mutex_lock(aes67_mutex_t *m)
{
#if defined(_WIN32)
    EnterCriticalSection(m);
#else
    pthread_mutex_lock(m);
#endif
}

static inline void aes67_mutex_unlock(aes67_mutex_t *m)
{
#if defined(_WIN32)
    LeaveCriticalSection(m);
#else
    pthread_mutex_unlock(m);
#endif
}

#if defined(_WIN32)
typedef unsigned (__stdcall *aes67_thread_main_t)(void *);
#else
typedef void *(*aes67_thread_main_t)(void *);
#endif

static inline bool aes67_thread_start(aes67_thread_t *t, aes67_thread_main_t fn, void *arg)
{
#if defined(_WIN32)
    *t = (HANDLE) _beginthreadex(NULL, 0, fn, arg, 0, NULL);
    return *t != NULL;
#else
    return pthread_create(t, NULL, fn, arg) == 0;
#endif
}

static inline void aes67_thread_join(aes67_thread_t t)
{
#if defined(_WIN32)
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
#else
    pthread_join(t, NULL);
#endif
}

#endif /* AES67_SRC_PLATFORM_H */
