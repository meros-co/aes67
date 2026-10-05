# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Meros Inc.

# libaes67 -- AES67 / SMPTE ST 2110-30 RTP receive and transmit, SDP and SAP.
#
# Portable C11 with no dependencies beyond the platform's sockets and threads.
# The packet arithmetic (rtp.c, sdp.c) is identical on every platform and is
# what the tests exercise exhaustively; the socket paths differ per platform
# (see include/aes67/rx.h).

add_library(meros_aes67 STATIC
    src/rtp.c
    src/sdp.c
    src/rx.c
    src/netrx.c
    src/tx.c
)
add_library(meros::aes67 ALIAS meros_aes67)

target_include_directories(meros_aes67 PUBLIC include)
set_target_properties(meros_aes67 PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

if(MSVC)
    target_compile_definitions(meros_aes67 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
if(WIN32)
    target_link_libraries(meros_aes67 PUBLIC ws2_32 avrt)   # avrt: MMCSS for the receive thread
else()
    target_compile_options(meros_aes67 PRIVATE -Wall -Wextra)
    find_package(Threads REQUIRED)
    target_link_libraries(meros_aes67 PUBLIC Threads::Threads)
endif()

if(BUILD_TESTING)
    add_executable(test_aes67 tests/test_aes67.c)
    target_link_libraries(test_aes67 PRIVATE meros_aes67)
    if(MSVC)
        target_compile_definitions(test_aes67 PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
    add_test(NAME aes67 COMMAND test_aes67)

    # The headers from C++, before the standard library's: include order must
    # not matter to a C++ consumer.
    enable_language(CXX)
    add_executable(test_aes67_cpp tests/test_cpp_include.cpp)
    target_link_libraries(test_aes67_cpp PRIVATE meros_aes67)
    set_target_properties(test_aes67_cpp PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
    add_test(NAME aes67_cpp COMMAND test_aes67_cpp)
endif()
