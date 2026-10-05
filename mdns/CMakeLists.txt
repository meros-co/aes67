# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Meros Inc.

# libmdns -- DNS-SD over multicast DNS, the device's half: announce its own
# services and find others' (what NMOS IS-04 discovery needs), with one socket
# and no system daemon.
#
# Portable C11. The packet arithmetic (mdns_build_*, mdns_parse_message, the
# answer and browse-assembly logic) has no socket in it and is what the tests
# pin.

add_library(meros_mdns STATIC
    src/mdns.c
)
add_library(meros::mdns ALIAS meros_mdns)

target_include_directories(meros_mdns PUBLIC include)
set_target_properties(meros_mdns PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

if(MSVC)
    target_compile_definitions(meros_mdns PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
if(WIN32)
    target_link_libraries(meros_mdns PUBLIC ws2_32)
else()
    target_compile_options(meros_mdns PRIVATE -Wall -Wextra)
endif()

if(BUILD_TESTING)
    add_executable(test_mdns tests/test_mdns.c)
    target_link_libraries(test_mdns PRIVATE meros_mdns)
    if(MSVC)
        target_compile_definitions(test_mdns PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
    add_test(NAME mdns COMMAND test_mdns)
endif()
