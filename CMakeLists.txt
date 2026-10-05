# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Meros Inc.

cmake_minimum_required(VERSION 3.16)
project(meros_aes67 VERSION 0.1.0 LANGUAGES C)

# Built on its own, the tests are on by default; inside another project,
# that project's BUILD_TESTING decides.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    include(CTest)
endif()

add_subdirectory(aes67)
add_subdirectory(mdns)
