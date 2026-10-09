#
# Copyright 2026 Kartik Gohil
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#
cmake_minimum_required(VERSION 3.20)
project(libuspmtp VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Protocol Buffers ───────────────────────────────────────────────────────
find_package(Protobuf REQUIRED)

set(LIBUSPMTP_PROTO_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/usp-msg-1-5.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/usp-record-1-5.proto
)

protobuf_generate_cpp(LIBUSPMTP_PROTO_SRCS LIBUSPMTP_PROTO_HDRS
    ${LIBUSPMTP_PROTO_FILES}
)

# ── Options ────────────────────────────────────────────────────────────────
option(LIBUSPMTP_BUILD_SHARED "Build shared library (default: static)" OFF)
option(LIBUSPMTP_BUILD_TESTS  "Build test executables" OFF)
option(LIBUSPMTP_COVERAGE     "Instrument the library and tests for gcov line coverage" OFF)

# ── Source files ───────────────────────────────────────────────────────────
set(LIBUSPMTP_SOURCES
    src/usp_proto.cpp
    src/transport.cpp
    src/client.cpp
    src/libuspmtp.cpp
    ${LIBUSPMTP_PROTO_SRCS}
    ${LIBUSPMTP_PROTO_HDRS}
)

# ── Library target ─────────────────────────────────────────────────────────
if(LIBUSPMTP_BUILD_SHARED)
    add_library(libuspmtp SHARED ${LIBUSPMTP_SOURCES})
    target_compile_definitions(libuspmtp
        PRIVATE  LIBUSPMTP_BUILD_SHARED LIBUSPMTP_EXPORTS
        PUBLIC   LIBUSPMTP_BUILD_SHARED)
else()
    add_library(libuspmtp STATIC ${LIBUSPMTP_SOURCES})
endif()

# Alias for consumers using find_package / add_subdirectory
add_library(libuspmtp::libuspmtp ALIAS libuspmtp)

set_target_properties(libuspmtp PROPERTIES
    OUTPUT_NAME uspmtp
    VERSION     ${PROJECT_VERSION}
    SOVERSION   0
)

target_include_directories(libuspmtp
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}
)

# Thread support (pthreads on Linux/macOS)
find_package(Threads REQUIRED)
target_link_libraries(libuspmtp PRIVATE Threads::Threads protobuf::libprotobuf)

# Compiler warnings
target_compile_options(libuspmtp PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:
        -Wall -Wextra -Wpedantic -Wno-unused-parameter>
)

# ── Coverage ───────────────────────────────────────────────────────────────
# cmake -B build-cov -DLIBUSPMTP_BUILD_TESTS=ON -DLIBUSPMTP_COVERAGE=ON
# cmake --build build-cov && ctest --test-dir build-cov && cmake --build build-cov --target coverage
if(LIBUSPMTP_COVERAGE)
    set(LIBUSPMTP_COVERAGE_MIN_LINES 70 CACHE STRING
        "Minimum line coverage (percent) of src/ for the coverage target to succeed")
    target_compile_options(libuspmtp PRIVATE --coverage -O0)
    target_link_options(libuspmtp PUBLIC --coverage)
    find_program(GCOVR_EXECUTABLE gcovr)
    if(GCOVR_EXECUTABLE)
        add_custom_target(coverage
            COMMAND ${GCOVR_EXECUTABLE}
                --root ${CMAKE_CURRENT_SOURCE_DIR}
                --filter "src/.*"
                --exclude ".*\\.pb\\.(cc|h)"
                --print-summary
                --fail-under-line ${LIBUSPMTP_COVERAGE_MIN_LINES}
                ${CMAKE_CURRENT_BINARY_DIR}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Line coverage of src/ from the last test run (gcovr)"
            VERBATIM)
    else()
        message(WARNING "LIBUSPMTP_COVERAGE is ON but gcovr was not found; the coverage target is unavailable")
    endif()
endif()

# ── Tests ──────────────────────────────────────────────────────────────────
if(LIBUSPMTP_BUILD_TESTS)
    enable_testing()

    foreach(test_name IN ITEMS test_proto test_transport test_client)
        add_executable(${test_name} tests/${test_name}.cpp)
        target_link_libraries(${test_name} PRIVATE libuspmtp::libuspmtp Threads::Threads)
        target_include_directories(${test_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()

# ── Install rules ──────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS libuspmtp
    EXPORT  libuspmtpTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES include/libuspmtp.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT libuspmtpTargets
    FILE      libuspmtpTargets.cmake
    NAMESPACE libuspmtp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libuspmtp
)

# Generate and install a basic config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/libuspmtpConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libuspmtpConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libuspmtpConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libuspmtp
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/libuspmtpConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libuspmtpConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libuspmtp
)
