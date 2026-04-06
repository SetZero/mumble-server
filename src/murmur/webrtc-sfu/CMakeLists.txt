# Copyright The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.

# WebRTC SFU module (Rust cdylib built via cargo).
#
# This target runs `cargo build` on the Rust crate in 3rdparty/webrtc-sfu
# and copies the resulting shared library next to the server binary.
# The server loads it at runtime via QLibrary - no link-time dependency.

option(webrtc-sfu "Build the WebRTC SFU module (requires Rust toolchain)." ON)

if(NOT webrtc-sfu)
	message(STATUS "WebRTC SFU module disabled (webrtc-sfu=OFF)")
	return()
endif()

find_program(CARGO_EXECUTABLE cargo)
if(NOT CARGO_EXECUTABLE)
	message(WARNING "cargo not found - WebRTC SFU module will not be built. "
	                "Install Rust (rustup.rs) to enable it.")
	return()
endif()

set(SFU_CRATE_DIR "${3RDPARTY_DIR}/webrtc-sfu")

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
	set(CARGO_BUILD_TYPE "--release")
	set(CARGO_TARGET_DIR "release")
else()
	set(CARGO_BUILD_TYPE "")
	set(CARGO_TARGET_DIR "debug")
endif()

if(WIN32)
	set(SFU_LIB_NAME "webrtc_sfu.dll")
elseif(APPLE)
	set(SFU_LIB_NAME "libwebrtc_sfu.dylib")
else()
	set(SFU_LIB_NAME "libwebrtc_sfu.so")
endif()

set(SFU_LIB_OUTPUT "${SFU_CRATE_DIR}/target/${CARGO_TARGET_DIR}/${SFU_LIB_NAME}")

add_custom_command(
	OUTPUT "${SFU_LIB_OUTPUT}"
	COMMAND ${CARGO_EXECUTABLE} build ${CARGO_BUILD_TYPE}
	WORKING_DIRECTORY "${SFU_CRATE_DIR}"
	COMMENT "Building WebRTC SFU Rust library"
	VERBATIM
)

add_custom_target(webrtc_sfu_build ALL
	DEPENDS "${SFU_LIB_OUTPUT}"
)

# Copy the built library next to the server binary.
add_custom_command(TARGET webrtc_sfu_build POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		"${SFU_LIB_OUTPUT}"
		"${CMAKE_BINARY_DIR}/${SFU_LIB_NAME}"
	COMMENT "Copying WebRTC SFU library to build directory"
)

# Provide include path for the C header.
target_include_directories(mumble_server_object_lib
	PUBLIC
		"${SFU_CRATE_DIR}/include"
)
