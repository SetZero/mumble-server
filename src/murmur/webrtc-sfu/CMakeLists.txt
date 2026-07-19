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

# On the Windows CI the C++ build (and thus this custom command) runs under Git
# Bash, whose /usr/bin/link.exe - the GNU coreutils `link` hard-link tool -
# shadows the MSVC linker on PATH. cargo's rustc then invokes the wrong
# `link.exe` and fails to link even trivial build scripts (proc-macro2, quote,
# getrandom) with "/usr/bin/link: extra operand". Pin rustc's linker for the
# MSVC host target to the real link.exe that sits next to cl.exe
# (CMAKE_CXX_COMPILER), bypassing PATH lookup entirely. link.exe is always in the
# same toolchain bin directory as cl.exe.
set(SFU_CARGO_LAUNCHER "")
if(WIN32 AND MSVC)
	get_filename_component(_msvc_bin_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
	set(SFU_CARGO_LAUNCHER ${CMAKE_COMMAND} -E env
		"CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=${_msvc_bin_dir}/link.exe")
endif()

add_custom_command(
	OUTPUT "${SFU_LIB_OUTPUT}"
	COMMAND ${SFU_CARGO_LAUNCHER} ${CARGO_EXECUTABLE} build ${CARGO_BUILD_TYPE}
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
