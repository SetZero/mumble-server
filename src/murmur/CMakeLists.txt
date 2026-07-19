# Copyright The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.

set(MURMUR_RC "${CMAKE_CURRENT_BINARY_DIR}/murmur.rc")
set(MURMUR_ICON "${CMAKE_SOURCE_DIR}/icons/murmur.ico")
set(MURMUR_PLIST "${CMAKE_CURRENT_BINARY_DIR}/murmur.plist")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/murmur.plist.in" "${MURMUR_PLIST}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/murmur.rc.in" "${MURMUR_RC}")

set(ICE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/MumbleServer.ice")

include(qt-utils)

option(ice "Build support for Ice RPC." ON)

find_pkg(Qt6 COMPONENTS Sql REQUIRED)

add_library(mumble_server_object_lib OBJECT
	"AudioReceiverBuffer.cpp"
	"AudioReceiverBuffer.h"
	"Cert.cpp"
	"LegacyPasswordHash.cpp"
	"Messages.cpp"
	"Meta.cpp"
	"Meta.h"
	"PBKDF2.cpp"
	"PBKDF2.h"
	"Totp.cpp"
	"Totp.h"
	"Register.cpp"
	"RPC.cpp"
	"Server.cpp"
	"Server.h"
	"AclSubsystem.cpp"
	"AclSubsystem.h"
	"UserStateSerializer.cpp"
	"UserStateSerializer.h"
"ServerUser.cpp"
	"ServerUser.h"
	"Globals.cpp"
	"ServerApplication.cpp"
	"DBWrapper.cpp"

	"pchat/PersistentChatManager.cpp"
	"pchat/PchatProtocolHandlers.cpp"
	"pchat/ServerBridge.cpp"
	"pchat/TokenBucketRateLimiter.cpp"

	"push/PushNotificationDispatcher.cpp"

	"WebRtcSfuManager.cpp"
	"WebRtcSfuManager.h"

	"PluginHostManager.cpp"
	"PluginHostManager.h"
	"LinkPreviewBridge.cpp"
	"LinkPreviewBridge.h"

	"ServerEventDistributor.cpp"
	"ServerEventDistributor.h"


	"${SHARED_SOURCE_DIR}/ACL.cpp"
	"${SHARED_SOURCE_DIR}/ACL.h"
	"${SHARED_SOURCE_DIR}/Channel.cpp"
	"${SHARED_SOURCE_DIR}/Channel.h"
	"${SHARED_SOURCE_DIR}/ChannelListenerManager.cpp"
	"${SHARED_SOURCE_DIR}/ChannelListenerManager.h"
	"${SHARED_SOURCE_DIR}/Connection.cpp"
	"${SHARED_SOURCE_DIR}/Connection.h"
	"${SHARED_SOURCE_DIR}/Group.cpp"
	"${SHARED_SOURCE_DIR}/Group.h"
	"${SHARED_SOURCE_DIR}/User.cpp"
	"${SHARED_SOURCE_DIR}/User.h"
)

if(WIN32)
	add_executable(mumble-server WIN32 "main.cpp")
else()
	add_executable(mumble-server "main.cpp")
endif()

target_link_libraries(mumble-server mumble_server_object_lib CLI11::CLI11)

set_property(TARGET mumble-server PROPERTY INTERPROCEDURAL_OPTIMIZATION ${lto})
set_property(TARGET mumble_server_object_lib PROPERTY INTERPROCEDURAL_OPTIMIZATION ${lto})

set_target_properties(mumble_server_object_lib
	PROPERTIES
		AUTOMOC ON
)

set_target_properties(mumble-server
	PROPERTIES
		AUTOMOC ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set(AUTOGEN_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/murmur_autogen")
message(STATUS "File: ${AUTOGEN_BUILD_DIR}")
set_source_files_properties("${AUTOGEN_BUILD_DIR}/mocs_compilation.cpp" PROPERTIES COMPILE_FLAGS "-w")

target_compile_definitions(mumble_server_object_lib
	PUBLIC
		"MURMUR"
		"QT_RESTRICTED_CAST_FROM_ASCII"
)

target_include_directories(mumble_server_object_lib
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR} # This is required for includes in current folder to be found by files from the shared directory.
		${SHARED_SOURCE_DIR}
)

find_pkg(Qt6 COMPONENTS Network REQUIRED)

target_link_libraries(mumble_server_object_lib PUBLIC shared Qt6::Sql Qt6::Network nlohmann_json::nlohmann_json)

# Qt6 internal headers (e.g. qhash.h) trigger -Walloc-size-larger-than= on GCC
# because of allocation expressions that GCC's static analysis cannot bound.
# These are false positives in third-party code; suppress the diagnostic for
# this target only.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	target_compile_options(mumble_server_object_lib PRIVATE -Wno-alloc-size-larger-than)
endif()

# --- mumble-plugin-host (Rust cdylib) -------------------------------------
# The server links against this crate's C ABI (cbindgen header at
# host/include/mumble_plugin_host.h). It has to exist before the link, so:
#
#   * if a packager/CI dropped a prebuilt library in lib/, link that (the Docker
#     images build the cdylib in a separate stage and copy it there so the C++
#     build stage needs no Rust toolchain);
#   * otherwise build it here with cargo, the same way the WebRTC SFU module is
#     built, so a plain `cmake --build` (local dev, CodeQL, ...) resolves the
#     plugin_host_* symbols without a separate manual step.
#
# Previously this only did find_library + a warning, so every build harness that
# was not build.sh (CodeQL, local cmake) linked with undefined plugin_host_*.
set(MUMBLE_PLUGIN_HOST_DIR "${CMAKE_SOURCE_DIR}/3rdparty/mumble-plugin-host")
target_include_directories(mumble_server_object_lib PUBLIC
    "${MUMBLE_PLUGIN_HOST_DIR}/host/include"
    "${MUMBLE_PLUGIN_HOST_DIR}/include"
)

# A stale NOTFOUND in the cache must not stick once the library is dropped in;
# re-resolve every configure.
unset(MUMBLE_PLUGIN_HOST_LIB CACHE)
find_library(MUMBLE_PLUGIN_HOST_LIB
    NAMES mumble_plugin_host
    HINTS
        "${MUMBLE_PLUGIN_HOST_DIR}/lib"
        "${MUMBLE_PLUGIN_HOST_DIR}/target/release"
    NO_DEFAULT_PATH
)

if(MUMBLE_PLUGIN_HOST_LIB)
    message(STATUS "mumble-plugin-host: linking prebuilt ${MUMBLE_PLUGIN_HOST_LIB}")
    target_link_libraries(mumble_server_object_lib PUBLIC "${MUMBLE_PLUGIN_HOST_LIB}")
else()
    find_program(CARGO_EXECUTABLE cargo)
    if(NOT CARGO_EXECUTABLE)
        message(FATAL_ERROR
            "mumble_plugin_host was not found in "
            "${MUMBLE_PLUGIN_HOST_DIR}/{lib,target/release} and cargo is not "
            "available to build it. Install Rust (https://rustup.rs) or drop a "
            "prebuilt libmumble_plugin_host into "
            "${MUMBLE_PLUGIN_HOST_DIR}/lib.")
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(_ph_cargo_profile "")
        set(_ph_target_subdir "debug")
    else()
        set(_ph_cargo_profile "--release")
        set(_ph_target_subdir "release")
    endif()

    # WASM component plugins are the plugin host's default feature set, but they
    # pull in the whole wasmtime runtime, which dominates build time. None of the
    # exported plugin_host_* C symbols depend on it, so a build that only needs
    # native cdylib plugins (or a resource-constrained CI runner) can drop it and
    # still link. Default ON to preserve full functionality.
    option(plugin-host-wasm
        "Build the plugin host with WASM component support (pulls in wasmtime)." ON)
    if(plugin-host-wasm)
        set(_ph_cargo_features "")
    else()
        message(STATUS "mumble-plugin-host: WASM component support disabled (plugin-host-wasm=OFF)")
        set(_ph_cargo_features "--no-default-features")
    endif()

    # cdylib output name and the file the C++ actually links against. On MSVC
    # that is the import lib, and the DLL has to sit next to the binary at
    # runtime; ELF/Mach-O link the shared object directly.
    if(WIN32)
        set(_ph_runtime "mumble_plugin_host.dll")
        set(_ph_link_lib "${MUMBLE_PLUGIN_HOST_DIR}/target/${_ph_target_subdir}/mumble_plugin_host.dll.lib")
        set(_ph_build_output "${_ph_link_lib}")
    elseif(APPLE)
        set(_ph_link_lib "${MUMBLE_PLUGIN_HOST_DIR}/target/${_ph_target_subdir}/libmumble_plugin_host.dylib")
        set(_ph_build_output "${_ph_link_lib}")
    else()
        set(_ph_link_lib "${MUMBLE_PLUGIN_HOST_DIR}/target/${_ph_target_subdir}/libmumble_plugin_host.so")
        set(_ph_build_output "${_ph_link_lib}")
    endif()

    # On the Windows CI the C++ build runs under Git Bash, whose
    # /usr/bin/link.exe (GNU coreutils) shadows the MSVC linker on PATH, so
    # cargo's rustc picks the wrong link.exe ("extra operand"). Pin rustc's
    # linker to the real link.exe next to cl.exe. Same fix as the SFU module.
    set(_ph_cargo_launcher "")
    if(WIN32 AND MSVC)
        get_filename_component(_msvc_bin_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
        set(_ph_cargo_launcher ${CMAKE_COMMAND} -E env
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=${_msvc_bin_dir}/link.exe")
    endif()

    message(STATUS "mumble-plugin-host: building via cargo (${_ph_build_output})")
    add_custom_command(
        OUTPUT "${_ph_build_output}"
        COMMAND ${_ph_cargo_launcher} ${CARGO_EXECUTABLE} build ${_ph_cargo_profile} ${_ph_cargo_features} -p mumble-plugin-host
        WORKING_DIRECTORY "${MUMBLE_PLUGIN_HOST_DIR}"
        COMMENT "Building mumble-plugin-host Rust cdylib"
        VERBATIM
    )
    add_custom_target(mumble_plugin_host_build DEPENDS "${_ph_build_output}")
    # Force cargo to run (and regenerate the cbindgen header) before any C++ in
    # the object lib compiles or links.
    add_dependencies(mumble_server_object_lib mumble_plugin_host_build)
    target_link_libraries(mumble_server_object_lib PUBLIC "${_ph_link_lib}")

    if(WIN32)
        # The import lib is not enough at runtime; put the DLL next to the exe.
        add_custom_command(TARGET mumble_plugin_host_build POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${MUMBLE_PLUGIN_HOST_DIR}/target/${_ph_target_subdir}/${_ph_runtime}"
                "${CMAKE_BINARY_DIR}/${_ph_runtime}"
            COMMENT "Copying mumble_plugin_host.dll next to the server binary"
        )
    endif()
endif()

if(static)
	# MariaDB and MySQL
	if(TARGET Qt6::QMYSQLDriverPlugin)
		include_qt_plugin(mumble_server_object_lib PRIVATE "QMYSQLDriverPlugin")
		target_link_libraries(mumble_server_object_lib PRIVATE Qt6::QMYSQLDriverPlugin)
	endif()
	# Open DataBase Connectivity
	if(TARGET Qt6::QODBCDriverPlugin)
		include_qt_plugin(mumble_server_object_lib PRIVATE "QODBCDriverPlugin")
		target_link_libraries(mumble_server_object_lib PRIVATE Qt6::QODBCDriverPlugin)
		if(WIN32)
			find_library(LIB_ODBC32 "odbc32")
			target_link_libraries(mumble_server_object_lib PRIVATE ${LIB_ODBC32})
		endif()
	endif()
	# PostgreSQL
	if(TARGET Qt6::QPSQLDriverPlugin)
		include_qt_plugin(mumble_server_object_lib PRIVATE "QPSQLDriverPlugin")
		target_link_libraries(mumble_server_object_lib PRIVATE Qt6::QPSQLDriverPlugin)
	endif()
	# SQLite
	if(TARGET Qt6::QSQLiteDriverPlugin)
		include_qt_plugin(mumble_server_object_lib PRIVATE "QSQLiteDriverPlugin")
		target_link_libraries(mumble_server_object_lib PRIVATE Qt6::QSQLiteDriverPlugin)
	endif()
endif()

if(WIN32)
	target_sources(mumble_server_object_lib
		PRIVATE
			"About.cpp"
			"About.h"
			"Tray.cpp"
			"Tray.h"
			"murmur.qrc"

			"${CMAKE_SOURCE_DIR}/auxiliary_files/mumble.appcompat.manifest"
			"${MURMUR_RC}"
	)

	set_target_properties(mumble_server_object_lib
		PROPERTIES
			AUTORCC ON
	)

	find_pkg(Qt6 COMPONENTS Widgets REQUIRED)

	target_link_libraries(mumble_server_object_lib
		PUBLIC
			Qt6::Widgets
			dbghelp.lib
			shlwapi.lib
			rpcrt4.lib
	)

	if(static AND TARGET Qt6::QWindowsIntegrationPlugin)
		include_qt_plugin(mumble_server_object_lib PRIVATE QWindowsIntegrationPlugin)
		target_link_libraries(mumble_server_object_lib PRIVATE Qt6::QWindowsIntegrationPlugin)
	endif()
else()
	target_sources(mumble_server_object_lib
		PRIVATE
			"UnixMurmur.cpp"
			"UnixMurmur.h"
	)

	if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
		find_library(CAP_LIBRARY NAMES cap)
		target_link_libraries(mumble_server_object_lib PUBLIC ${CAP_LIBRARY})
	endif()
endif()

if(zeroconf)
	if(NOT APPLE)
		find_pkg(avahi-compat-libdns_sd QUIET)
		if(avahi-compat-libdns_sd_FOUND)
			target_include_directories(mumble_server_object_lib PUBLIC ${avahi-compat-libdns_sd_INCLUDE_DIRS})
			target_link_libraries(mumble_server_object_lib PUBLIC ${avahi-compat-libdns_sd_LIBRARIES})
		else()
			find_library(LIB_DNSSD "dnssd")
			if(${LIB_DNSSD} STREQUAL "LIB_DNSSD-NOTFOUND")
				message(FATAL_ERROR "DNS-SD library not found!")
			endif()
			target_link_libraries(mumble_server_object_lib PUBLIC ${LIB_DNSSD})
		endif()
	endif()

	target_compile_definitions(mumble_server_object_lib PUBLIC "USE_ZEROCONF")

	target_include_directories(mumble_server_object_lib PUBLIC "${3RDPARTY_DIR}/qqbonjour")

	target_sources(mumble_server_object_lib
		PRIVATE
			"Zeroconf.cpp"
			"Zeroconf.h"
			# Unlike what the name implies, this 3rdparty helper is not actually related to Bonjour.
			# It just uses the API provided by mDNSResponder, making it compatible with Avahi too.
			"${3RDPARTY_DIR}/qqbonjour/BonjourRecord.h"
			"${3RDPARTY_DIR}/qqbonjour/BonjourServiceRegister.cpp"
			"${3RDPARTY_DIR}/qqbonjour/BonjourServiceRegister.h"
	)
endif()

if(ice)
	find_pkg(Ice
		COMPONENTS
			Ice
			IceSSL
		OPTIONAL_COMPONENTS
			IceDiscovery
			IceLocatorDiscovery
			IceUtil
		REQUIRED
	)

	if(Ice_VERSION_MAJOR LESS 3)
		message(FATAL_ERROR "Unsupported Ice version, at least 3.0 is required.")
	endif()

	get_filename_component(ICE_FILE_NAME ${ICE_FILE} NAME_WE)

	list(APPEND ICE_GENERATED_FILES
		"${ICE_FILE_NAME}.cpp"
		"${ICE_FILE_NAME}.h"
	)

	foreach(SLICE_DIR ${Ice_SLICE_DIRS})
		list(APPEND SLICE_INCLUDE_ARGS "-I${SLICE_DIR}")
	endforeach()

	add_custom_command(
		OUTPUT ${ICE_GENERATED_FILES}
		COMMAND ${Ice_SLICE2CPP_EXECUTABLE}
		ARGS "--checksum" ${SLICE_INCLUDE_ARGS} ${ICE_FILE}
		MAIN_DEPENDENCY ${ICE_FILE}
		COMMENT "Generating Ice files"
		VERBATIM
	)

	add_custom_target(generate_murmur_ice_wrapper
		DEPENDS "MumbleServerIceWrapper.cpp" 
	)
	add_dependencies(mumble_server_object_lib generate_murmur_ice_wrapper)
	add_custom_command(
		OUTPUT "MumbleServerIceWrapper.cpp"
		COMMAND Python::Interpreter
		ARGS "${CMAKE_SOURCE_DIR}/scripts/generateIceWrapper.py" -i "${ICE_FILE}"
			-g "${ICE_FILE_NAME}.h" -o "MumbleServerIceWrapper.cpp" -q
		DEPENDS ${ICE_GENERATED_FILES}
		COMMENT "Generating MumbleServerIceWrapper"
	)
	# Even though the file is a .cpp, it is still being included in MumbleServerIce.cpp
	target_include_directories(mumble_server_object_lib PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

	# We explicitly tell CMake not to call any autogen tools (e.g. MOC) for the generated files.
	# @ref https://cmake.org/cmake/help/latest/policy/CMP0071.html
	set_property(SOURCE ${ICE_GENERATED_FILES} PROPERTY SKIP_AUTOGEN ON)

	target_sources(mumble_server_object_lib
		PRIVATE
			"MumbleServerIce.cpp"
			"MumbleServerIce.h"
			${ICE_GENERATED_FILES}
	)
	target_compile_definitions(mumble_server_object_lib
		PUBLIC
			"USE_ICE"
			"ICE_STATIC_LIBS"
	)

	target_include_directories(mumble_server_object_lib PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

	if(static)
		# BZip2 is used by Ice, specifically in ConnectionI.cpp.
		# We link to the library explicitly because CMake is not aware of the dependency.
		# TODO: Fix or rewrite the official FindIce.cmake.
		find_pkg(BZip2 REQUIRED)
	endif()
	target_link_libraries(mumble_server_object_lib
		PUBLIC
			Ice::Ice
			Ice::IceSSL
			$<TARGET_NAME_IF_EXISTS:Ice::IceDiscovery>
			$<TARGET_NAME_IF_EXISTS:Ice::IceLocatorDiscovery>
			$<TARGET_NAME_IF_EXISTS:Ice::IceUtil>
			$<TARGET_NAME_IF_EXISTS:BZip2::BZip2>
	)
	
	file(COPY "${ICE_FILE}" DESTINATION ${CMAKE_BINARY_DIR})
endif()

install(TARGETS mumble-server RUNTIME DESTINATION "${MUMBLE_INSTALL_EXECUTABLEDIR}" COMPONENT mumble_server)

if(packaging)
	if(WIN32)
		if(translations)
			list(APPEND installer_vars "--all-languages")
		endif()

		list(APPEND installer_vars
			"--version" ${PROJECT_VERSION}
			"--arch" ${MUMBLE_TARGET_ARCH}
			"--vc-redist-required" "${VC_REDIST_VERSION}"
		)

		if(skip-msi-rebuild)
			list(APPEND installer_vars
				"--skip-msi-rebuild"
			)
		endif()

		file(COPY
			${CMAKE_SOURCE_DIR}/installer/MumbleInstall.cs
			${CMAKE_SOURCE_DIR}/installer/ServerInstaller.cs
			DESTINATION
				${CMAKE_BINARY_DIR}/installer/server
		)

		add_custom_command(TARGET mumble-server
			POST_BUILD
			COMMAND cscs.exe -cd MumbleInstall.cs 
			COMMAND cscs.exe ServerInstaller.cs ${installer_vars}
			WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/installer/server
		)
	endif()
endif()


# Compile and link against database implementation
add_subdirectory(database)

target_link_libraries(mumble_server_object_lib PUBLIC mumble_server_database)

# FCM push notification module (standalone shared library, optional)
add_subdirectory(fcm)

# WebRTC SFU module (Rust cdylib, optional)
add_subdirectory(webrtc-sfu)
