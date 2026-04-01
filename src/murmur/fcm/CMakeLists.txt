# Copyright The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.

# Standalone FCM push notification module.
# Built as a shared library that the Mumble server loads at runtime.
# If this target is disabled or the .so/.dll is not deployed, the
# server simply runs without push notification support.

option(fcm-push "Build the FCM push notification module (shared library)." ON)

if(NOT fcm-push)
	message(STATUS "FCM push module disabled (fcm-push=OFF)")
	return()
endif()

find_pkg(Poco COMPONENTS Foundation JSON JWT Net NetSSL Crypto QUIET)

if(NOT Poco_FOUND)
	message(WARNING "Poco libraries not found - FCM push module will not be built. "
	                "Install libpoco-dev (or equivalent) to enable it.")
	return()
endif()

add_library(mumble_push_fcm SHARED
	"mumble_push_fcm.cpp"
)

target_compile_definitions(mumble_push_fcm PRIVATE MUMBLE_PUSH_BUILD_DLL)

target_include_directories(mumble_push_fcm
	PUBLIC
		"${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(mumble_push_fcm
	PRIVATE
		Poco::Foundation
		Poco::JSON
		Poco::JWT
		Poco::Net
		Poco::NetSSL
		Poco::Crypto
)

set_target_properties(mumble_push_fcm
	PROPERTIES
		# On Linux: libmumble_push_fcm.so
		# On Windows: mumble_push_fcm.dll
		OUTPUT_NAME "mumble_push_fcm"
		VERSION "${PROJECT_VERSION}"
		SOVERSION 1
		POSITION_INDEPENDENT_CODE ON
		C_VISIBILITY_PRESET hidden
		CXX_VISIBILITY_PRESET hidden
		VISIBILITY_INLINES_HIDDEN ON
)

# Install alongside the server binary so it can be found at runtime.
install(TARGETS mumble_push_fcm
	LIBRARY DESTINATION "${MUMBLE_INSTALL_EXECUTABLEDIR}"
	RUNTIME DESTINATION "${MUMBLE_INSTALL_EXECUTABLEDIR}"
)
