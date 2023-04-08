# Copyright 2020-2023 The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.

include(GNUInstallDirs)
include(pkg-utils)

# Turns a path into an absolute path if it isn't absolute already
function(make_absolute out_path in_path)
	get_filename_component(abs_path "${in_path}" ABSOLUTE BASE_DIR "${CMAKE_INSTALL_PREFIX}")
	set(${out_path} "${abs_path}" PARENT_SCOPE)
endfunction()

function(assert_is_relative path)
	make_absolute(abs_path "${path}")

	if("${path}" STREQUAL "${abs_path}")
		message(FATAL_ERROR "Encountered absolute install path but expected a relative one (\"${path}\")")
	endif()
endfunction()

function(pkgconf_install_path outputVariable module variable default)
	find_package(PkgConfig)

	if(NOT PkgConfig_FOUND)
		# Immediately use the default and return
		set(${outputVariable} "${default}" PARENT_SCOPE)
		return()
	endif()

	get_pkgconf_variable(
		OUTPUT_VARIABLE PKGCONF_PATH
		MODULE ${module}
		VARIABLE_NAME ${variable}
	)

	if(NOT PKGCONF_PATH)
		set(${outputVariable} "${default}" PARENT_SCOPE)
		message(WARNING "Using fallback install path for ${outputVariable}: '${default}'")
	elseif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
		set(${outputVariable} "${PKGCONF_PATH}" PARENT_SCOPE)
	else()
		# The paths returned by pkgconf are always absolute, which breaks cmake's system using
		# CMAKE_INSTALL_PREFIX to determine where file should be installed to.
		# Therefore, we have to make the path relative instead.
		if("${PKGCONF_PATH}" MATCHES "^/usr/local/.*")
			string(REGEX REPLACE "^/usr/local/" "" REL_PATH "${PKGCONF_PATH}")
		elseif("${PKGCONF_PATH}" MATCHES "^/usr/.*")
			string(REGEX REPLACE "^/usr/" "" REL_PATH "${PKGCONF_PATH}")
		else()
			string(REGEX REPLACE "^/" "" REL_PATH "${PKGCONF_PATH}")
		endif()

		set(${outputVariable} "${REL_PATH}" PARENT_SCOPE)
	endif()
endfunction()


if(UNIX)
	if(APPLE)
		set(EXECUTABLEDIR_DEFAULT ".")
		set(SERVICEFILEDIR_DEFAULT "./services/")
		set(SYSUSERSDIR_DEFAULT "./sysusers/")
		set(TMPFILESDIR_DEFAULT "./tmpfiles/")
	else()
		set(EXECUTABLEDIR_DEFAULT "${CMAKE_INSTALL_BINDIR}")
		pkgconf_install_path(SERVICEFILEDIR_DEFAULT systemd systemd_system_unit_dir "${CMAKE_INSTALL_SYSCONFDIR}/systemd/system/")
		pkgconf_install_path(SYSUSERSDIR_DEFAULT systemd sysusers_dir "${CMAKE_INSTALL_SYSCONFDIR}/sysusers.d")
		pkgconf_install_path(TMPFILESDIR_DEFAULT systemd tmpfiles_dir "${CMAKE_INSTALL_SYSCONFDIR}/tmpfiles.d")
	endif()

	set(LIBDIR_DEFAULT "${CMAKE_INSTALL_LIBDIR}/mumble")
	set(PLUGINDIR_DEFAULT "${CMAKE_INSTALL_LIBDIR}/mumble/plugins")
	set(SCRIPTDIR_DEFAULT "${CMAKE_INSTALL_BINDIR}")
	set(MANDIR_DEFAULT "${CMAKE_INSTALL_MANDIR}/man1")
	set(DOCDIR_DEFAULT "${CMAKE_INSTALL_DOCDIR}")
	set(LICENSEDIR_DEFAULT "${EXECUTABLEDIR_DEFAULT}/licenses")
	set(SYSCONFDIR_DEFAULT "${CMAKE_INSTALL_SYSCONFDIR}/mumble")
	set(METADATADIR_DEFAULT "${CMAKE_INSTALL_DATAROOTDIR}/metainfo")
	set(APPLICATIONSDIR_DEFAULT "${CMAKE_INSTALL_DATAROOTDIR}/applications")
else()
	set(EXECUTABLEDIR_DEFAULT ".")
	# In order for the installer to produce a working version of Mumble, this
	# path must not be changed.
	set(LIBDIR_DEFAULT ".")
	set(PLUGINDIR_DEFAULT "./plugins")
	set(SCRIPTDIR_DEFAULT "./scripts")
	set(MANDIR_DEFAULT "./man1")
	set(DOCDIR_DEFAULT "./docs")
	set(LICENSEDIR_DEFAULT "${EXECUTABLEDIR_DEFAULT}/licenses")
	set(SYSCONFDIR_DEFAULT "${CMAKE_INSTALL_SYSCONFDIR}/mumble")
	set(METADATADIR_DEFAULT "./metainfo")
	set(APPLICATIONSDIR_DEFAULT "./applications")
	set(SERVICEFILEDIR_DEFAULT "./services/")
	set(SYSUSERSDIR_DEFAULT "./sysusers/")
	set(TMPFILESDIR_DEFAULT "./tmpfiles/")
endif()

set(MUMBLE_INSTALL_EXECUTABLEDIR "${EXECUTABLEDIR_DEFAULT}" CACHE PATH "The directory to install the main executable(s) into")
set(MUMBLE_INSTALL_LIBDIR "${LIBDIR_DEFAULT}" CACHE PATH "The directory to install the built libraries into")
set(MUMBLE_INSTALL_PLUGINDIR "${PLUGINDIR_DEFAULT}" CACHE PATH "The directory to install the built plugins into")
set(MUMBLE_INSTALL_SCRIPTDIR "${SCRIPTDIR_DEFAULT}" CACHE PATH "The directory to install any additional scripts into")
set(MUMBLE_INSTALL_MANDIR "${MANDIR_DEFAULT}" CACHE PATH "The directory to install man files into")
set(MUMBLE_INSTALL_DOCDIR "${DOCDIR_DEFAULT}" CACHE PATH "The directory to install documentation files into")
set(MUMBLE_INSTALL_LICENSEDIR "${LICENSEDIR_DEFAULT}" CACHE PATH "The directory to install license files into")
set(MUMBLE_INSTALL_SYSCONFDIR "${SYSCONFDIR_DEFAULT}" CACHE PATH "The directory to install system-wide config files to")
set(MUMBLE_INSTALL_METADATADIR "${METADATADIR_DEFAULT}" CACHE PATH "The directory to install metadata files files to")
set(MUMBLE_INSTALL_APPLICATIONSDIR "${APPLICATIONSDIR_DEFAULT}" CACHE PATH "The directory to install application files files to")
set(MUMBLE_INSTALL_SERVICEFILEDIR "${SERVICEFILEDIR_DEFAULT}" CACHE PATH "The directory to install systemd service files to")
set(MUMBLE_INSTALL_SYSUSERSDIR "${SYSUSERSDIR_DEFAULT}" CACHE PATH "The directory to install systemd sysusers files to")
set(MUMBLE_INSTALL_TMPFILESDIR "${TMPFILESDIR_DEFAULT}" CACHE PATH "The directory to install systemd tmpfiles files to")

if(packaging)
	# Using absolute install paths doesn't allow CPack to create the installer for us.
	# Therefore we have to make sure that the paths are indeed relative.
	assert_is_relative("${MUMBLE_INSTALL_EXECUTABLEDIR}")
	assert_is_relative("${MUMBLE_INSTALL_LIBDIR}")
	assert_is_relative("${MUMBLE_INSTALL_PLUGINDIR}")
	assert_is_relative("${MUMBLE_INSTALL_SCRIPTDIR}")
	assert_is_relative("${MUMBLE_INSTALL_MANDIR}")
	assert_is_relative("${MUMBLE_INSTALL_DOCDIR}")
	assert_is_relative("${MUMBLE_INSTALL_LICENSEDIR}")
	assert_is_relative("${MUMBLE_INSTALL_SYSCONFDIR}")
	assert_is_relative("${MUMBLE_INSTALL_METADATADIR}")
	assert_is_relative("${MUMBLE_INSTALL_APPLICATIONSDIR}")
	assert_is_relative("${MUMBLE_INSTALL_SERVICEFILEDIR}")
	assert_is_relative("${MUMBLE_INSTALL_SYSUSERSDIR}")
	assert_is_relative("${MUMBLE_INSTALL_TMPFILESDIR}")

	if (WIN32)
		if(NOT "${MUMBLE_INSTALL_LIBDIR}" STREQUAL "${LIBDIR_DEFAULT}")
			# The path has been altered which will not allow for a working installer to be created
			message(FATAL_ERROR "Found non default MUMBLE_INSTALL_LIBDIR path, that will not result in a working installer! (\"${MUMBLE_INSTALL_LIBDIR}\")")
		endif()
	endif()
endif()

# Generate an absolute path from all our relative install paths, so they can be used in places where
# the final, full installation path is required.
make_absolute(MUMBLE_INSTALL_ABS_EXECUTABLEDIR "${MUMBLE_INSTALL_EXECUTABLEDIR}")
make_absolute(MUMBLE_INSTALL_ABS_LIBDIR "${MUMBLE_INSTALL_LIBDIR}")
make_absolute(MUMBLE_INSTALL_ABS_PLUGINDIR "${MUMBLE_INSTALL_PLUGINDIR}")
make_absolute(MUMBLE_INSTALL_ABS_SCRIPTDIR "${MUMBLE_INSTALL_SCRIPTDIR}")
make_absolute(MUMBLE_INSTALL_ABS_MANDIR "${MUMBLE_INSTALL_MANDIR}")
make_absolute(MUMBLE_INSTALL_ABS_DOCDIR "${MUMBLE_INSTALL_DOCDIR}")
make_absolute(MUMBLE_INSTALL_ABS_LICENSEDIR "${MUMBLE_INSTALL_LICENSEDIR}")
make_absolute(MUMBLE_INSTALL_ABS_SYSCONFDIR "${MUMBLE_INSTALL_SYSCONFDIR}")
make_absolute(MUMBLE_INSTALL_ABS_METADATADIR "${MUMBLE_INSTALL_METADATADIR}")
make_absolute(MUMBLE_INSTALL_ABS_APPLICATIONSDIR "${MUMBLE_INSTALL_APPLICATIONSDIR}")
make_absolute(MUMBLE_INSTALL_ABS_SERVICEFILEDIR "${MUMBLE_INSTALL_SERVICEFILEDIR}")
make_absolute(MUMBLE_INSTALL_ABS_SYSUSERSDIR "${MUMBLE_INSTALL_SYSUSERSDIR}")
make_absolute(MUMBLE_INSTALL_ABS_TMPFILESDIR "${MUMBLE_INSTALL_TMPFILESDIR}")

option(display-install-paths OFF)

if(display-install-paths)
	message(STATUS "")
	message(STATUS "These are the paths the different components will be installed to:")
	message(STATUS "Executables:       \"${MUMBLE_INSTALL_ABS_EXECUTABLEDIR}\"")
	message(STATUS "Libraries:         \"${MUMBLE_INSTALL_ABS_LIBDIR}\"")
	message(STATUS "Plugins:           \"${MUMBLE_INSTALL_ABS_PLUGINDIR}\"")
	message(STATUS "Scripts:           \"${MUMBLE_INSTALL_ABS_SCRIPTDIR}\"")
	message(STATUS "Man-files:         \"${MUMBLE_INSTALL_ABS_MANDIR}\"")
	message(STATUS "Documentation:     \"${MUMBLE_INSTALL_ABS_DOCDIR}\"")
	message(STATUS "Licenses:          \"${MUMBLE_INSTALL_ABS_LICENSEDIR}\"")
	message(STATUS "Config files:      \"${MUMBLE_INSTALL_ABS_SYSCONFDIR}\"")
	message(STATUS "Metadata files:    \"${MUMBLE_INSTALL_ABS_METADATADIR}\"")
	message(STATUS "Application files: \"${MUMBLE_INSTALL_ABS_APPLICATIONSDIR}\"")
	message(STATUS "Service files:     \"${MUMBLE_INSTALL_ABS_SERVICEFILEDIR}\"")
	message(STATUS "Sysusers files:    \"${MUMBLE_INSTALL_ABS_SYSUSERSDIR}\"")
	message(STATUS "Tmpfiles files:    \"${MUMBLE_INSTALL_ABS_TMPFILESDIR}\"")
	message(STATUS "")
endif()

