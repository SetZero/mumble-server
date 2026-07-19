#!/usr/bin/env bash

set -e
set -x

os=$1
build_type=$2
arch=$3

# Turn variables into lowercase
os="${os,,}"
# only consider name up to the hyphen
os=$(echo "$os" | sed 's/-.*//')
build_type="${build_type,,}"
arch="${arch,,}"


OS_SPECIFIC_CMAKE_OPTIONS=""

case "$os" in
	"ubuntu")
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-sqlite-tests=ON"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-mysql-tests=ON"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-postgresql-tests=ON"
		;;
	"windows")
		if ! [[ "$arch" = "x86_64" ]]; then
			echo "Unsupported architecture '$arch'"
			exit 1
		fi

		eval "$( "C:/vcvars-bash/vcvarsall.sh" x64 )"

		PATH="$PATH:/C/WixSharp"
		echo "PATH=$PATH" >> "$GITHUB_ENV"

		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -DCMAKE_C_COMPILER=cl"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -DCMAKE_CXX_COMPILER=cl"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-sqlite-tests=ON"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-mysql-tests=ON"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-postgresql-tests=OFF"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Dpackaging=ON"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Dasio=ON"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Dg15=ON"

		if [[ "$MUMBLE_SKIP_MSI_REBUILD" = "ON" ]]; then
			OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Dskip-msi-rebuild=ON"
		fi

		if [[ -n "$MUMBLE_USE_ELEVATION" ]]; then
			OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Delevation=ON"
		fi
		;;
	"macos")
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-sqlite-tests=ON"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-mysql-tests=OFF"
		OS_SPECIFIC_CMAKE_OPTIONS="$OS_SPECIFIC_CMAKE_OPTIONS -Ddatabase-postgresql-tests=ON"
		OS_SPECIFIC_CMAKE_OPTIONS="-DCMAKE_OSX_ARCHITECTURES=$arch"
		;;
	*)
		echo "OS $os is not supported"
		exit 1
		;;
esac


# --- Build the mumble-plugin-host Rust cdylib -----------------------------
# The server links against libmumble_plugin_host (src/murmur/CMakeLists.txt
# discovers it via find_library). It is built out-of-tree, so build it before
# configuring CMake or the mumble-server link fails with undefined
# plugin_host_* references. Only the host crate is a link-time dependency; the
# plugin cdylibs (file-server, calendar, ...) are loaded at runtime and are not
# needed here. This runs after the OS case block so the Windows MSVC toolchain
# (from vcvarsall) is available for the cargo build.
pluginHostDir="${GITHUB_WORKSPACE}/3rdparty/mumble-plugin-host"
( cd "$pluginHostDir" && cargo build --release -p mumble-plugin-host )
if [[ "$os" = "windows" ]]; then
	# On MSVC find_library() wants mumble_plugin_host.lib, but cargo emits the
	# import lib as mumble_plugin_host.dll.lib; drop a correctly named copy where
	# CMake looks. (ELF/Mach-O builds are found directly in target/release.)
	mkdir -p "$pluginHostDir/lib"
	cp "$pluginHostDir/target/release/mumble_plugin_host.dll" "$pluginHostDir/lib/"
	cp "$pluginHostDir/target/release/mumble_plugin_host.dll.lib" \
		"$pluginHostDir/lib/mumble_plugin_host.lib" 2>/dev/null \
		|| cp "$pluginHostDir/target/release/mumble_plugin_host.lib" "$pluginHostDir/lib/"
fi

buildDir="${GITHUB_WORKSPACE}/build"

mkdir -p "$buildDir"

cd "$buildDir"

# Run cmake with all necessary options
cmake -G Ninja \
	  -S "$GITHUB_WORKSPACE" \
	  -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
	  -DBUILD_NUMBER=$MUMBLE_BUILD_NUMBER \
	  $OS_SPECIFIC_CMAKE_OPTIONS \
	  $CMAKE_OPTIONS \
      -DCMAKE_UNITY_BUILD=ON \
	  -Ddisplay-install-paths=ON \
	  $ADDITIONAL_CMAKE_OPTIONS \
	  $VCPKG_CMAKE_OPTIONS

# Actually build
cmake --build . --config $BUILD_TYPE

