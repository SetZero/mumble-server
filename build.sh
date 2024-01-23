#!/usr/bin/env bash

set -e
set -x

cmake \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_NUMBER=$buildNumber \
	-Dclient=OFF \
	-Dserver=ON \
	-Dice=ON \
	-Dtests=ON \
	-Dwarnings-as-errors=OFF \
	-Dzeroconf=OFF \
	$MUMBLE_CMAKE_ARGS \
	..

cmake --build . -j $(nproc)

ctest --output-on-failure . -j $(nproc)
