// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MUMBLEDEPRECATION_H_
#define MUMBLE_MUMBLEDEPRECATION_H_

// Some protobuf fields are intentionally marked `[deprecated = true]` in
// Mumble.proto because Fancy Mumble supersedes them (ChannelState.can_enter /
// .is_enter_restricted / .temporary -> the `attributes` field;
// PluginDataTransmission -> PluginMessage). The server and desktop client must
// still read/write those fields for backward compatibility with legacy clients,
// which - under -Werror - would fail on the resulting self-inflicted deprecation
// warning (GCC/Clang: -Wdeprecated-declarations, MSVC: C4996).
//
// Wrap ONLY the deliberate legacy-compatibility accesses so the deprecation
// marker (and its warning at every other, non-compat use site) stays intact:
//
//     MUMBLE_DEPRECATED_PUSH
//     mpcs.set_can_enter(uSource->hasPermission(chan, ChanACL::Enter));
//     MUMBLE_DEPRECATED_POP
//
// The macros expand to compiler-appropriate diagnostic push/pop pairs and are
// no-ops on unknown compilers.

#if defined(_MSC_VER)
#	define MUMBLE_DEPRECATED_PUSH __pragma(warning(push)) __pragma(warning(disable : 4996))
#	define MUMBLE_DEPRECATED_POP __pragma(warning(pop))
#elif defined(__clang__)
#	define MUMBLE_DEPRECATED_PUSH \
		_Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
#	define MUMBLE_DEPRECATED_POP _Pragma("clang diagnostic pop")
#elif defined(__GNUC__)
#	define MUMBLE_DEPRECATED_PUSH \
		_Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#	define MUMBLE_DEPRECATED_POP _Pragma("GCC diagnostic pop")
#else
#	define MUMBLE_DEPRECATED_PUSH
#	define MUMBLE_DEPRECATED_POP
#endif

#endif // MUMBLE_MUMBLEDEPRECATION_H_
