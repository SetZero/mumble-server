// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_USERSTATESERIALIZER_H_
#define MUMBLE_MURMUR_USERSTATESERIALIZER_H_

namespace MumbleProto {
class UserState;
}

class ServerUser;
class ChannelListenerManager;

/// Serialises a user into a *full* UserState protobuf - the complete snapshot
/// used to (re)announce a user to a client, mirroring the per-user announce in
/// Server::msgAuthenticate.
///
/// Lives in its own unit rather than on the Server class: building wire state
/// from a user is a single, self-contained responsibility, and pulling it out
/// keeps it from accreting onto an already overgrown Server. It depends only on
/// the data it actually needs (the two users and the listener registry) - never
/// on Server itself.
///
/// @param mpus                  Message to populate; existing fields are left as-is.
/// @param user                  The user being described.
/// @param recipient             The user that will receive the message; its
///                              negotiated protocol selects hashed vs. inline
///                              avatar/comment blobs.
/// @param listeners             Channel-listener registry (the user's listens).
/// @param includeListenerVolume Whether to attach per-listen volume adjustments.
void serializeUserState(MumbleProto::UserState &mpus, const ServerUser &user, const ServerUser &recipient,
						const ChannelListenerManager &listeners, bool includeListenerVolume);

#endif // MUMBLE_MURMUR_USERSTATESERIALIZER_H_
