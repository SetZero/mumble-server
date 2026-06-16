// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "UserStateSerializer.h"

#include "Channel.h"
#include "ChannelListenerManager.h"
#include "QtUtils.h"
#include "ServerUser.h"
#include "VolumeAdjustment.h"

#include "Mumble.pb.h"

// Each helper populates one cohesive slice of a UserState, so serializeUserState
// below reads as a checklist of "what describes a user" rather than one long
// ladder of conditionals.

// Stable identity: the minimum a recipient needs to bind a session to a person.
static void fillIdentity(MumbleProto::UserState &mpus, const ServerUser &u) {
	mpus.set_session(u.uiSession);
	mpus.set_name(u8(u.qsName));
	if (u.iId >= 0) {
		mpus.set_user_id(static_cast< unsigned int >(u.iId));
	}
	if (!u.qsHash.isEmpty()) {
		mpus.set_hash(u8(u.qsHash));
	}
}

// Avatar: prefer the hash for modern clients, fall back to the inline blob.
static void fillTexture(MumbleProto::UserState &mpus, const ServerUser &u, bool hashedBlobs) {
	if (hashedBlobs && !u.qbaTextureHash.isEmpty()) {
		mpus.set_texture_hash(blob(u.qbaTextureHash));
	} else if (!u.qbaTexture.isEmpty()) {
		mpus.set_texture(blob(u.qbaTexture));
	}
}

// Comment: same hash-vs-inline rule as the avatar.
static void fillComment(MumbleProto::UserState &mpus, const ServerUser &u, bool hashedBlobs) {
	if (hashedBlobs && !u.qbaCommentHash.isEmpty()) {
		mpus.set_comment_hash(blob(u.qbaCommentHash));
	} else if (!u.qsComment.isEmpty()) {
		mpus.set_comment(u8(u.qsComment));
	}
}

// Live state flags. deaf implies mute and self-deaf implies self-mute, so each
// pair sends only the stronger flag; the rest are independent.
static void fillStateFlags(MumbleProto::UserState &mpus, const ServerUser &u) {
	if (u.bDeaf) {
		mpus.set_deaf(true);
	} else if (u.bMute) {
		mpus.set_mute(true);
	}

	if (u.bSelfDeaf) {
		mpus.set_self_deaf(true);
	} else if (u.bSelfMute) {
		mpus.set_self_mute(true);
	}

	if (u.bSuppress) {
		mpus.set_suppress(true);
	}
	if (u.bPrioritySpeaker) {
		mpus.set_priority_speaker(true);
	}
	if (u.bRecording) {
		mpus.set_recording(true);
	}
}

// Channels the user is listening to (without being in them), with per-channel
// volume only when the server broadcasts those adjustments.
static void fillListeners(MumbleProto::UserState &mpus, const ServerUser &u, const ChannelListenerManager &listeners,
						  bool withVolume) {
	for (unsigned int channelID : listeners.getListenedChannelsForUser(u.uiSession)) {
		mpus.add_listening_channel_add(channelID);
		if (withVolume) {
			const VolumeAdjustment volume = listeners.getListenerVolumeAdjustment(u.uiSession, channelID);
			auto *adjustment              = mpus.add_listening_volume_adjustment();
			adjustment->set_listening_channel(channelID);
			adjustment->set_volume_adjustment(volume.factor);
		}
	}
}

void serializeUserState(MumbleProto::UserState &mpus, const ServerUser &user, const ServerUser &recipient,
						const ChannelListenerManager &listeners, bool includeListenerVolume) {
	const bool hashedBlobs = recipient.usesBlobHashes();

	fillIdentity(mpus, user);
	fillTexture(mpus, user, hashedBlobs);
	fillComment(mpus, user, hashedBlobs);
	fillStateFlags(mpus, user);
	fillListeners(mpus, user, listeners, includeListenerVolume);

	if (user.cChannel->iId != 0) {
		mpus.set_channel_id(user.cChannel->iId);
	}

	if (user.isFancyClient()) {
		mpus.add_client_features(MumbleProto::UserState::FEATURE_PCHAT_E2EE);
	}
}
