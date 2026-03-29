// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PCHAT_PROTOCOLHANDLERS_H_
#define MUMBLE_MURMUR_PCHAT_PROTOCOLHANDLERS_H_

#include "IPchatProtocolHandler.h"

namespace mumble {
namespace server {
	namespace db {
		class PChatMessageTable;
		class PChatMemberJoinTable;
	} // namespace db
} // namespace server
} // namespace mumble

namespace pchat {

struct IServerBridge;

/// Shared composition helper for protocols that store messages server-side.
///
/// Used by PostJoinProtocolHandler, FullArchiveProtocolHandler, and
/// ServerManagedProtocolHandler via composition (not inheritance).
class ServerSideStorage {
public:
	explicit ServerSideStorage(::mumble::server::db::PChatMessageTable &msgTable);

	/// Check for duplicates, handle replaces_id, and persist the message.
	StoreResult storeMessage(const MessageContext &ctx);

private:
	::mumble::server::db::PChatMessageTable &m_msgTable;
};

/// Handler for FANCY_V1_POST_JOIN protocol channels.
///
/// Stores messages server-side, filters fetches by member join time,
/// records joins, uses HMAC key challenge, fixed relay cap of 3.
class PostJoinProtocolHandler final : public IPchatProtocolHandler {
public:
	PostJoinProtocolHandler(::mumble::server::db::PChatMessageTable &msgTable,
							::mumble::server::db::PChatMemberJoinTable &joinTable);

	std::string_view protocolName() const override;
	bool storesMessages() const override;
	bool recordsJoin() const override;
	bool autoVerifiesOnReport() const override;
	unsigned int computeRelayCap(unsigned int onlineMembers) const override;
	MumbleProto::PchatProtocol keyRequestProtocol() const override;
	StoreResult handleMessageStore(const MessageContext &ctx) override;
	FetchResult handleFetch(const FetchContext &ctx) override;

private:
	ServerSideStorage m_storage;
	::mumble::server::db::PChatMemberJoinTable &m_joinTable;
};

/// Handler for FANCY_V1_FULL_ARCHIVE protocol channels.
///
/// Stores messages server-side, no join-time filtering on fetch,
/// no join records, uses HMAC key challenge, dynamically computed relay cap.
class FullArchiveProtocolHandler final : public IPchatProtocolHandler {
public:
	explicit FullArchiveProtocolHandler(::mumble::server::db::PChatMessageTable &msgTable);

	std::string_view protocolName() const override;
	bool storesMessages() const override;
	bool recordsJoin() const override;
	bool autoVerifiesOnReport() const override;
	unsigned int computeRelayCap(unsigned int onlineMembers) const override;
	MumbleProto::PchatProtocol keyRequestProtocol() const override;
	StoreResult handleMessageStore(const MessageContext &ctx) override;
	FetchResult handleFetch(const FetchContext &ctx) override;

private:
	ServerSideStorage m_storage;
};

/// Handler for SERVER_MANAGED protocol channels.
///
/// Same storage behavior as FullArchive.
class ServerManagedProtocolHandler final : public IPchatProtocolHandler {
public:
	explicit ServerManagedProtocolHandler(::mumble::server::db::PChatMessageTable &msgTable);

	std::string_view protocolName() const override;
	bool storesMessages() const override;
	bool recordsJoin() const override;
	bool autoVerifiesOnReport() const override;
	unsigned int computeRelayCap(unsigned int onlineMembers) const override;
	MumbleProto::PchatProtocol keyRequestProtocol() const override;
	StoreResult handleMessageStore(const MessageContext &ctx) override;
	FetchResult handleFetch(const FetchContext &ctx) override;

private:
	ServerSideStorage m_storage;
};

/// Handler for SIGNAL_V1 protocol channels.
///
/// No server-side message storage (relay-only), returns empty fetch responses,
/// records joins, auto-verifies on key holder report, fixed relay cap of 3.
class SignalV1ProtocolHandler final : public IPchatProtocolHandler {
public:
	explicit SignalV1ProtocolHandler(IServerBridge &bridge);

	std::string_view protocolName() const override;
	bool storesMessages() const override;
	bool recordsJoin() const override;
	bool autoVerifiesOnReport() const override;
	unsigned int computeRelayCap(unsigned int onlineMembers) const override;
	MumbleProto::PchatProtocol keyRequestProtocol() const override;
	StoreResult handleMessageStore(const MessageContext &ctx) override;
	FetchResult handleFetch(const FetchContext &ctx) override;

private:
	IServerBridge &m_bridge;
};

} // namespace pchat

#endif // MUMBLE_MURMUR_PCHAT_PROTOCOLHANDLERS_H_
