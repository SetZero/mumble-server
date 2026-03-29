// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "ChannelPropertyTable.h"
#include "ChannelTable.h"

#include "database/AccessException.h"
#include "database/Column.h"
#include "database/Constraint.h"
#include "database/DataType.h"
#include "database/Database.h"
#include "database/ForeignKey.h"
#include "database/MigrationException.h"
#include "database/PrimaryKey.h"
#include "database/TransactionHolder.h"
#include "database/Utils.h"

#include <soci/soci.h>

#include <cassert>
#include <exception>

namespace mdb = ::mumble::db;

namespace mumble {
namespace server {
	namespace db {

		constexpr const char *ChannelPropertyTable::NAME;
		constexpr const char *ChannelPropertyTable::column::server_id;
		constexpr const char *ChannelPropertyTable::column::channel_id;
		constexpr const char *ChannelPropertyTable::column::key;
		constexpr const char *ChannelPropertyTable::column::value;


		ChannelPropertyTable::ChannelPropertyTable(soci::session &sql, ::mdb::Backend backend,
												   const ChannelTable &channelTable)
			: ::mdb::Table(sql, backend, NAME) {
			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column keyCol(column::key, ::mdb::DataType(::mdb::DataType::Integer));
			keyCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column valueCol(column::value, ::mdb::DataType(::mdb::DataType::Text));
			valueCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));


			setColumns({ serverCol, channelCol, keyCol, valueCol });


			::mdb::PrimaryKey pk({ column::server_id, column::channel_id, column::key });
			setPrimaryKey(pk);


			::mdb::ForeignKey fk(channelTable, { serverCol, channelCol });
			addForeignKey(fk);
		}

		std::string ChannelPropertyTable::doGetProperty(unsigned int serverID, unsigned int channelID,
														ChannelProperty property) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::string val;

				int intProp = static_cast< int >(property);

				m_sql << "SELECT \"" << column::value << "\" FROM \"" << NAME << "\" WHERE \"" << column::server_id
					  << "\" = :serverID AND \"" << column::channel_id << "\" = :channelID AND \"" << column::key
					  << "\" = :key",
					soci::into(val), soci::use(serverID), soci::use(channelID), soci::use(intProp);

				::mdb::utils::verifyQueryResultedInData(m_sql);

				transaction.commit();

				return val;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException(
					"Failed at fetching property " + std::to_string(static_cast< int >(property))
					+ " for channel with ID " + std::to_string(channelID) + " on server " + std::to_string(serverID)));
			}
		}

		bool ChannelPropertyTable::isPropertySet(unsigned int serverID, unsigned int channelID,
												 ChannelProperty property) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int intProp = static_cast< int >(property);
				int exists  = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :serverID AND \""
					  << column::channel_id << "\" = :channelID AND \"" << column::key << "\" = :key",
					soci::into(exists), soci::use(serverID), soci::use(channelID), soci::use(intProp);

				transaction.commit();

				return exists;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException(
					"Failed at checking whether property " + std::to_string(static_cast< int >(property))
					+ " is set for channel with ID " + std::to_string(channelID) + " on server "
					+ std::to_string(serverID)));
			}
		}

		void ChannelPropertyTable::setProperty(unsigned int serverID, unsigned int channelID, ChannelProperty property,
											   const std::string &value) {
			bool propertyAlreadySet = isPropertySet(serverID, channelID, property);
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int intProp = static_cast< int >(property);

				if (propertyAlreadySet) {
					m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::value << "\" = :value WHERE \""
						  << column::server_id << "\" = :serverID AND \"" << column::channel_id
						  << "\" = :channelID AND \"" << column::key << "\" = :key",
						soci::use(value), soci::use(serverID), soci::use(channelID), soci::use(intProp);
				} else {
					m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \"" << column::channel_id
						  << "\", \"" << column::key << "\", \"" << column::value
						  << "\") VALUES (:serverID, :channelID, :key, :value)",
						soci::use(serverID), soci::use(channelID), soci::use(intProp), soci::use(value);
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException(
					"Failed at setting or updating property " + std::to_string(static_cast< int >(property))
					+ " for channel with ID " + std::to_string(channelID) + " on server " + std::to_string(serverID)));
			}
		}

		void ChannelPropertyTable::clearProperty(unsigned int serverID, unsigned int channelID,
												 ChannelProperty property) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int intProp = static_cast< int >(property);

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :serverID AND \""
					  << column::channel_id << "\" = :channelID AND \"" << column::key << "\" = :key",
					soci::use(serverID), soci::use(channelID), soci::use(intProp);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException(
					"Failed at clearing property " + std::to_string(static_cast< int >(property))
					+ " for channel with ID " + std::to_string(channelID) + " on server " + std::to_string(serverID)));
			}
		}

		void ChannelPropertyTable::clearAllProperties(unsigned int serverID, unsigned int channelID) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :serverID AND \""
					  << column::channel_id << "\" = :channelID",
					soci::use(serverID), soci::use(channelID);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at clearing all properties for channel with ID "
															  + std::to_string(channelID) + " on server "
															  + std::to_string(serverID)));
			}
		}

		void ChannelPropertyTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			// Note: Always hard-code old table and column names in this function in order to ensure that this
			// migration path always stays the same regardless of whether the respective named constants change.
			assert(fromSchemaVersion <= toSchemaVersion);

			try {
				if (fromSchemaVersion < 10) {
					// In v10 we renamed this table from "channel_info" to "channel_properties"
					// -> Import all data from the old table into the new one
					// Filter out rows with NULL value since the new schema has a NOT NULL constraint.
					m_sql << "INSERT INTO \"" << getName() << "\" (\"" << column::server_id << "\", \""
						  << column::channel_id << "\", \"" << column::key << "\", \"" << column::value
						  << "\") SELECT \"server_id\", \"channel_id\", \"key\", value FROM \"channel_info"
						  << mdb::Database::OLD_TABLE_SUFFIX << "\" WHERE value IS NOT NULL";
				} else {
					// Use default implementation to handle migration without change of format
					mdb::Table::migrate(fromSchemaVersion, toSchemaVersion);
				}

				if (fromSchemaVersion < 14) {
					// v14: PchatPersistenceMode was unified into PchatProtocol with shifted
					// enum values.  The old enum was:
					//   PCHAT_MODE_POST_JOIN    = 0
					//   PCHAT_MODE_FULL_ARCHIVE = 1
					// The new enum is:
					//   PCHAT_PROTOCOL_NONE               = 0
					//   PCHAT_PROTOCOL_FANCY_V1_POST_JOIN  = 1
					//   PCHAT_PROTOCOL_FANCY_V1_FULL_ARCHIVE = 2
					//   PCHAT_PROTOCOL_SERVER_MANAGED      = 3
					//
					// Remap stored integer values: old 1 -> new 2, then old 0 -> new 1.
					// Order matters to avoid double-remapping.
					// Property key 3 = ChannelProperty::PChatProtocol.
					m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::value
						  << "\" = '2' WHERE \"" << column::key << "\" = 3 AND \""
						  << column::value << "\" = '1'";
					m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::value
						  << "\" = '1' WHERE \"" << column::key << "\" = 3 AND \""
						  << column::value << "\" = '0'";
				}
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::MigrationException(
					std::string("Failed at migrating table \"") + NAME + "\" from schema version "
					+ std::to_string(fromSchemaVersion) + " to " + std::to_string(toSchemaVersion)));
			}
		}

	} // namespace db
} // namespace server
} // namespace mumble
