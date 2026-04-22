// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "GroupTable.h"
#include "ChannelTable.h"

#include "database/AccessException.h"
#include "database/Backend.h"
#include "database/Column.h"
#include "database/Constraint.h"
#include "database/DataType.h"
#include "database/Database.h"
#include "database/ForeignKey.h"
#include "database/FormatException.h"
#include "database/Index.h"
#include "database/MigrationException.h"
#include "database/PrimaryKey.h"
#include "database/TransactionHolder.h"
#include "database/Utils.h"

#include <soci/soci.h>

#include <cassert>
#include <exception>
#include <optional>

namespace mdb = ::mumble::db;

namespace mumble {
namespace server {
	namespace db {

		constexpr const char *GroupTable::NAME;
		constexpr const char *GroupTable::column::server_id;
		constexpr const char *GroupTable::column::group_id;
		constexpr const char *GroupTable::column::group_name;
		constexpr const char *GroupTable::column::channel_id;
		constexpr const char *GroupTable::column::inherit;
		constexpr const char *GroupTable::column::is_inheritable;
		constexpr const char *GroupTable::column::color;
		constexpr const char *GroupTable::column::icon;
		constexpr const char *GroupTable::column::style_preset;
		constexpr const char *GroupTable::column::metadata_json;


		GroupTable::GroupTable(soci::session &sql, ::mdb::Backend backend, const ChannelTable &channelTable)
			: ::mdb::Table(sql, backend, NAME) {
			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column groupIDCol(column::group_id, ::mdb::DataType(::mdb::DataType::Integer));
			groupIDCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column groupNameCol(column::group_name, ::mdb::DataType(::mdb::DataType::VarChar, 255));
			groupNameCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelIDCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelIDCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column inheritCol(column::inherit, ::mdb::DataType(::mdb::DataType::SmallInteger));
			inheritCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));
			inheritCol.setDefaultValue("1");

			::mdb::Column isInheritableCol(column::is_inheritable, ::mdb::DataType(::mdb::DataType::SmallInteger));
			isInheritableCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));
			isInheritableCol.setDefaultValue("1");

			// FancyMumble role customization columns. All nullable so that existing
			// groups remain valid without an explicit value.
			::mdb::Column colorCol(column::color, ::mdb::DataType(::mdb::DataType::Text));
			colorCol.setDefaultValue("NULL");

			::mdb::Column iconCol(column::icon, ::mdb::DataType(::mdb::DataType::Blob));
			iconCol.setDefaultValue("NULL");

			::mdb::Column stylePresetCol(column::style_preset, ::mdb::DataType(::mdb::DataType::Text));
			stylePresetCol.setDefaultValue("NULL");

			::mdb::Column metadataCol(column::metadata_json, ::mdb::DataType(::mdb::DataType::Text));
			metadataCol.setDefaultValue("NULL");


			setColumns({ serverCol, groupIDCol, groupNameCol, channelIDCol, inheritCol, isInheritableCol, colorCol,
						 iconCol, stylePresetCol, metadataCol });


			::mdb::PrimaryKey pk(std::vector< std::string >{ column::server_id, column::group_id });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(channelTable, { serverCol, channelIDCol });
			addForeignKey(fk);

			// Ensure group names are not duplicated within a given channel on a given server
			::mdb::Index ind(std::string(NAME) + "_unique_group_name_index",
							 { column::server_id, column::channel_id, column::group_name }, ::mdb::Index::UNIQUE);
			addIndex(ind, false);
		}

		unsigned int GroupTable::getFreeGroupID(unsigned int serverID) {
			try {
				int freeID;

				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << ::mdb::utils::getLowestUnoccupiedIDStatement(
					m_backend, NAME, column::group_id, { ::mdb::utils::ColAlias(column::server_id, "serverID") }),
					soci::use(serverID, "serverID"), soci::into(freeID);

				::mdb::utils::verifyQueryResultedInData(m_sql);

				transaction.commit();

				return static_cast< unsigned int >(freeID);
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at fetching free group ID for server with ID "
															  + std::to_string(serverID)));
			}
		}

		unsigned int GroupTable::addGroup(const DBGroup &group) {
			if (group.name.empty()) {
				throw ::mdb::FormatException("A group's name must not be empty");
			}

			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				short inherit      = group.inherit;
				short inheritable  = group.is_inheritable;
				long long group_id = 0;

				soci::indicator colorInd       = group.color.empty() ? soci::i_null : soci::i_ok;
				soci::indicator iconInd        = group.icon.empty() ? soci::i_null : soci::i_ok;
				soci::indicator stylePresetInd = group.style_preset.empty() ? soci::i_null : soci::i_ok;
				soci::indicator metadataInd    = group.metadata_json.empty() ? soci::i_null : soci::i_ok;

				soci::blob iconBlob(m_sql);
				if (iconInd == soci::i_ok) {
					iconBlob.write_from_start(reinterpret_cast< const char * >(group.icon.data()), group.icon.size());
				}

				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \"" << column::group_id
					  << "\", \"" << column::channel_id << "\", \"" << column::group_name << "\", \"" << column::inherit
					  << "\", \"" << column::is_inheritable << "\", \"" << column::color << "\", \"" << column::icon
					  << "\", \"" << column::style_preset << "\", \"" << column::metadata_json
					  << "\") VALUES (:serverID, :groupID, :channelID, :name, :inherit, :inheritable, :color, :icon, "
						 ":stylePreset, :metadata)",
					soci::use(group.serverID), soci::use(group.groupID), soci::use(group.channelID),
					soci::use(group.name), soci::use(inherit), soci::use(inheritable),
					soci::use(group.color, colorInd), soci::use(iconBlob, iconInd),
					soci::use(group.style_preset, stylePresetInd), soci::use(group.metadata_json, metadataInd),
					soci::into(group_id);

				transaction.commit();

				return static_cast< unsigned int >(group_id);
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at adding group for channel with ID "
																  + std::to_string(group.channelID) + " on server with ID "
																  + std::to_string(group.serverID)));
			}
		}

		void GroupTable::updateGroup(const DBGroup &group) {
			assert(groupExists(group));

			if (group.name.empty()) {
				throw ::mdb::FormatException("A group's name must not be empty");
			}

			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				short inhert      = group.inherit;
				short inheritable = group.is_inheritable;

				soci::indicator colorInd       = group.color.empty() ? soci::i_null : soci::i_ok;
				soci::indicator iconInd        = group.icon.empty() ? soci::i_null : soci::i_ok;
				soci::indicator stylePresetInd = group.style_preset.empty() ? soci::i_null : soci::i_ok;
				soci::indicator metadataInd    = group.metadata_json.empty() ? soci::i_null : soci::i_ok;

				soci::blob iconBlob(m_sql);
				if (iconInd == soci::i_ok) {
					iconBlob.write_from_start(reinterpret_cast< const char * >(group.icon.data()), group.icon.size());
				}

				m_sql << "UPDATE \"" << NAME << "\"SET \"" << column::group_name << "\" = :name, \""
					  << column::channel_id << "\" = :channelID, \"" << column::inherit << "\" = :inherit, \""
					  << column::is_inheritable << "\" = :inheritable, \"" << column::color << "\" = :color, \""
					  << column::icon << "\" = :icon, \"" << column::style_preset << "\" = :stylePreset, \""
					  << column::metadata_json << "\" = :metadata WHERE \"" << column::server_id
					  << "\" = :serverID AND \"" << column::group_id << "\" = :groupID",
					soci::use(group.name), soci::use(group.channelID), soci::use(inhert), soci::use(inheritable),
					soci::use(group.color, colorInd), soci::use(iconBlob, iconInd),
					soci::use(group.style_preset, stylePresetInd), soci::use(group.metadata_json, metadataInd),
					soci::use(group.serverID), soci::use(group.groupID);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at updating group with ID "
																  + std::to_string(group.groupID) + " on server with ID "
																  + std::to_string(group.serverID)));
			}
		}

		void GroupTable::removeGroup(const DBGroup &group) { removeGroup(group.serverID, group.groupID); }

		void GroupTable::removeGroup(unsigned int serverID, unsigned int groupID) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :serverID AND \""
					  << column::group_id << "\" = :groupID",
					soci::use(serverID), soci::use(groupID);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at updating group with ID "
															  + std::to_string(groupID) + " on server with ID "
															  + std::to_string(serverID)));
			}
		}

		bool GroupTable::groupExists(const DBGroup &group) { return groupExists(group.serverID, group.groupID); }

		bool GroupTable::groupExists(unsigned int serverID, unsigned int groupID) {
			try {
				int exists = false;

				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :serverID AND \""
					  << column::group_id << "\" = :groupID LIMIT 1",
					soci::use(serverID), soci::use(groupID), soci::into(exists);

				transaction.commit();

				return exists;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at checking of existence of group with ID "
															  + std::to_string(groupID) + " on server with ID "
															  + std::to_string(serverID)));
			}
		}

		DBGroup GroupTable::getGroup(unsigned int serverID, unsigned int groupID) {
			assert(groupExists(serverID, groupID));

			try {
				DBGroup group;
				group.serverID = serverID;
				group.groupID  = groupID;

				int inherit        = false;
				int is_inheritable = false;
				soci::indicator colorInd, iconInd, stylePresetInd, metadataInd;
				soci::blob iconBlob(m_sql);

				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "SELECT \"" << column::channel_id << "\", \"" << column::group_name << "\", \""
					  << column::inherit << "\", \"" << column::is_inheritable << "\", \"" << column::color << "\", \""
					  << column::icon << "\", \"" << column::style_preset << "\", \"" << column::metadata_json
					  << "\" FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :serverID AND \""
					  << column::group_id << "\" = :groupID",
					soci::into(group.channelID), soci::into(group.name), soci::into(inherit),
					soci::into(is_inheritable), soci::into(group.color, colorInd),
					soci::into(iconBlob, iconInd), soci::into(group.style_preset, stylePresetInd),
					soci::into(group.metadata_json, metadataInd), soci::use(serverID), soci::use(groupID);

				::mdb::utils::verifyQueryResultedInData(m_sql);

				transaction.commit();

				group.inherit        = inherit;
				group.is_inheritable = is_inheritable;
				if (colorInd == soci::i_null) {
					group.color.clear();
				}
				if (iconInd == soci::i_null) {
					group.icon.clear();
				} else {
					group.icon.resize(iconBlob.get_len());
					if (!group.icon.empty()) {
						iconBlob.read_from_start(reinterpret_cast< char * >(group.icon.data()), group.icon.size());
					}
				}
				if (stylePresetInd == soci::i_null) {
					group.style_preset.clear();
				}
				if (metadataInd == soci::i_null) {
					group.metadata_json.clear();
				}

				return group;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at getting details for group with ID "
																  + std::to_string(groupID) + " on server with ID "
																  + std::to_string(serverID)));
			}
		}

		void GroupTable::clearGroups(unsigned int serverID, unsigned int channelID) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :serverID AND \""
					  << column::channel_id << "\" = :channelID",
					soci::use(serverID), soci::use(channelID);

				transaction.commit();

			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at clearing groups for channel with ID "
															  + std::to_string(channelID) + " on server with ID "
															  + std::to_string(serverID)));
			}
		}

		std::optional< unsigned int > GroupTable::findGroupID(unsigned int serverID, const std::string &name) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				unsigned int groupID;

				m_sql << "SELECT \"" << column::group_id << "\" FROM \"" << NAME << "\" WHERE \"" << column::server_id
					  << "\" = :serverID AND \"" << column::group_name << "\" = :groupName",
					soci::use(serverID), soci::use(name), soci::into(groupID);

				transaction.commit();

				return m_sql.got_data() ? std::optional< unsigned int >(groupID) : std::nullopt;

			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at searching for group with name \"" + name
															  + "\" on server with ID " + std::to_string(serverID)));
			}
		}

		std::size_t GroupTable::countGroups(unsigned int serverID, unsigned int channelID) {
			try {
				long long nGroups = 0;

				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "SELECT COUNT(*) FROM (SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id
					  << "\" = :serverID AND \"" << column::channel_id << "\" = :channelID) AS dummy",
					soci::use(serverID), soci::use(channelID), soci::into(nGroups);

				::mdb::utils::verifyQueryResultedInData(m_sql);

				transaction.commit();

				return static_cast< std::size_t >(nGroups);
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at counting groups for channel with ID "
															  + std::to_string(channelID) + " on server with ID "
															  + std::to_string(serverID)));
			}
		}

		std::vector< DBGroup > GroupTable::getAllGroups(unsigned int serverID, unsigned int channelID) {
			try {
				std::vector< DBGroup > groups;

				::mdb::TransactionHolder transaction = ensureTransaction();

				int groupID        = 0;
				std::string name;
				int inherit        = 0;
				int is_inheritable = 0;
				std::string color;
				soci::blob iconBlob(m_sql);
				std::string stylePreset;
				std::string metadataJson;
				soci::indicator colorInd = soci::i_ok;
				soci::indicator iconInd  = soci::i_ok;
				soci::indicator styleInd = soci::i_ok;
				soci::indicator metaInd  = soci::i_ok;

				soci::statement stmt =
					(m_sql.prepare << "SELECT \"" << column::group_id << "\", \"" << column::group_name << "\", \""
								   << column::inherit << "\", \"" << column::is_inheritable << "\", \"" << column::color
								   << "\", \"" << column::icon << "\", \"" << column::style_preset << "\", \""
								   << column::metadata_json << "\" FROM \"" << NAME << "\" WHERE \""
								   << column::server_id << "\" = :serverID AND \"" << column::channel_id
								   << "\" = :channelID",
					 soci::use(serverID), soci::use(channelID), soci::into(groupID), soci::into(name),
					 soci::into(inherit), soci::into(is_inheritable), soci::into(color, colorInd),
					 soci::into(iconBlob, iconInd), soci::into(stylePreset, styleInd),
					 soci::into(metadataJson, metaInd));

				stmt.execute(false);

				while (stmt.fetch()) {
					DBGroup group;
					group.serverID       = serverID;
					group.channelID      = channelID;
					group.groupID        = static_cast< unsigned int >(groupID);
					group.name           = name;
					group.inherit        = inherit;
					group.is_inheritable = is_inheritable;
					group.color          = (colorInd == soci::i_null) ? std::string() : color;
					if (iconInd == soci::i_null) {
						group.icon.clear();
					} else {
						group.icon.resize(iconBlob.get_len());
						if (!group.icon.empty()) {
							iconBlob.read_from_start(reinterpret_cast< char * >(group.icon.data()),
													 group.icon.size());
						}
					}
					group.style_preset  = (styleInd == soci::i_null) ? std::string() : stylePreset;
					group.metadata_json = (metaInd == soci::i_null) ? std::string() : metadataJson;

					groups.push_back(std::move(group));
				}

				transaction.commit();

				return groups;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed at getting all groups for channel with ID " + std::to_string(channelID) + " on server with ID " + std::to_string(serverID))); } }

		void GroupTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			// Note: Always hard-code table and column names in this function in order to ensure that this
			// migration path always stays the same regardless of whether the respective named constants change.
			assert(fromSchemaVersion <= toSchemaVersion);

			try {
				if (fromSchemaVersion < 10) {
					// In v10 we renamed the columns "name" -> "group_name" and "inheritable" -> "is_inheritable"
					// -> Import all data from the old table into the new one. The four FancyMumble role columns
					// added in v18 are simply left at NULL for migrated rows.
					m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \"" << column::group_id
						  << "\", \"" << column::group_name << "\", \"" << column::channel_id << "\", \""
						  << column::inherit << "\", \"" << column::is_inheritable
						  << "\") SELECT \"server_id\", \"group_id\", \"name\", \"channel_id\", "
						  << ::mdb::utils::nonNullOf("\"inherit\"").otherwise("1") << ", "
						  << ::mdb::utils::nonNullOf("\"inheritable\"").otherwise("1") << " FROM \"groups"
						  << mdb::Database::OLD_TABLE_SUFFIX << "\"";
				} else if (fromSchemaVersion < 18) {
					// In v18 we added the FancyMumble role columns. Import all v17 columns from the old table
					// and let the new columns default to NULL.
					m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \"" << column::group_id
						  << "\", \"" << column::group_name << "\", \"" << column::channel_id << "\", \""
						  << column::inherit << "\", \"" << column::is_inheritable
						  << "\") SELECT \"server_id\", \"group_id\", \"group_name\", \"channel_id\", \"inherit\", "
						  << "\"is_inheritable\" FROM \"groups" << mdb::Database::OLD_TABLE_SUFFIX << "\"";
				} else {
					// Use default implementation to handle migration without change of format
					mdb::Table::migrate(fromSchemaVersion, toSchemaVersion);
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
