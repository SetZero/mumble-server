# Copyright The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.

add_executable(TestPersistentChatManager TestPersistentChatManager.cpp)

set_target_properties(TestPersistentChatManager PROPERTIES AUTOMOC ON)

target_link_libraries(TestPersistentChatManager PRIVATE mumble_server_object_lib shared Qt6::Test)

add_test(NAME TestPersistentChatManager COMMAND $<TARGET_FILE:TestPersistentChatManager>)
