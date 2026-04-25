# Mumble-server C++ integration scaffolding

These files are the C++ glue that the upstream `mumble-server` repo needs
in order to load `mumble-plugin-host.dll/.so/.dylib` and forward server
events into Rust plugins (currently the file-server plugin).

## Files

| File | Drop into |
|------|-----------|
| `PluginHostManager.h` | `mumble-server/src/murmur/PluginHostManager.h` |
| `PluginHostManager.cpp` | `mumble-server/src/murmur/PluginHostManager.cpp` |

The generated C header `mumble_plugin_host.h` (built by cbindgen and
written to [crates/mumble-plugin-host/include/mumble_plugin_host.h](../include/mumble_plugin_host.h))
must also be installed where the C++ build can find it
(e.g. `mumble-server/3rdparty/mumble-plugin-host/include/`).

## CMake integration sketch

```cmake
# In mumble-server/src/murmur/CMakeLists.txt:

option(USE_PLUGIN_HOST "Enable Rust plugin host" ON)

if(USE_PLUGIN_HOST)
    target_sources(mumble-server PRIVATE
        PluginHostManager.cpp
        PluginHostManager.h
    )
    target_compile_definitions(mumble-server PRIVATE USE_PLUGIN_HOST)

    # Link against the prebuilt Rust cdylib.
    set(PLUGIN_HOST_DIR "${CMAKE_SOURCE_DIR}/3rdparty/mumble-plugin-host"
        CACHE PATH "Location of mumble-plugin-host cdylib + header")
    target_include_directories(mumble-server PRIVATE
        "${PLUGIN_HOST_DIR}/include")

    if(WIN32)
        target_link_libraries(mumble-server PRIVATE
            "${PLUGIN_HOST_DIR}/lib/mumble_plugin_host.dll.lib")
    elseif(APPLE)
        target_link_libraries(mumble-server PRIVATE
            "${PLUGIN_HOST_DIR}/lib/libmumble_plugin_host.dylib")
    else()
        target_link_libraries(mumble-server PRIVATE
            "${PLUGIN_HOST_DIR}/lib/libmumble_plugin_host.so")
    endif()
endif()
```

## Hooking into Server.cpp

```cpp
// Server constructor:
#ifdef USE_PLUGIN_HOST
    m_pluginHost = std::make_unique<PluginHostManager>(this);
#endif

// In Server::userEnterChannel or wherever clients are confirmed connected
// after auth (typically Server::msgAuthenticate end):
#ifdef USE_PLUGIN_HOST
    if (m_pluginHost) {
        m_pluginHost->onClientConnected(uSource->uiSession,
                                        uSource->qsName,
                                        uSource->qsHash);
    }
#endif

// In Server::removeUser():
#ifdef USE_PLUGIN_HOST
    if (m_pluginHost) {
        m_pluginHost->onClientDisconnected(u->uiSession);
    }
#endif

// In Server::msgPluginDataTransmission() (NEW handler – currently
// PluginDataTransmission is unimplemented server-side):
#ifdef USE_PLUGIN_HOST
    if (m_pluginHost) {
        m_pluginHost->onPluginData(uSource->uiSession,
                                   QString::fromStdString(msg.dataid()),
                                   QByteArray(msg.data().data(),
                                              static_cast<int>(msg.data().size())));
    }
#endif
    // Also forward the message to receiver_sessions per Mumble protocol
    // (existing client-to-client routing).
```

## Configuration (murmur.ini)

```ini
[plugin.file-server]
enabled = true
port = 64739
base_url = https://files.example.com
max_file_size_bytes = 268435456     ; 256 MiB
max_total_storage_bytes = 10737418240 ; 10 GiB hard cap
storage_path = /var/lib/murmur/files
delete_on_ttl = true
ttl_seconds = 86400
delete_on_download = false
delete_on_disconnect = false
```

`Server::getConf("plugin.file-server.<key>", default)` reads these into
the host via the `get_config` callback.
