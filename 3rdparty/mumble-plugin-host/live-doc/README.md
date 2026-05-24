# mumble-live-doc

Real-time collaborative document plugin for the Mumble server.
Implements `mumble_plugin_api::MumblePlugin` and serves a WebSocket
endpoint that brokers Yjs CRDT updates between clients editing the
same channel-scoped document.

## How it fits together

```
Mumble client (Tauri webview, browser Yjs)
       |
       |  fancy-live-doc/open  (PluginDataTransmission)
       v
Mumble C++ server  --[Rust plugin host FFI]-->  mumble-live-doc
       ^                                              |
       |  fancy-live-doc/invite (token, ws_url)       |
       +----------------------------------------------+
       |
       v
WebSocket (this plugin)  <-->  yrs::Doc per (server, channel, slug)
                                 |
                                 v
                               file-server plugin
                               `PUT /admin/documents/{name}`
                               (revisioned persistence on idle / teardown)
```

## Config

```ini
[plugin.live-doc]
enabled = true
host = 0.0.0.0
port = 64740
state_path = /var/lib/mumble/live-doc

# Optional - public origin clients should connect to.  Defaults to ws://<bind>.
public_url = wss://chat.example.com/live-doc

# Optional - 32-byte HMAC secret.  Random one is generated in memory
# if not supplied.  Provide a stable value across restarts to keep
# already-minted JWTs valid.
# jwt_secret = "hex or random string"

# Persistence bridge to the file-server plugin.  The admin token
# must match `[plugin.file-server].admin_token` exactly.  When unset,
# live docs start blank on every open and are never persisted.
file_server_url = "http://127.0.0.1:64739"
file_server_admin_token = "<shared secret>"

max_update_bytes = 4194304
snapshot_idle_secs = 60
teardown_grace_secs = 30
```

## Known follow-ups

1. **Revision history UI** in the client.  The file-server now stores
   every save as a numbered revision (`document_revisions` table) and
   `GET /admin/documents/{name}/revisions` returns the list.  The
   `LiveDocPanel` "History" button still alerts "coming soon" - wire
   it to fetch the listing and let the user restore a prior revision.

2. **Markdown body alongside the Yjs marker.**  Persistence currently
   stores only the binary CRDT state embedded in a markdown comment.
   When the client also flushes a rendered markdown body the file
   becomes human-readable from outside the app.

## Wire format

The WebSocket frames carry the standard `y-protocols` envelopes
(sync step 1 / sync step 2 / update / awareness query / awareness
update).  Browser Yjs + `y-websocket` interop is wire-for-wire
identical to this server's [`doc::DocRoom`].
