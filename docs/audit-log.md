# Audit Log & Moderation Signals - Design

Status: draft / design
Tracks: [FancyMumble#45 "Audit log"](https://github.com/Fancy-Mumble/FancyMumble/issues/45),
[FancyMumble discussion #94 "Tracking events"](https://github.com/Fancy-Mumble/FancyMumble/discussions/94)

This document works out two related asks:

1. **Audit log** (#45) - a searchable log of admin and moderator actions,
   authored and stored by the server.
2. **Moderation signals** (#94) - the client reporting user-level events (who
   mutes whom, blocks, reports) back to the server so community operators can
   spot problematic users.

They are related but **not** the same thing, and the difference matters. (1) is
a record of *authoritative* actions the server already performs and can vouch
for. (2) asks the server to collect *client-side, subjective* behaviour - which
is useful, but is surveillance-shaped and needs guardrails. This doc keeps them
as two subsystems that share storage and a query surface, but have very
different trust and privacy properties.

### Decisions (this revision)

- **Built as a plugin** on `mumble-plugin-host`, not baked into the C++ core.
  To feed it, the host gains a **server-event stream** on the plugin bridge
  (§7.10). That is the real leverage: once moderation/lifecycle events are on
  the bridge, *every* plugin can subscribe to them, not just the audit plugin.
- **This is an admin/operator audit.** No end-user disclosure is required;
  there is an *optional* switch for admins who want to tell their users (§6.4).
- **Git-style hash chain** for the record (§7.1) - decided, not a "maybe".
- **Telemetry is OpenTelemetry (OTLP)** - the single chosen export path, and it
  is enable/disable-able (§8).
- **Two new permissions: `ViewAudit` and `ConfigureAudit`** (§9).
- **Fine-grained, per-part toggles.** Every audit category, every signal, and
  every telemetry stream is individually switchable by an admin holding
  `ConfigureAudit`, so one operator can collect mute telemetry and another not
  (§9.2). Plugin-initiated destructive/invasive actions are captured too (§7.10).
- **Admin page with dual-mode search** (§10): a config half and a dashboard/
  viewer half, searchable both by point-and-click filters and by a SQL-like
  query language - parsed with **`sqlparser`** behind a deny-by-default AST
  whitelist that lowers to the same gated query as the filter builder (§10.3).
- **The event stream is a durable, Kafka-like log** (§7.10): append-only,
  offset-addressed, per-consumer offsets, at-least-once with replay - so no
  event is lost because a plugin was busy or restarting.
- **Every privileged plugin callback emits**; what gets *recorded* is a toggle,
  not an emit-time filter (§7.10, §9.2).
- **Toggles stop the future, never rewrite the past** (§9.2): switching a part
  off halts new entries but deletes nothing, deletion is a separate audited
  action, and the toggle change is itself an audit entry - so disabling the
  watcher is the first thing the log shows.
- **Permissions ride on ACL today, behind an `AuditAuthz` seam** (§9.1) so the
  model can be replaced later without touching call sites.
- **Retention is configurable per part** with a 30-day default and a shipped
  reference policy (§7.9) - and it is constrained, because it is the one
  legitimate deletion path: a hard 30-day floor on `audit.*`, lowering is never
  retroactive (expiry is stamped at write time), and every retention change is
  itself audited. An admin cannot shorten their way out of the record.
- **Full-text search goes through a per-backend strategy** (§4): FTS5 / tsvector
  / `FULLTEXT`, with a `LIKE` fallback, chosen from live capabilities.
- **Advanced SQL mode gets the full surface** - joins, unions, CTEs, aggregates
  - made safe by moving the boundary into the database: read-only,
  view-scoped, engine-enforced (grants on PG/MySQL, an authorizer on SQLite),
  with resource guards and every query audited. **On by default**, but it
  self-tests the sandbox at startup and refuses to enable if the boundary
  isn't provably in place (§10.4).

---

## 1. Goals and non-goals

**Goals**

- A durable, structured, **searchable** record of moderation-relevant actions on
  a virtual server.
- Answer "who did what to whom, when, and why" for bans, kicks, mutes, ACL
  changes, registrations, channel lifecycle, plugin administration and pchat
  moderation.
- Give operators an opt-in way to surface *client-side* signals (mutes/blocks/
  reports) as **advisory flags** for human moderators.
- Fit the existing architecture: soci-backed DB tables with migrations, the
  `MUMBLE_ALL_TCP_MESSAGES` wire dispatch, and the `Write`-on-root admin gate.

**Non-goals**

- **Automated punishment.** Signals raise flags for humans; the server never
  auto-bans from telemetry. (See §7.)
- Replacing the existing free-text `server_logs` (`LogTable`). The audit log is
  a *structured* companion, not a reformat of the operational log.
- Cross-server / global reputation. Everything is scoped to one virtual server.

---

## 2. Design principles

1. **Authoritative vs. reported.** Every stored event carries a `source`
   (`server`, `client`, `plugin`). Server-sourced events are facts the server
   mediated; client-sourced events are *claims*. The UI must render them
   differently and never conflate a subjective mute with a moderator action.
2. **Advisory, not punitive.** Signals feed a moderator's judgement. No
   thresholds trigger a ban/kick on their own.
3. **Consent and transparency for client data.** Reporting client-side
   behaviour is **off by default**, enabled per server by the operator, and
   visible to users when active (the client shows it; see §6.4). A community
   that collects mute data should have to say so.
4. **Aggregate before you individualize.** The default for signals is *counts*
   ("N distinct users muted X in the last 30 days"), not the raw who→whom
   edge list. Raw pairs are a separate, higher-privilege, higher-retention-cost
   option.
5. **Least privilege.** Viewing/searching the audit log and (especially) signal
   data is gated behind an explicit permission, not merely "is registered".
6. **Tamper-evidence.** The audit trail is append-only and hash-chained so a
   rogue admin can't silently delete or edit entries without detection (§7.1).
7. **Bounded.** Retention, row caps and rate limits are configured, so the table
   can't grow without limit or be used as a DoS amplifier.

---

## 3. What gets audited (server-authoritative)

The moderation surface already lives in a handful of `Server::msg*` handlers.
Each becomes a call site for a single `AuditLog::record(...)` sink.

| Action category      | Source handler (`src/murmur/Messages.cpp`)        | Captured detail |
|----------------------|---------------------------------------------------|-----------------|
| Kick / ban           | `msgUserRemove` (`:1514`)                          | target, reason, ban vs kick, ban duration |
| Ban-list edit        | `msgBanList` (`:892`)                              | added/removed CIDR + reason + expiry |
| Server mute/deafen/suppress/priority-speaker | `msgUserState` (`:994`)          | which flag, on/off, target, channel |
| Forced move          | `msgUserState` (`:994`)                            | from-channel → to-channel, target |
| ACL / group change   | `msgACL` (`:2437`)                                 | channel, diff of ACL rows and groups |
| Channel create/remove/rename | `msgChannelState` / `msgChannelRemove`    | channel id, name, parent, temporary flag |
| User (de)registration| registration paths + `FancyAccount*` (154–156)    | target user id, by whom |
| Server config change | `msgFancyServerSettingsUpdate` (153)              | key, old→new (secrets redacted) |
| Plugin administration| `msgFancyPluginAdmin*` (146–151)                  | install/uninstall/enable/disable + plugin name |
| Persistent-chat moderation | `PersistentChatManager` (delete/pin/rate-limit) | channel, message id, actor |
| Recording / listener changes | `msgUserState` recording/listen flags     | target, on/off |
| SuperUser / elevated login | authentication paths                        | session, cert hash, elevated? |

Every record is `{ actor, action, target?, channel?, reason?, before/after? }`
plus timestamps and identity snapshots (see §4). The `AuditLog::record` sink
also writes a one-line human summary into the existing `server_logs` for
operators who only read the flat log.

**Reason capture.** Bans and kicks should *prompt* for a reason. `UserRemove`
already carries a `reason` field; the client should surface a required text box
for destructive actions, and the server stores whatever arrives (empty allowed,
but flagged in the UI as "no reason given").

---

## 4. Data model

A new structured table, modelled on `LogTable` (`src/murmur/database/`) but
indexed for search. Name: `server_audit`.

```
AuditEvent
  id             INTEGER PK (monotonic per server)
  server_id      INTEGER            -- virtual server
  ts             INTEGER            -- unix millis, server clock
  source         TEXT               -- 'server' | 'client' | 'plugin'
  category       TEXT               -- 'ban','kick','mute','acl','channel',
                                     --   'register','config','plugin','pchat',
                                     --   'signal.mute','signal.block',
                                     --   'signal.report', ...
  severity       TEXT               -- 'info' | 'notice' | 'warning' | 'critical'

  actor_user_id  INTEGER NULL       -- registered id, or NULL for guest/system
  actor_hash     TEXT NULL          -- cert hash snapshot (stable identity)
  actor_name     TEXT NULL          -- display name *at the time*

  target_user_id INTEGER NULL
  target_hash    TEXT NULL
  target_name    TEXT NULL

  channel_id     INTEGER NULL
  reason         TEXT NULL
  detail_json    TEXT NULL          -- action-specific structured payload
                                     --   (before/after, CIDR, duration, ...)

  prev_hash      BLOB NULL          -- hash of previous row (tamper chain, §7.1)
  entry_hash     BLOB NULL          -- H(prev_hash || canonical(this row))
```

Notes:

- **Identity is snapshotted.** `*_name` is stored as it was at the time; joins
  to live user rows are best-effort for the current display name. A renamed or
  deleted user must not rewrite history.
- **`detail_json`** keeps the schema stable while letting each category carry its
  own shape (an ACL diff looks nothing like a ban). The client renders known
  categories richly and unknown ones as key/value.
- **Indexes**: `(server_id, ts)`, `(server_id, target_user_id, ts)`,
  `(server_id, actor_user_id, ts)`, `(server_id, category, ts)`. Text search on
  `reason` / `detail_json` goes through a **search-strategy seam** rather than a
  lowest-common-denominator `LIKE`: a `TextSearch` trait with one implementation
  per backend, each using the best that backend offers -

  | Backend | Strategy |
  |---|---|
  | SQLite | FTS5 virtual table (real ranked full-text) |
  | PostgreSQL | `tsvector` + GIN index, `to_tsquery` |
  | MySQL/MariaDB | `FULLTEXT` index, `MATCH ... AGAINST` |
  | fallback | `LIKE`, for any backend/build without the above |

  The strategy is selected once at startup from the live connection's
  capabilities (not assumed from the configured backend name, so a SQLite build
  without FTS5 degrades cleanly). Callers get one API; only ranking quality
  differs. The fallback keeps a new backend working before its strategy exists.
- **Migrations** follow the `Table::migrate(fromSchemaVersion, toSchemaVersion)`
  override that `LogTable` uses.

---

## 5. Query & search protocol (wire)

Two new Fancy TCP messages in the free range (**157–199**; Fancy currently uses
≤156 plus 200/201). Registered in `MUMBLE_ALL_TCP_MESSAGES`
(`src/MumbleProtocol.h`) like every other Fancy message.

```
FancyAuditQuery      (157)  Client -> Server
  optional string  query_id            // correlation
  repeated string  categories          // empty = all
  optional string  source              // 'server'|'client'|'plugin'
  optional uint32  actor_user_id
  optional uint32  target_user_id
  optional uint32  channel_id
  optional string  text                // matches reason/detail
  optional uint64  since_ms
  optional uint64  until_ms
  optional uint32  limit               // capped server-side (e.g. 200)
  optional uint64  before_id           // keyset pagination
  optional bool    subscribe           // live-tail new events

FancyAuditResponse   (158)  Server -> Client
  optional string        query_id
  repeated AuditEntry    entries        // newest first
  optional bool          has_more
  optional uint64        next_before_id

FancyAuditEvent      (159)  Server -> Client   // pushed to live subscribers
  AuditEntry entry
```

- **Gating.** `FancyAuditQuery` requires `Write` on the root channel - the same
  gate `msgFancyPluginAdminListRequest` already uses - *or* a dedicated
  permission (see §9). Non-authorized queries get an empty response, never a
  partial leak.
- **Pagination** is keyset (`before_id`) not offset, so a busy log paginates
  correctly while new entries arrive.
- **Subscriptions** stream `FancyAuditEvent` for entries matching the filter,
  so a moderator's open audit view tails live. Reuse the same "verified
  session" bookkeeping pattern the pchat manager uses for targeted delivery.
- **Rate-limited** through the existing token-bucket limiter (`IRateLimiter`),
  with an `audit` bucket, so search can't hammer the DB.

---

## 6. Client-reported moderation signals (#94)

This is the part that needs care. A local mute in Mumble is a *private user
preference*. Reporting "who muted whom" upstream turns a personal setting into
community-visible behavioural data. That can genuinely help moderation ("40% of
a channel muted this account within an hour" is a strong troll signal) **and**
can enable retaliation or chilling effects if done carelessly.

### 6.1 What can be reported

Client → server signal events (all opt-in, see §6.4):

| Signal              | Meaning                                            |
|---------------------|----------------------------------------------------|
| `signal.mute`       | local user muted/unmuted another user              |
| `signal.deafen_from`| local user stopped listening to another            |
| `signal.block`      | local user blocked another (stronger than mute)    |
| `signal.report`     | explicit "report this user" with a reason/category |
| `signal.hide`       | hid a user's messages / left channel on their join  |

`signal.report` is the important one: an **explicit**, intentional report is far
better moderation data than an inferred mute, and carries none of the "I muted
them because they're loud, not toxic" ambiguity. The design should push
operators toward explicit reports and treat passive mute-telemetry as a weak,
supplementary signal.

### 6.2 Aggregate-first storage

By default the server stores **aggregates**, not raw edges:

```
SignalAggregate (per target, per signal type, rolling window)
  server_id, target_user_id, signal, window_start,
  distinct_actors, total_events, last_ts
```

So a moderator sees *"18 distinct users muted X in the last 7 days (↑ from 3)"*
without the server holding a permanent who-muted-whom graph. Raw per-edge rows
(`signal.mute` with actor identity) are only written when the operator opts into
"detailed signals", carry shorter retention, and are visible only with the
signal-view permission (§9).

### 6.3 Anti-abuse

- **Brigading resistance.** Weight distinct-actor counts by simple trust
  proxies (registered vs guest, account age, prior presence) so a swarm of
  throwaway accounts can't manufacture a flag. Surface both raw and weighted
  counts.
- **No reciprocity leak.** A user must never be able to learn who muted them.
  Signal data is moderator-only; the client never exposes it back to targets or
  peers.
- **Rate-limited & deduplicated.** Rapid mute/unmute toggling collapses to one
  edge; the `signal` token bucket caps report spam.
- **Guest handling.** Guests (`user_id < 0`) can be actors for aggregate counts
  but are heavily discounted and never stored as raw identified edges.

### 6.4 Configuration & (optional) disclosure

- **Per-part switches, off by default.** There is no single `signals.enabled`
  master switch. Each signal (`signal.mute`, `signal.block`, `signal.report`,
  …) and its detailed/raw-edge variant is toggled independently by an admin with
  `ConfigureAudit` (§9.2). One operator can collect mute telemetry, the next can
  leave it off and take explicit reports only.
- **This is an admin audit - disclosure is optional.** The audit and signal data
  is operator-facing; no end-user consent flow is required by default. For
  operators who *want* to tell their users (policy, or a jurisdiction that
  expects it), a per-server `disclose_to_users` switch shows a client indicator
  ("This server records moderation signals") via the existing
  `FancyOnboardingConfig` (136–140) surface. Off by default; the admin opts in.
- **Data-subject controls.** Aggregates are pseudonymous; raw edges are
  deletable per user (right-to-erasure) and covered by the retention policy.
- **Reversibility.** Turning a part off stops *new* collection; it does not
  delete what was already gathered (§9.2). Removing existing data is a separate,
  explicit and audited action - the retention policy or a right-to-erasure
  request (§7.9) - so "stop collecting this" and "destroy what we collected"
  stay distinct decisions.

### 6.5 Wire

```
FancyModSignal       (160)  Client -> Server
  optional string  target_hash      // who the signal is about
  optional string  signal           // 'mute' | 'block' | 'report' | ...
  optional bool    active           // true=set, false=cleared (mute/unmute)
  optional string  reason           // required for 'report'
  optional string  category         // report category (spam/abuse/...)
```

The server validates the target exists, applies rate-limiting and trust
weighting, updates the aggregate, optionally writes a raw edge, and (for
`report`) writes an `AuditEvent` with `source='client'`, `category='signal.report'`
so explicit reports show up in the same searchable audit view as everything
else.

---

## 7. Additional ideas

Beyond the literal ticket:

### 7.1 Git-style hash chain (decided)
The record is an **append-only, git-style hash chain**: every entry commits to
its parent, exactly like a git commit references its parent commit.

```
entry_hash = SHA-256( parent_hash || canonical_encode(entry_without_hashes) )
```

- `canonical_encode` is a deterministic serialization of the entry's fields
  (fixed field order, no map ambiguity) so the hash is reproducible.
- The chain is per virtual server; the genesis entry uses an all-zero parent.
- **Signed checkpoints.** Periodically (every N entries / T minutes) the plugin
  writes a checkpoint entry - `{ height, entry_hash, ts }` signed with the
  server key. A checkpoint is a lightweight "tag": verifying it proves every
  entry up to that height is intact, without re-hashing the whole chain.
- **Verification tool.** A `verify` path walks the chain and reports the first
  break (a deleted row leaves a parent-hash gap; an edited row fails to
  reproduce its `entry_hash`). Exposed to `ViewAudit` holders and runnable
  offline against an export.

This matters precisely because the people with DB write access *are* the people
being audited: a rogue admin who deletes or edits a row breaks the chain
visibly, and cannot forge a later signed checkpoint without the server key.
(Optional next step: per-action moderator signatures, §7.11, prove *which*
operator - the chain proves *nothing was tampered with*.)

### 7.2 Audit the auditors
Viewing/searching/exporting/clearing the audit log is itself an `AuditEvent`
(`category='audit.access'`). Clearing is never a silent hard-delete; it writes a
"log cleared by X (N entries, range …)" tombstone.

### 7.3 Required reasons + reason templates
Destructive actions (ban/kick/de-register) prompt for a reason, with quick
templates ("spam", "harassment", "ban evasion"). Empty reasons are allowed but
visibly flagged.

### 7.4 Linked / reversible actions
Store a `relates_to` id so a later unban points back at the ban, a move-back at
the move, an unmute at the mute. The UI then shows action *pairs* and current
state ("banned 3d ago, unbanned 1d ago").

### 7.5 Per-user moderation history ("rap sheet")
A target-scoped view: every action against a user + every signal about them, on
one timeline. This is the natural home for #94's "who could be a problematic
person" - as a **human-readable dossier a moderator reads**, not an automated
score.

### 7.6 Advisory rules engine
Operator-defined thresholds that raise a **flag** (notify moderators, pin to a
review queue) - never an automatic sanction. E.g. "≥ N weighted distinct mutes
within M minutes", "kicked from ≥ K channels today". Every flag records which
rule fired and the evidence, and lands in the audit log as `category='flag'`.

### 7.7 Moderator notifications & review queue
High-severity events (ban of a registered user, a fired flag, a burst of
reports) push a notification to online moderators (reuse the push path,
`FancyPush*` 122–123) and populate a "needs review" queue.

### 7.8 Export & webhooks
`FancyAuditQuery` results are exportable (CSV/JSON). An operator can register a
webhook so audit events / flags fan out to Discord, a SIEM, or a bot - the same
"generalized request/response bridge" the plugin host already uses could carry
this to a plugin. For dashboards/metrics specifically (Grafana, Prometheus,
Loki, OTLP, Kibana, InfluxDB), see §8.

### 7.9 Retention & privacy policy surface

Retention is the **only** thing that deletes on a schedule - toggles never do
(§9.2) - and expiry runs as a documented, audited sweep. It is configurable per
part, with a 30-day global default for anything unlisted, and ships with this
reference policy: privacy-sensitive data stays short, the accountability record
lives long.

| Part | Retention | Why |
|---|---|---|
| `audit.ban`, `audit.kick` | **indefinite** | the record most needed later - ban evasion, appeals |
| `audit.acl`, `audit.config`, `audit.plugin_admin`, `audit.access` | **2 years** | who changed permissions or disabled logging; slow-burn abuse |
| `audit.register` | **2 years** | account lifecycle |
| `audit.mute_deafen_suppress`, `audit.move`, `audit.channel`, `audit.pchat_moderation`, `audit.plugin_action` | **180 days** | routine and high-volume; useful for patterns, not forever |
| `signal.*` aggregates | **1 year** | pseudonymous counts, low risk |
| `signal.*` raw edges (who→whom) | **30 days** | the most privacy-sensitive data in the system |
| telemetry | n/a | lives in the OTLP backend; that retention is the operator's |

Right-to-erasure tooling for a specific user sits alongside this, as an explicit
operator action rather than an automatic behaviour.

#### Retention is an attack surface, so it is constrained

Retention is the one *legitimate* deletion path, which makes it the obvious way
to launder tampering: an admin who cannot delete a chained entry (§7.1) could
otherwise set `audit.*` to one day and let their own actions expire. Three rules
close that:

1. **Hard floor of 30 days on `audit.*`.** The accountability categories cannot
   be configured below it - not by an admin, not by config file, not by API. A
   request to go lower is refused *and* recorded. (Signal parts have no floor;
   shortening those is a privacy improvement, not a cover-up.)
2. **Lowering retention is never retroactive.** Each row's `expires_at` is
   stamped **at write time** from the policy then in force. Reducing a retention
   setting therefore affects only records written afterwards - it cannot shorten
   the life of anything that already exists. Raising retention may extend
   existing rows, since that direction is safe. This is the same principle as
   the toggle rule (§9.2): change the future, never rewrite the past.
3. **Every retention change is an audit entry** (`category='config'`) recording
   actor, part, old value and new value - and it lands in `audit.config`, which
   is itself floored at 30 days and, under the reference policy, kept for two
   years. So the act of shortening retention outlives the shortening.

Together these mean the fastest possible cover-up is "wait 30 days, in a log
that already recorded you trying" - and expiring a chained entry leaves a
verifiable gap (§7.1) rather than a silent hole, so the chain still shows that
*something* aged out.

### 7.10 Architecture: an audit plugin on an enriched event bridge (decided)

The whole thing is a **plugin** on `mumble-plugin-host` (isolation, optional,
Rust, its own tables + migrations). The interesting part is what it forces the
host to grow.

**A server-event stream on the bridge.** The host doesn't emit moderation events
today. We add a host→plugin **event fan-out** so core can publish structured
events and any plugin can subscribe:

```
// host -> plugin (new bridge hook)
on_server_event(ServerEvent {
    server_id, ts,
    kind,        // 'ban','kick','mute','move','acl','channel.create',
                 //   'channel.remove','register','config','plugin.action', ...
    actor,       // session + user_id + cert hash (or 'system')
    target,      // optional user
    channel_id,  // optional
    detail_json, // kind-specific payload (before/after, duration, CIDR, ...)
})
```

Core calls a single `emitServerEvent(...)` from the same handlers listed in §3
(`msgUserRemove`, `msgBanList`, `msgUserState`, `msgACL`, channel lifecycle,
registration, `FancyServerSettings`). The host broadcasts to subscribed plugins.

**Why this is the good design, not just a means to an end.** Once these events
exist on the bridge, they are reusable infrastructure:

- the **audit plugin** records them (hash-chained, §7.1) and exports them (§8);
- a **moderation-bot** plugin can react to a ban (post to a channel, sync a
  blocklist);
- **friends / calendar / pchat** plugins can react to `channel.remove` or a user
  de-registration to clean up their own state instead of polling;
- future plugins get a documented event vocabulary for free.

So the audit feature pays for a general capability. This is worth calling out as
its own win: **the bridge becomes event-driven, not just request/response.**

**Transport: a small Kafka-like log, not a fire-and-forget callback.** The
stream is a **durable, append-only, offset-addressed log** owned by the host:

- every event gets a monotonic `offset` (per virtual server) and is appended
  before any consumer is woken, so an event can't be lost because a plugin was
  busy, slow or restarting;
- each subscribed plugin is a **consumer with its own committed offset**;
  delivery is **at-least-once** and resumes from the last commit after a plugin
  reload or a server restart;
- consumers are **independent** - a stalled calendar plugin cannot block the
  audit plugin, and a new plugin can **replay** history from offset 0 (or from
  the retention floor) to backfill;
- the log is **bounded** by size/age. A consumer that lags past the floor gets
  an explicit "gap" signal rather than silently missing events - the audit
  plugin records that gap as an entry, so a hole in the record is itself
  visible.

Implementation can be modest: an append-only table in the host's SQLite (already
a dependency) with a `consumer_offsets` table, rather than a real broker. The
semantics are what matter, not the machinery.

**At-least-once means consumers must be idempotent.** This matters specifically
for the hash chain (§7.1): a redelivered event must not append a second chained
entry. The audit plugin therefore keys on the event `offset`, records the last
applied one, and skips anything it has already chained.

**Subscription + filtering.** A plugin declares which `kind`s it wants (so a
calendar plugin isn't woken for every mute), applied as a server-side filter on
the log read.

**Auditing plugin actions themselves.** Plugins hold privileged
`PluginContext` calls - `create_channel`, `grant_channel_access`,
`revoke_channel_access`, pchat message deletion, config writes. **Every
privileged callback emits a `plugin.action` event**, not just a
"destructive" subset: deciding up front which calls are interesting bakes a
judgement into the emit path, and the cheap, reversible place to make that
choice is the *logging* toggle (§9.2), not the event source. Emission is
uniform; what gets recorded is policy.

The event is emitted **from inside the host's privileged callback** - never
self-reported by the calling plugin, which can't be trusted to report its own
actions - and is tagged with the plugin name/slot, the operation and its
arguments. A plugin deleting a channel or revoking access therefore lands in
the same hash-chained trail as a human admin doing it, with `source='plugin'`.
Destructive callbacks can additionally be gated by policy (e.g. "channel
deletion by a plugin requires capability X"), enforced host-side.

**Trust boundary.** Core still *owns* emitting the authoritative events (a
plugin can't fabricate a "ban" it didn't cause, because the event originates in
the core handler or the host's own privileged callback). The plugin owns
*storage, chaining, policy, rules, export* - all the opinionated, swappable
parts. The trusted record stays sourced from trusted code.

### 7.11 Signed moderator actions (later)
For high-assurance deployments, a moderator action could be signed client-side
with the moderator's key, so the audit entry proves *which operator* (not just
which session) acted. Optional; layers on top of the chain in §7.1.

---

## 8. Telemetry & visualization integrations

Operators running communities want dashboards, trend lines and alerts, not just
a search box. Everything below ships over **one transport - OpenTelemetry
(§8.1)** - to a collector that fans out to whatever backend the operator runs.
Audit/signal data still has **two shapes**, and keeping them apart is the one
thing that matters:

- **Metrics** - aggregate time series (counts, rates, gauges), emitted as OTLP
  metrics → Prometheus / Influx → **Grafana**. Trends, "is this normal for a
  Tuesday", and alerting.
- **Events / logs** - the individual audit rows, emitted as OTLP logs → Loki /
  Elastic / OpenSearch → Grafana Explore / **Kibana**. Search and per-user
  drill-down.

**Where it lives.** Not in the C++ core. The telemetry exporter is part of the
audit **plugin**, which already subscribes to the server-event stream (§7.10)
and holds the aggregates - so it exports what it already has. This keeps an
optional, vendor-touching integration out of the trusted server binary.

### 8.1 OpenTelemetry (OTLP) - the export path (decided)

Telemetry export is **OpenTelemetry, and only OpenTelemetry.** The plugin emits
OTLP over gRPC/HTTP to an OpenTelemetry Collector; the collector fans out to
whatever the operator runs - Prometheus, Loki, Tempo, Grafana / Grafana Cloud,
Elastic/OpenSearch, InfluxDB, Datadog, Honeycomb, … One exporter in our code,
any backend downstream, no vendor lock-in, nothing bespoke to maintain per
target. We do **not** ship a Prometheus scrape endpoint, a Loki client, an
InfluxDB writer, etc. - the collector already speaks all of those, so pushing
them into the server would be redundant surface with its own failure modes.

- **Enable/disable.** OTLP export is **off by default**, turned on per server by
  an admin with `ConfigureAudit`. What it *emits* is governed by the same
  per-part toggles as everything else (§9.2): a stream that is switched off is
  never exported.
- **Signals of what.** Metrics and logs now; traces are available later for free
  (spans around slow queries / rule evaluation) since we're already on OTLP.

### 8.2 What is exported - and cardinality discipline

OTLP carries the same two shapes (§ intro), and the metrics-vs-logs split is
where the one classic mistake lives.

**Metrics** (OTLP metrics → Prometheus/Influx/… via the collector): aggregate
only. A per-user or per-target attribute (`mute_count{target="alice"}`) is
unbounded cardinality and will melt any metrics backend. Keep attributes
low-cardinality:

```
fancymumble.audit.events        counter   {category, source, severity}
fancymumble.moderation.actions  counter   {action}
fancymumble.active_flags        gauge     {severity}
fancymumble.signal.reports      counter   {category}
fancymumble.connected_users     gauge
fancymumble.channels            gauge
```

**Logs** (OTLP logs → Loki/Elastic/… via the collector): the individual audit
entries as structured records. This is where **per-user drill-down** lives -
filter by target in the log query, never as a metric attribute. The moderator's
workflow is: a metrics panel shows the trend, click through to the log backend
for the specific events. This is also where the "who could be a problematic
person" view resolves (see the rap sheet, §7.5).

### 8.3 Starter Grafana dashboard

Ship a **starter dashboard** (JSON, committed under `docs/dashboards/`) built
against the OTLP metrics above: moderation actions over time, top categories,
flag rate, reports by category, connected users. Alerting (Grafana or
Alertmanager) fires on the aggregates - e.g. "report rate > N / 5 min" pages a
moderator. Grafana is named because it's the likely default, but nothing here is
Grafana-specific: any OTLP-fed backend can drive the same panels.

### Guardrails

- **Aggregate & pseudonymous by default.** No raw who-muted-whom on a dashboard;
  metrics never carry per-user attributes. Identified detail stays in the OTLP
  *log* stream, behind the log backend's access control, and only for the
  signal parts an admin explicitly enabled (§9.2).
- **Off by default, scoped auth.** OTLP export is opt-in per server, with its own
  endpoint + auth headers; point it at a private collector, not the public net.
- **Dashboards inherit the signal rules (§7.6).** A Grafana / Alertmanager alert
  may *notify* a moderator; it must never be wired to an automatic ban. The
  advisory-not-punitive line holds all the way out to the dashboard.
- **Retention lives with the backend.** Collector/backend retention is the
  operator's; the audit plugin's own retention policy (§7.9) is independent.

### Config sketch

```toml
# audit plugin config
[audit.telemetry]
otlp_enabled  = false                        # master switch, off by default
otlp_endpoint = ""                           # e.g. "http://otel-collector:4317"
otlp_protocol = "grpc"                       # "grpc" | "http/protobuf"
otlp_headers  = ""                           # "authorization=Bearer ..."
# which of the enabled (§9.2) streams are also exported over OTLP:
export_metrics = true
export_logs    = false                       # per-entry logs carry identities
```

## 9. Permissions & fine-grained configuration

### 9.1 Two new permissions

Two dedicated, grantable Fancy ACL bits (so communities can appoint auditors and
audit-admins who aren't full server admins):

- **`ViewAudit`** - read/search the audit log, run the chain `verify` (§7.1),
  view the per-user rap sheet (§7.5), and see aggregate signal counts. This is
  the "moderator/auditor" grant.
- **`ConfigureAudit`** - change *what is collected and exported*: the per-part
  toggles (§9.2), OTLP settings (§8), retention (§7.9), rules (§7.6), and the
  optional user-disclosure switch (§6.4). This is the "audit-admin" grant and is
  strictly higher than `ViewAudit`.

Both are checked host-side, and every use of `ConfigureAudit` (and every
clear/export) is itself an audit entry (§7.2). Viewing **raw signal edges** - the
most privacy-sensitive data - requires `ViewAudit` **plus** the raw-signal part
being enabled (§9.2); it is not implied by a plain audit view. **Targets** never
get access to signals about themselves (§6.3).

**Backed by ACL for now, behind a seam.** Both permissions are implemented as
Mumble ACL bits - that is what exists, what admins already understand, and what
the client permission editor can already display. But ACL is channel-scoped and
coarse, and a future model (roles, per-scope grants, time-boxed audit access)
may fit an audit system better. So the audit plugin does **not** call the ACL
API directly; it resolves permissions through a narrow interface:

```rust
trait AuditAuthz {
    fn can_view(&self, server: ServerId, session: SessionId) -> bool;
    fn can_configure(&self, server: ServerId, session: SessionId) -> bool;
    fn can_view_raw_signals(&self, server: ServerId, session: SessionId) -> bool;
}
```

with an ACL-backed implementation today. Swapping in a different model later is
then one implementation, not a hunt through call sites - and the DB grants in
§10.4 key off the same three answers.

### 9.2 Fine-grained, per-part toggles

There is no single on/off. Every collectable/exportable part is an independent
switch owned by `ConfigureAudit`, so two operators can run very different
policies on the same software - one collects mute telemetry, the next takes
explicit reports only. Conceptually a matrix of `{ part → collect?, export?,
retention }`:

| Part                          | Default | Notes |
|-------------------------------|---------|-------|
| `audit.ban` / `audit.kick`    | on      | core moderation; rarely disabled |
| `audit.mute_deafen_suppress`  | on      | server-imposed voice moderation |
| `audit.move`                  | on      | forced channel moves |
| `audit.acl`                   | on      | ACL/group edits |
| `audit.channel`               | on      | channel create/remove/rename |
| `audit.register`              | on      | (de)registration |
| `audit.config`                | on      | server-settings changes (secrets redacted) |
| `audit.plugin_admin`          | on      | install/enable/disable plugins |
| `audit.plugin_action`         | on      | plugin-initiated privileged calls (§7.10) |
| `audit.pchat_moderation`      | on      | pchat delete/pin/rate-limit |
| `audit.access`                | on      | audit-the-auditors (§7.2) |
| `signal.report`               | on*     | explicit user reports (recommended) |
| `signal.mute`                 | **off** | passive mute telemetry |
| `signal.block`                | **off** | |
| `signal.hide` / `deafen_from` | **off** | |
| `signal.*` raw edges          | **off** | who→whom; separate from aggregate counts |
| `telemetry.otlp.metrics`      | **off** | aggregate metrics over OTLP |
| `telemetry.otlp.logs`         | **off** | per-entry logs over OTLP (carry identity) |
| `disclose_to_users`           | **off** | show the client indicator (§6.4) |

\* `signal.report` is only active once *any* signal collection is enabled; with
everything off, the plugin still records the server-authoritative audit trail
(which is the actual ticket) and simply collects no client signals.

#### Toggle semantics: stop the future, never rewrite the past

A toggle governs **what is recorded from now on. It never deletes what was
already recorded.** Three consequences:

1. **Turning a part off stops new entries only.** Existing history stays exactly
   as it was. Anything else would be rewriting the past - and for chained
   entries (§7.1) it is not even possible without visibly breaking the chain,
   which is the point of having one.
2. **Deleting is a separate, explicit, permissioned action** - retention policy
   or a right-to-erasure request (§7.9) - never a side effect of flipping a
   switch. That separation keeps "stop collecting this" and "destroy what we
   collected" from being the same gesture, because they are very different
   decisions.
3. **The toggle change is itself an audit event.** Enabling or disabling any
   part writes an entry (`category='config'`, actor recorded), so "who turned
   off `audit.plugin_action`, and when" is always answerable. An operator cannot
   quietly disable the thing that is watching them without that act being the
   first thing in the log.

This is also why `audit.plugin_action` is a *logging* toggle rather than an
emit-time filter (§7.10): the event stream stays uniform and complete, and the
toggle only decides what the audit plugin persists.

---

## 10. Admin page

A single new page in the admin settings, in two halves (tabs). It has its **own
self-contained dashboard** - it queries the audit table directly and renders its
own charts, so it works with zero external infrastructure. Grafana/OTLP (§8) is
the *heavy-duty, optional* path for operators who want more; the admin page must
never require it.

Two rendering surfaces, matching how plugins already do UI:

- **In-client** via the plugin's `SettingsPanel` / component manifest
  (`api/src/client_manifest.rs`) - good enough for the configuration half and
  basic filtering, no browser needed.
- **Rich web page** - a plugin-served **React + MUI** app (the file-server web
  pattern: Vite build, `@mui/material`, served over the plugin's axum HTTP) for
  the full Grafana/Kibana-style viewer with charts and advanced search.

### 10.1 Half A - Configuration (requires `ConfigureAudit`)

Renders the §9.2 toggle matrix as friendly grouped switches - **Audit**,
**Signals**, **Telemetry**, **Retention**, **Rules**, **Disclosure** - so a
non-technical operator flips "collect mute telemetry" without touching a config
file. Also:

- assign `ViewAudit` / `ConfigureAudit` to users/groups (§9.1);
- OTLP settings (endpoint, protocol, headers, which streams - §8);
- per-part retention (§7.9) and the rules editor (§7.6);
- a live "what's being collected right now" summary and **chain status** with a
  one-click `verify` (§7.1).

Every change here is itself an audit entry (`category='config'`, §7.2).

### 10.2 Half B - Viewer (requires `ViewAudit`)

Dashboard style modeled on the file-server admin page:

- **KPI tiles** - actions today, active flags, open reports, distinct actors.
- **Time-series & breakdown charts** - actions over time, by category, flag
  rate, reports by category, top-N most-actioned users / most-active moderators.
  (Charts follow the project's dataviz conventions; the same aggregates that
  feed OTLP metrics in §8 drive them locally.)
- **Results table** - the audit entries, keyset-paginated and sortable; click a
  row for a detail drawer (full `detail_json`, chain position, `relates_to`
  links, jump to the user's rap sheet §7.5).
- **The search scopes the whole dashboard** (Kibana-style): narrowing the query
  re-renders the tiles, charts and table together.
- **Live tail** toggle (the subscribe stream, §5) and **export** (CSV/JSON) of
  the current result.

### 10.3 Dual-mode search - the core requirement

One search, two front-ends onto the *same* query, kept in sync so users graduate
from one to the other:

- **Filter builder (non-technical).** Chips/dropdowns for category, actor,
  target, channel, severity, source and a time-range picker, with facet counts
  ("ban 42, kick 18"). Point-and-click; no syntax. Feels like Kibana's filter
  pills / Grafana's label filters.
- **Query language (technical).** A SQL/KQL-like text box:

  ```
  category = "ban" and target.name ~ "trol*" and ts > now-7d and actor.name = "mod3"
  ```

  Field operators (`=`, `!=`, `~` like, `in`, `<`, `>`), boolean `and/or/not`,
  time helpers (`now-7d`), free-text terms, with field/value autocomplete.

- **They are bound both ways.** Building filters writes the query text; editing
  the query updates the pills. A non-technical user never sees the DSL; a
  technical user gets full power; both describe the same search.
- **Saved & shareable searches** (named, URL-encoded), so a community can pin
  "recent bans without a reason" or "new-account reports this week".

#### Two execution modes

Power users asked for the *full* SQL surface - joins, unions, CTEs, aggregates -
not a toy subset. That is worth having, but it changes where the security
boundary can live, so the viewer has two modes:

| Mode | Reached by | Expressiveness | Boundary |
|---|---|---|---|
| **Simple** | filter builder, and the plain `field = value` DSL | flat filters over audit entries | lowers to `FancyAuditQuery` (§5); parameterised, permission-gated in one place |
| **Advanced SQL** | the query editor, opt-in | full `SELECT`: joins, unions, CTEs, aggregates, window functions | read-only execution against permission-scoped **views**, enforced by the database engine (§10.4) |

Simple mode stays the default and covers the point-and-click path. Advanced mode
is what a technical user drops into when they want "every user banned within 24h
of their first message, joined to their report count".

**Why the boundary has to move.** In the restricted design, the parser *was* the
security boundary: a whitelist that could only express what `FancyAuditQuery`
allows. That does not survive joins and unions - `UNION SELECT` and arbitrary
joins are precisely the primitives that reach other tables, and a whitelist that
permits them is no longer a boundary. So for advanced mode the enforcement moves
down into the database, where it is a real, engine-level control rather than
string inspection (§10.4).

#### Parser: what to build on (researched)

There *is* a crate that advertises exactly "Lucene syntax → SQL" -
[`lucene-query-syntax`](https://crates.io/crates/lucene-query-syntax) - and it is
**not usable here**:

- **Licence: AGPL-3.0-or-later.** The server is BSD-licensed; linking AGPL code
  into it would push network-copyleft obligations onto the server and onto every
  operator running it. It also isn't on the workspace licence allow-list, so
  `cargo deny check licenses` rejects it outright.
- **Unproven.** v0.1.1, ~739 total / ~11 recent downloads, untouched since
  2025-08. Not something to put on the query path of an audit system.

Two viable options instead:

| Option | Crate | Licence | Health (Jul 2026) | Trade-off |
|---|---|---|---|---|
| **A. Real SQL grammar** | [`sqlparser`](https://crates.io/crates/sqlparser) (sqlparser-rs, used by Apache DataFusion) | Apache-2.0 | v0.62, ~10.4M recent downloads | Battle-tested SQL grammar for free, and the only option that can serve *both* modes: `parse_expr()` for a standalone `WHERE`-style expression in simple mode, full statement parsing for validation/shaping in advanced mode (§10.4). Users get genuinely familiar syntax. |
| **B. Hand-roll a tiny grammar** | [`winnow`](https://crates.io/crates/winnow) or [`chumsky`](https://crates.io/crates/chumsky) | MIT | winnow ~204M recent; chumsky ~8.6M recent, excellent error messages | Safe by construction, but caps expressiveness at whatever we implement - it cannot deliver the requested joins/unions without becoming a SQL engine of our own. Would also mean owning the grammar, errors and autocomplete metadata. |

**Decided: A - `sqlparser`.** The ask is explicitly a SQL language, and
`sqlparser` gives the real grammar (and all its edge cases) for free under a
compatible licence. In **simple mode** it parses an expression and lowers to
`FancyAuditQuery`; in **advanced mode** it parses the full statement for
validation and shaping (§10.4). Time helpers like `now-7d` are pre-processed
before the parse, or written as `ts > now() - interval '7 days'`.

### 10.4 Advanced SQL: read-only, view-scoped, engine-enforced

Full SQL is safe here only because the caller never touches base tables and
never holds write capability. Four layers, in order of importance:

1. **Views, not tables.** Advanced mode can reference only a small set of
   curated read-only views - `audit_entries`, `audit_flags`,
   `audit_signals_agg`, and `audit_signal_edges`. The views project exactly the
   columns an auditor may see (identity snapshots, no internal chain plumbing)
   and are the *only* objects in scope.
2. **The database enforces it, not the parser.** This is the actual boundary:
   - **PostgreSQL / MySQL** - a dedicated role with `GRANT SELECT` on those
     views and nothing else. A `UNION SELECT` against any other table fails in
     the engine, not in our code.
   - **SQLite** (no roles) - a separate connection opened `SQLITE_OPEN_READONLY`
     with an **authorizer callback** (`sqlite3_set_authorizer`, exposed by
     rusqlite as `set_authorizer`) that denies every action except `SELECT` on
     the whitelisted views, and refuses `ATTACH`, `PRAGMA`, DDL and DML
     outright. An authorizer is an engine-level hook, so it holds regardless of
     how the SQL is written.
3. **Permission scoping lives in the grant.** `audit_signal_edges` (the raw
   who→whom data) is only reachable when the caller has that part enabled
   (§9.2); otherwise the object is simply not authorised. A `ViewAudit` holder
   without it cannot reach the data no matter what SQL they write - there is no
   query to get clever with.
4. **Parse-time checks as defence in depth**, not as the boundary: reject
   anything that isn't a single `SELECT`/CTE, enforce a `LIMIT`, and extract the
   referenced objects for a fast pre-check and for autocomplete.

**Resource guards.** Full SQL means a user can write a cartesian join, so
advanced mode runs with a statement timeout, a hard row cap, and (SQLite) a
progress handler that can interrupt a long-running statement. A slow query
degrades that one request, not the server.

**Every advanced query is audited** (§7.2) with its SQL text - the people with
the most query power are the ones most worth logging.

**On by default - but it proves the sandbox first.** Advanced mode is available
to `ViewAudit` holders out of the box. Its safety depends on the deployment
actually having the boundary in place (the right grants, or the authorizer
installed), and an operator can't be expected to verify that by hand - so the
plugin verifies it itself, at startup:

- open the read-only/authorized connection and attempt a handful of things that
  **must** fail - `SELECT` from a table outside the view set, a write, an
  `ATTACH`, a `PRAGMA`;
- if every one is refused, advanced mode enables;
- if *any* of them succeeds, advanced mode **stays off**, the server logs why,
  and it is recorded as an audit entry.

So the failure mode is "advanced search is unavailable and says so", never
"advanced search quietly runs with a boundary that isn't there". Simple mode is
unaffected either way, since it never emits free-form SQL. The self-check also
doubles as the regression test for the grants and the authorizer.

### 10.5 Making it approachable

Full SQL must not become the only way to get answers:

- **Filter builder first** (§10.3) - the default surface; no syntax at all.
- **Builder → SQL escape hatch.** The pills can *generate* the equivalent SQL
  and drop it into the editor, which is how a non-technical user gradually
  learns the language instead of facing a blank editor.
- **Syntax autocomplete** in the editor: view and column names, enum values
  (`category`, `severity`, `source`), and facet values pulled live from the
  data, plus signature help for functions. The server exposes the view schema +
  enum domains for this, so the client never hardcodes them.
- **Query templates** - a starter library ("bans without a reason this month",
  "most-actioned users", "moderator activity by day") that are ordinary saved
  queries, so they double as worked examples.
- **Explain / dry-run** - show the row estimate and let the user cancel before
  running something expensive.

[`tantivy`](https://crates.io/crates/tantivy) (MIT, healthy) is worth noting but
is a different thing: a full search *engine* with its own index, not a SQL
bridge. Only reach for it if we later want ranked full-text over `reason` /
`detail_json` - and then it's a second index to keep in sync, not a replacement
for the SQL path.

---

## 11. Implementation phases

Since it's a plugin, the first real work is the **bridge event stream** (§7.10)
- it's the dependency everything else hangs off, and it's independently useful.

1. **Bridge event stream (host + core).** Add the host→plugin `on_server_event`
   fan-out with per-`kind` subscription, and `emitServerEvent(...)` calls in the
   core moderation handlers (`msgUserRemove`, `msgBanList`, `msgUserState`,
   `msgACL`, channel lifecycle, registration, `FancyServerSettings`) plus the
   host's privileged callbacks (`plugin.action`). No storage yet - a test plugin
   asserts the events arrive.
2. **Audit plugin MVP.** `server_audit` table + migrations, git-style hash chain
   (§7.1), subscribe to the stream and record. `ConfigureAudit`/`ViewAudit`
   permissions and the per-part toggle set (§9.2). Verify via the plugin's own
   tests and the DB.
3. **Search protocol + admin viewer (§10).** `FancyAuditQuery`/`Response`/`Event`
   (157–159), `ViewAudit` gate, keyset pagination, live subscribe. The admin page
   viewer half: KPI tiles, charts, results table, the dual-mode search (filter
   builder ⇄ safe DSL), and a chain `verify` action. Config half (§10.1) renders
   the §9.2 toggles.
4. **Reasons, links, rap sheet.** Reason prompts, `relates_to`, per-user timeline.
5. **Signals (per-part opt-in).** `FancyModSignal` (160), aggregate table, trust
   weighting, the §9.2 toggles, optional `disclose_to_users`. Explicit `report`
   first; passive mute/block telemetry each behind its own switch.
6. **Advanced.** Signed checkpoints (§7.1), rules engine + review queue,
   moderator notifications, retention/erasure tooling.
7. **Telemetry (§8).** OTLP exporter in the plugin: aggregate metrics + optional
   per-entry logs, gated by the §9.2 telemetry toggles. Committed starter
   dashboard under `docs/dashboards/`. Depends on phase 2 (events stored) and,
   for signal metrics, phase 5.

---

## 12. Open questions

- **Log retention floor for the event stream (§7.10).** Decided that it is a
  bounded Kafka-like log; still open is *how* bounded (size vs age), and whether
  the audit consumer should get a stricter floor than reactive consumers so it
  can never be the one that hits a gap.
