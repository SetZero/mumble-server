//! The host server-event stream as a durable, Kafka-like log (§7.10).
//!
//! In the shipped architecture this log is owned by the host so *every* plugin
//! can subscribe (a moderation bot, calendar cleanup, the audit plugin). It is
//! implemented here, with its full semantics and tests, as the consumable core;
//! lifting it into the `host` crate is a move, not a rewrite — "the semantics
//! are what matter, not the machinery" (§7.10).
//!
//! Semantics:
//!
//! - every event gets a monotonic `offset` (per virtual server) and is appended
//!   before any consumer is woken, so nothing is lost to a busy/restarting
//!   plugin;
//! - each consumer has its **own committed offset**; delivery is
//!   **at-least-once** and resumes from the last commit;
//! - consumers are **independent** — a stalled one cannot block another — and a
//!   new consumer can **replay** from offset 0 (or the floor) to backfill;
//! - the log is **bounded**; a consumer that lags past the floor gets an
//!   explicit [`Gap`] rather than silently missing events.

use std::collections::BTreeMap;
use std::collections::VecDeque;

use crate::model::Identity;

/// A structured moderation/lifecycle event published by core onto the bridge
/// (§7.10). `offset` is assigned by the log on append and is the idempotency
/// key downstream consumers dedupe on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEvent {
    /// Virtual server the event belongs to.
    pub server_id: i32,
    /// Event time in unix milliseconds on the server clock.
    pub ts_ms: i64,
    /// Event kind: `ban`, `kick`, `mute`, `move`, `acl`, `channel.create`,
    /// `channel.remove`, `register`, `config`, `plugin.action`, `signal.*`, …
    pub kind: String,
    /// Who caused the event (or a `system` identity).
    pub actor: Identity,
    /// Who the event was about, if any.
    pub target: Identity,
    /// Channel the event concerned, if any.
    pub channel_id: Option<i64>,
    /// Kind-specific payload as a canonical JSON string.
    pub detail_json: Option<String>,
}

impl ServerEvent {
    /// Construct an event of `kind` at `ts_ms` on `server_id`.
    #[must_use]
    pub fn new(server_id: i32, ts_ms: i64, kind: impl Into<String>) -> Self {
        Self {
            server_id,
            ts_ms,
            kind: kind.into(),
            actor: Identity::default(),
            target: Identity::default(),
            channel_id: None,
            detail_json: None,
        }
    }

    /// Set the actor.
    #[must_use]
    pub fn with_actor(mut self, actor: Identity) -> Self {
        self.actor = actor;
        self
    }

    /// Set the target.
    #[must_use]
    pub fn with_target(mut self, target: Identity) -> Self {
        self.target = target;
        self
    }

    /// Set the channel id.
    #[must_use]
    pub const fn with_channel(mut self, channel_id: i64) -> Self {
        self.channel_id = Some(channel_id);
        self
    }

    /// Set the detail payload.
    #[must_use]
    pub fn with_detail_json(mut self, detail_json: impl Into<String>) -> Self {
        self.detail_json = Some(detail_json.into());
        self
    }
}

/// An event paired with its assigned offset, as delivered to a consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    /// The monotonic per-server offset assigned at append.
    pub offset: u64,
    /// The event.
    pub event: ServerEvent,
}

/// Which event kinds a consumer wants (§7.10 subscription filtering).
#[derive(Debug, Clone, Default)]
pub enum KindFilter {
    /// Receive every kind.
    #[default]
    All,
    /// Receive only these kinds. An entry ending in `.*` matches by prefix
    /// (e.g. `channel.*` matches `channel.create`).
    Only(Vec<String>),
}

impl KindFilter {
    /// Whether this filter accepts `kind`.
    #[must_use]
    pub fn accepts(&self, kind: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(patterns) => patterns
                .iter()
                .any(|pattern| pattern_matches(pattern, kind)),
        }
    }
}

fn pattern_matches(pattern: &str, kind: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or_else(|| pattern == kind, |prefix| kind.starts_with(prefix))
}

/// Returned by [`EventLog::poll`] when a consumer has fallen behind the log
/// floor: some events between its committed offset and the floor were dropped
/// by the bound and can never be delivered. The consumer records the gap so a
/// hole in the record is itself visible (§7.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// The consumer's committed offset (exclusive lower bound it wanted next).
    pub from: u64,
    /// The current log floor: the offset of the oldest still-retained event.
    pub to: u64,
}

#[derive(Debug, Clone)]
struct Consumer {
    /// Next offset this consumer has *not* yet processed. Everything `< committed`
    /// is done; delivery resumes here.
    committed: u64,
    filter: KindFilter,
}

/// A bounded, append-only, offset-addressed event log with per-consumer
/// offsets (§7.10). Single-server; a host holds one per virtual server.
#[derive(Debug)]
pub struct EventLog {
    /// Retained events in offset order.
    events: VecDeque<Delivered>,
    /// Offset the next appended event will get.
    next_offset: u64,
    /// Offset of the oldest retained event (== `next_offset` when empty).
    floor: u64,
    /// Maximum number of events retained before the oldest are dropped.
    capacity: usize,
    consumers: BTreeMap<String, Consumer>,
}

impl EventLog {
    /// Create a log bounded to at most `capacity` retained events. Capacity is
    /// clamped to at least 1.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: VecDeque::new(),
            next_offset: 0,
            floor: 0,
            capacity: capacity.max(1),
            consumers: BTreeMap::new(),
        }
    }

    /// Append `event`, assign it the next offset, and return that offset. The
    /// event is durable (retained) before any consumer is polled.
    pub fn append(&mut self, event: ServerEvent) -> u64 {
        let offset = self.next_offset;
        self.events.push_back(Delivered { offset, event });
        self.next_offset += 1;
        self.enforce_bound();
        offset
    }

    /// The offset the next appended event will receive (the head).
    #[must_use]
    pub const fn head(&self) -> u64 {
        self.next_offset
    }

    /// The oldest retained offset. Events below this have aged out.
    #[must_use]
    pub const fn floor(&self) -> u64 {
        self.floor
    }

    /// Register (or re-register) a consumer named `name`, starting delivery at
    /// `start`, wanting `filter`. Re-registering with a known name preserves
    /// nothing — the caller supplies the resume point, which in production is
    /// the consumer's persisted committed offset.
    pub fn register_consumer(
        &mut self,
        name: impl Into<String>,
        start: ConsumerStart,
        filter: KindFilter,
    ) {
        let committed = match start {
            ConsumerStart::Beginning => self.floor,
            ConsumerStart::Head => self.next_offset,
            ConsumerStart::At(offset) => offset,
        };
        let _ = self
            .consumers
            .insert(name.into(), Consumer { committed, filter });
    }

    /// Poll for events a consumer has not yet committed, honouring its filter.
    ///
    /// Does **not** advance the offset (at-least-once): the caller processes the
    /// batch and then [`commit`](Self::commit)s. Returns [`Gap`] if the
    /// consumer's committed offset is below the log floor.
    ///
    /// # Errors
    /// Returns [`Gap`] when the consumer lagged past the retained floor.
    pub fn poll(&self, name: &str) -> Result<Vec<Delivered>, Gap> {
        let Some(consumer) = self.consumers.get(name) else {
            return Ok(Vec::new());
        };
        if consumer.committed < self.floor {
            return Err(Gap {
                from: consumer.committed,
                to: self.floor,
            });
        }
        let batch = self
            .events
            .iter()
            .filter(|delivered| delivered.offset >= consumer.committed)
            .filter(|delivered| consumer.filter.accepts(&delivered.event.kind))
            .cloned()
            .collect();
        Ok(batch)
    }

    /// Mark everything up to and including `offset` as processed for `name`, so
    /// the next poll resumes after it. Committing an older offset is ignored
    /// (offsets only move forward).
    pub fn commit(&mut self, name: &str, offset: u64) {
        if let Some(consumer) = self.consumers.get_mut(name) {
            let next = offset.saturating_add(1);
            if next > consumer.committed {
                consumer.committed = next;
            }
        }
    }

    /// After a gap, fast-forward a consumer to the current floor so it can
    /// resume from the oldest still-retained event.
    pub fn resume_after_gap(&mut self, name: &str) {
        if let Some(consumer) = self.consumers.get_mut(name) {
            consumer.committed = self.floor;
        }
    }

    fn enforce_bound(&mut self) {
        while self.events.len() > self.capacity {
            if self.events.pop_front().is_some() {
                self.floor += 1;
            }
        }
    }
}

/// Where a freshly-registered consumer begins reading.
#[derive(Debug, Clone, Copy)]
pub enum ConsumerStart {
    /// From the oldest retained event (replay/backfill).
    Beginning,
    /// From the current head (only future events).
    Head,
    /// From a specific persisted offset (resume after restart).
    At(u64),
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;

    fn ev(server: i32, kind: &str) -> ServerEvent {
        ServerEvent::new(server, 0, kind)
    }

    #[test]
    fn offsets_are_monotonic_from_zero() {
        let mut log = EventLog::with_capacity(100);
        assert_eq!(log.append(ev(1, "ban")), 0);
        assert_eq!(log.append(ev(1, "kick")), 1);
        assert_eq!(log.append(ev(1, "mute")), 2);
        assert_eq!(log.head(), 3);
    }

    #[test]
    fn a_consumer_reads_commits_and_resumes() {
        let mut log = EventLog::with_capacity(100);
        let _ = log.append(ev(1, "ban"));
        let _ = log.append(ev(1, "kick"));
        log.register_consumer("audit", ConsumerStart::Beginning, KindFilter::All);

        let batch = log.poll("audit").unwrap();
        assert_eq!(batch.len(), 2);
        // At-least-once: polling again before commit redelivers.
        assert_eq!(log.poll("audit").unwrap().len(), 2);

        log.commit("audit", batch.last().unwrap().offset);
        assert!(log.poll("audit").unwrap().is_empty());

        // New event flows to the committed consumer.
        let _ = log.append(ev(1, "mute"));
        let next = log.poll("audit").unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].event.kind, "mute");
    }

    #[test]
    fn consumers_are_independent() {
        let mut log = EventLog::with_capacity(100);
        let o0 = log.append(ev(1, "ban"));
        let _ = log.append(ev(1, "kick"));
        log.register_consumer("audit", ConsumerStart::Beginning, KindFilter::All);
        log.register_consumer("calendar", ConsumerStart::Beginning, KindFilter::All);

        // audit commits the first; calendar has not moved.
        log.commit("audit", o0);
        assert_eq!(log.poll("audit").unwrap().len(), 1);
        assert_eq!(log.poll("calendar").unwrap().len(), 2);
    }

    #[test]
    fn kind_filter_limits_delivery() {
        let mut log = EventLog::with_capacity(100);
        let _ = log.append(ev(1, "ban"));
        let _ = log.append(ev(1, "channel.create"));
        let _ = log.append(ev(1, "channel.remove"));
        let _ = log.append(ev(1, "mute"));
        log.register_consumer(
            "calendar",
            ConsumerStart::Beginning,
            KindFilter::Only(vec!["channel.*".to_owned()]),
        );
        let batch = log.poll("calendar").unwrap();
        assert_eq!(batch.len(), 2);
        assert!(batch.iter().all(|d| d.event.kind.starts_with("channel.")));
    }

    #[test]
    fn a_new_consumer_can_replay_from_the_beginning() {
        let mut log = EventLog::with_capacity(100);
        for _ in 0..5 {
            let _ = log.append(ev(1, "ban"));
        }
        log.register_consumer("late", ConsumerStart::Beginning, KindFilter::All);
        assert_eq!(log.poll("late").unwrap().len(), 5);
    }

    #[test]
    fn head_start_skips_history() {
        let mut log = EventLog::with_capacity(100);
        let _ = log.append(ev(1, "ban"));
        log.register_consumer("fresh", ConsumerStart::Head, KindFilter::All);
        assert!(log.poll("fresh").unwrap().is_empty());
        let _ = log.append(ev(1, "kick"));
        assert_eq!(log.poll("fresh").unwrap().len(), 1);
    }

    #[test]
    fn lagging_past_the_floor_yields_a_gap() {
        let mut log = EventLog::with_capacity(2);
        log.register_consumer("slow", ConsumerStart::Beginning, KindFilter::All);
        // Append past capacity so the oldest drop and the floor advances.
        for _ in 0..5 {
            let _ = log.append(ev(1, "ban"));
        }
        assert_eq!(log.floor(), 3, "capacity 2 keeps offsets 3,4");
        match log.poll("slow") {
            Err(gap) => {
                assert_eq!(gap.from, 0);
                assert_eq!(gap.to, 3);
            }
            Ok(_) => panic!("a lagged consumer must see a gap, not silent loss"),
        }
        // After recording the gap, it resumes at the floor.
        log.resume_after_gap("slow");
        assert_eq!(log.poll("slow").unwrap().len(), 2);
    }
}
