// A bounded, in-order trail of what happened right before an error: SQL queries, outbound calls,
// anything added by hand via `add_breadcrumb`. This crate has no web framework integration at all
// (unlike sdks/go's net/http/Gin middleware, or gems/forge_ops_tracker's Rack middleware), so
// there's no automatic source and no request boundary this module could hook a "start a fresh
// trail" step into on its own; a host app using this crate inside its own request handler is
// expected to call `clear_breadcrumbs()` itself at the start of each one, the same honest
// division of responsibility `set_user` in lib.rs already documents for the identical reason.
//
// A plain `thread_local!`, the same choice CURRENT_USER in lib.rs already made and for the
// identical reason (see that thread-local's own doc comment): the right fit for this crate's
// synchronous, thread-per-request-shaped design, not for an async runtime, where a single OS
// thread can interleave multiple unrelated tasks. Unlike CURRENT_USER, there's no `Option` wrapper
// here: a trail is always "on," just possibly empty, so `add_breadcrumb`/`current_breadcrumbs` can
// stay simple rather than needing to lazily create one first.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pii_scrubber::Value;

/// One entry in a trail. Matches the wire shape gems/forge_ops_tracker's own BreadcrumbBuffer#add
/// already builds, and the same four keys Api::V1::EventsController permits.
#[derive(Clone, Debug, PartialEq)]
pub struct Breadcrumb {
    pub category: String,
    pub message: String,
    pub level: String,
    pub timestamp: String,
    pub data: HashMap<String, Value>,
}

thread_local! {
    static BREADCRUMBS: RefCell<Vec<Breadcrumb>> = const { RefCell::new(Vec::new()) };
}

/// Records one entry into the current thread's trail: a query, an outbound call, or anything
/// worth remembering right up to the moment something actually goes wrong. `category` defaults to
/// `"custom"` and `level` to `"info"` when passed an empty string, the same zero-value-means-
/// default convention this crate's own `Configuration` uses for its env-seeded fields.
///
/// A no-op, not an error, when `track_breadcrumbs` is `false`: the same "the call site never has
/// to check first" posture every other independently-gated mechanism in this crate already has.
pub fn add_breadcrumb(
    track_breadcrumbs: bool,
    max_breadcrumbs: usize,
    message: &str,
    category: &str,
    level: &str,
    data: HashMap<String, Value>,
) {
    if !track_breadcrumbs || max_breadcrumbs == 0 {
        return;
    }

    let category = if category.is_empty() {
        "custom"
    } else {
        category
    };
    let level = if level.is_empty() { "info" } else { level };

    BREADCRUMBS.with(|trail| {
        let mut trail = trail.borrow_mut();
        trail.push(Breadcrumb {
            category: category.to_string(),
            message: message.to_string(),
            level: level.to_string(),
            timestamp: format_now(),
            data,
        });
        if trail.len() > max_breadcrumbs {
            let overflow = trail.len() - max_breadcrumbs;
            trail.drain(0..overflow);
        }
    });
}

/// Clears the current thread's trail: call this yourself at the start of each request, the same
/// place a host app would already be calling `set_user` (or clearing it) from, since this crate
/// has no middleware of its own to do it automatically. Without this, a synchronous, thread-
/// pool-based server (actix-web's own worker threads, for instance) would otherwise let one
/// request's trail bleed into the next one handled on the same reused thread.
pub fn clear_breadcrumbs() {
    BREADCRUMBS.with(|trail| trail.borrow_mut().clear());
}

/// Reads back a copy of the current thread's trail: `Reporter`'s own counterpart to
/// `add_breadcrumb` above, called automatically by `capture_error`/`capture_error_with_class`/the
/// panic hook, the same way `current_user()` already is.
pub fn current_breadcrumbs() -> Vec<Breadcrumb> {
    BREADCRUMBS.with(|trail| trail.borrow().clone())
}

fn format_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    crate::event_builder::format_unix_timestamp(now.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test below clears the thread-local trail first: cargo test runs tests in a thread
    // pool by default, and a pool thread genuinely can be reused across separate #[test]
    // functions, the same "the same OS thread can end up serving totally unrelated work" reason
    // clear_breadcrumbs() itself exists in the first place; without this, some other test's
    // leftover entries could leak into this one's own assertions depending purely on scheduling.
    fn reset() {
        clear_breadcrumbs();
    }

    #[test]
    fn add_breadcrumb_preserves_order_and_defaults() {
        reset();
        add_breadcrumb(true, 30, "first", "", "", HashMap::new());
        add_breadcrumb(
            true,
            30,
            "second",
            "custom",
            "warning",
            HashMap::from([("n".to_string(), Value::Number(1.0))]),
        );

        let trail = current_breadcrumbs();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].message, "first");
        assert_eq!(trail[0].category, "custom");
        assert_eq!(trail[0].level, "info");
        assert!(trail[0].data.is_empty());
        assert_eq!(trail[1].message, "second");
        assert_eq!(trail[1].level, "warning");
        assert_eq!(trail[1].data.get("n"), Some(&Value::Number(1.0)));
        assert!(!trail[0].timestamp.is_empty());
        reset();
    }

    #[test]
    fn add_breadcrumb_drops_oldest_once_over_max_size() {
        reset();
        add_breadcrumb(true, 2, "one", "", "", HashMap::new());
        add_breadcrumb(true, 2, "two", "", "", HashMap::new());
        add_breadcrumb(true, 2, "three", "", "", HashMap::new());

        let trail = current_breadcrumbs();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].message, "two");
        assert_eq!(trail[1].message, "three");
        reset();
    }

    #[test]
    fn add_breadcrumb_is_a_no_op_when_tracking_is_off() {
        reset();
        add_breadcrumb(false, 30, "hello", "", "", HashMap::new());

        assert!(current_breadcrumbs().is_empty());
        reset();
    }

    #[test]
    fn add_breadcrumb_is_a_no_op_when_max_size_is_zero() {
        reset();
        add_breadcrumb(true, 0, "hello", "", "", HashMap::new());

        assert!(current_breadcrumbs().is_empty());
        reset();
    }

    #[test]
    fn clear_breadcrumbs_empties_the_current_thread_trail() {
        reset();
        add_breadcrumb(true, 30, "hello", "", "", HashMap::new());
        assert_eq!(current_breadcrumbs().len(), 1);

        clear_breadcrumbs();

        assert!(current_breadcrumbs().is_empty());
    }
}
