//! The list of tunnel implementations HTM knows about.
//!
//! Adding a provider means adding one line to [`all`].

use std::sync::Arc;

use super::candytunnel::CandyTunnelProvider;
use super::{ProviderRef, TunnelProvider};

/// Every registered provider, in the order the UI should offer them.
pub fn all() -> Vec<ProviderRef> {
    vec![Arc::new(CandyTunnelProvider::new()) as ProviderRef]
}

/// Look a provider up by its stable id.
pub fn get(id: &str) -> Option<ProviderRef> {
    all().into_iter().find(|p| p.id() == id)
}

/// The provider used when saved state names one that no longer exists.
pub fn default_provider() -> ProviderRef {
    all()
        .into_iter()
        .next()
        .expect("at least one provider must be registered")
}

/// Resolve an id, falling back to the default rather than failing.
pub fn get_or_default(id: &str) -> ProviderRef {
    get(id).unwrap_or_else(default_provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candytunnel_is_registered() {
        assert!(get("candytunnel").is_some());
        assert_eq!(default_provider().id(), "candytunnel");
    }

    #[test]
    fn unknown_ids_fall_back() {
        assert_eq!(get_or_default("nope").id(), "candytunnel");
    }

    #[test]
    fn provider_ids_are_unique() {
        let ids: Vec<&str> = all().iter().map(|p| p.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }
}
