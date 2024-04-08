//! The cache line is the smallest unit of granularity at which cache attacks
//! operate. This module provides an abstraction [`CacheLine`] that can be used
//! to temporarily link cache lines together to form an eviction set that can be
//! accessed through traversing the linked list.
use intrusive_collections::LinkedListLink;
use intrusive_collections::intrusive_adapter;

/// The cache line is the smallest unit of granularity at which cache attacks
/// operate.
pub struct CacheLine {
    /// This link is a node in a doubly-linked list. It used to temporarily
    /// link together multiple cache lines to form an eviction set, where
    /// traversing the linked list results in access pattern that can evict
    /// other cache lines from the cache.
    pub link: LinkedListLink,
}

intrusive_adapter!(pub CacheLineAdapter<'a> = &'a CacheLine: CacheLine { link: LinkedListLink });
