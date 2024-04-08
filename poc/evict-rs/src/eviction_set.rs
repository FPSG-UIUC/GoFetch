use crate::cache_line::{CacheLine, CacheLineAdapter};
use crate::timer::Timer;
use intrusive_collections::{LinkedList, LinkedListLink};
use rand::Rng;
use rand::seq::SliceRandom;

/// The eviction set consists of a linked list of cache lists that can be
/// traversed multiple times in an attempt to evict certain cache lines.
pub struct EvictionSet<'a> {
    list: LinkedList<CacheLineAdapter<'a>>,
}

impl<'a> EvictionSet<'a> {
    /// Construct an eviction set from a set of cache lines.
    pub fn new(cache_lines: &'a [*mut u8]) -> Self {
        let mut list = LinkedList::new(CacheLineAdapter::new());

        for cache_line in cache_lines {
            let cache_line = unsafe { &mut *(*cache_line as *mut CacheLine) };
            cache_line.link = LinkedListLink::new();
            list.push_back(cache_line);
        }

        Self {
            list,
        }
    }

    /// Accesses the elements of the eviction set.
    #[inline(always)]
    pub fn access(&self) {
        for _ in 0..2 {
            // Perform a forward traversal over two linked lists with one cursor
            // lagging behind n steps to perform dual-chasing.
            let mut iter = self.list.iter();
            let lagging_iter = self.list.iter();

            for _ in 0..8 {
                iter.next();
            }

            for _ in lagging_iter {
                iter.next();
            }

            // Perform a backward traversal over two linked lists with one
            // cursor lagging behind n steps to perform dual-chasing.
            let mut iter = self.list.iter().rev();
            let lagging_iter = self.list.iter().rev();

            for _ in 0..8 {
                iter.next();
            }

            for _ in lagging_iter {
                iter.next();
            }
        }
    }

    pub fn evict_and_time_once<T: Timer>(
        &self,
        timer: &T,
        victim: *mut u8,
    ) -> u64 {
        // First load the victim.
        unsafe { victim.read_volatile() };
        unsafe { core::arch::asm!("dsb ish") };
        unsafe { core::arch::asm!("isb sy") };

        // Access this eviction set in an attempt to evict the victim.
        self.access();

        unsafe { core::arch::asm!("dsb ish") };
        unsafe { core::arch::asm!("isb sy") };

        // Load the victim again, but this time the access to determine if the
        // victim is still cached or whether it actually got evicted.
        timer.time_load(victim)
    }

    pub fn evict_and_time<R: Rng, T: Timer>(
        rng: &mut R,
        timer: &T,
        victim: *mut u8,
        cache_lines: &mut [*mut u8],
        timings: &mut [u64],
    ) -> u64 {
        for index in 0..timings.len() {
            // Randomize the set of cache lines.
            cache_lines.shuffle(rng);

            // Construct an eviction set.
            let eviction_set = EvictionSet::new(cache_lines);

            // Evict and time the victim access.
            timings[index] = eviction_set.evict_and_time_once(timer, victim);
        }

        timings.sort();

        timings[timings.len() / 2]
    }
}

impl<'a> Drop for EvictionSet<'a> {
    fn drop(&mut self) {
        self.list.fast_clear();
    }
}
