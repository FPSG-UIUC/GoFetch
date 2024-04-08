use crate::eviction_set::EvictionSet;
use crate::timer::Timer;
use rand::Rng;
use rand::seq::SliceRandom;
use std::time::Instant;

pub struct Allocator {
    pages: Vec<mmap_rs::MmapMut>,
    cache_lines: Vec<*mut u8>,
    offset: usize,
    stride: usize,
}

impl Allocator {
    fn allocate_page(&mut self) {
        use mmap_rs::MmapOptions;

        let page_size = MmapOptions::page_size().1;
        let mut page = MmapOptions::new(page_size)
            .map_mut()
            .unwrap();

        // Write to the page to ensure that the OS actually allocates it.
        page.fill(0x01);

        for index in (0..page.len()).step_by(self.stride) {
            let cache_line = unsafe {
                (page.as_mut_ptr() as *mut u8).add(index + self.offset)
            };

            self.cache_lines.push(cache_line);
        }

        self.pages.push(page);
    }
}

impl Allocator {
    pub fn new(offset: usize, stride: usize) -> Self {
        Self {
            pages: vec![],
            cache_lines: vec![],
            offset,
            stride,
        }
    }

    pub fn l1_evset_gen(
        &mut self, 
        ways: usize
    ) -> CacheLineSet {
        let mut cache_lines = vec![];
        for _ in 0..ways {
            let cache_line = self.allocate_line();
            cache_lines.push(cache_line);
        }

        CacheLineSet {
            cache_lines,
        }
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
        self.cache_lines.clear();
        for page in &mut self.pages {
            for index in (0..page.len()).step_by(self.stride) {
                let cache_line = unsafe {
                    (page.as_mut_ptr() as *mut u8).add(index + self.offset)
                };
    
                self.cache_lines.push(cache_line);
            }
        }
    }

    pub fn allocate_line(&mut self) -> *mut u8 {
        if let Some(cache_line) = self.cache_lines.pop() {
            return cache_line;
        }

        self.allocate_page();

        if let Some(cache_line) = self.cache_lines.pop() {
            return cache_line;
        }

        panic!("unable to allocate memory");
    }

    pub fn inflate<R: Rng, T: Timer>(
        &mut self,
        rng: &mut R,
        timer: &T,
        victim: *mut u8,
        max_size: usize,
        samples: usize,
        threshold: u64,
    ) -> CacheLineSet {
        let mut cache_lines = vec![];

        while cache_lines.len() < max_size {
            for _ in cache_lines.len()..(cache_lines.len() * 2).max(16) {
                let cache_line = self.allocate_line();

                cache_lines.push(cache_line);
            }

            let mut timings = vec![0u64; samples];

            let timing = EvictionSet::evict_and_time(
                rng,
                timer,
                victim,
                &mut cache_lines,
                &mut timings,
            );

            if timing >= threshold {
                break;
            }
        }

        CacheLineSet {
            cache_lines,
        }
    }

    // use reverse engineering M1 L2 set mapping
    #[cfg(target_os = "linux")]
    pub fn l2_evset_gen(
        &mut self, 
        ways: usize,
        slice: u8,
        pfn_set: u8
    ) -> CacheLineSet {
        let mut cache_lines = vec![];
        let mut cur_slice: u8 = 0;
        let mut cur_pfn_set: u8 = 0;
        let mut cur_num: usize = 0;
        while cur_num < ways {
            let cache_line = self.allocate_line();
            parse_pfn(&cache_line, &mut cur_slice, &mut cur_pfn_set);
            if (cur_slice == slice) && (cur_pfn_set == pfn_set) {
                cache_lines.push(cache_line);
                cur_num += 1;
            }
        }

        CacheLineSet {
            cache_lines,
        }
    }
}

pub struct CacheLineSet {
    pub cache_lines: Vec<*mut u8>
}

impl CacheLineSet {
    pub fn reduce<R: Rng, T: Timer>(
        &mut self,
        rng: &mut R,
        timer: &T,
        victim: *mut u8,
        samples: usize,
        threshold: u64,
        ways: usize,
    ) -> CacheLineSet {
        let mut reserve = vec![];
        let mut evicts = false;
        let now = Instant::now();

        while (self.cache_lines.len() != ways || !evicts) && (now.elapsed().as_secs() <= 10) {
            // Having fewer cache lines than the number of ways per cache set is
            // not ideal for our eviction set. Re-allocate cache lines until our
            // eviction set reaches double the number of ways.
            if self.cache_lines.len() <= ways {
                reserve.shuffle(rng);

                for _ in self.cache_lines.len()..(2 * ways) {
                    if let Some(cache_line) = reserve.pop() {
                        self.cache_lines.push(cache_line);
                    }
                }
            }

            // We split up the eviction set into the number of ways + 1 bins of
            // equal size. We then construct an eviction set excluding one of
            // the bins at a time, and check how well each of the eviction sets
            // performs. We then pick those bins that ended up having the
            // highest timings, as it means the eviction set without the bin is
            // still capable of evicting, i.e. the bin is not required.
            let starts: Vec<usize> = (0..self.cache_lines.len())
                .step_by(self.cache_lines.len() / (ways + 1))
                .collect();
            let mut ends = starts[1..].to_vec();
            ends.push(self.cache_lines.len());

            let mut best_timing = 0;
            let mut best_ranges = vec![];

            for (start, end) in starts.iter().zip(ends.iter()) {
                let range = *start..*end;
                let mut set = vec![];

                // Create an eviction set that does not contain the selected
                // bin.
                for (index, cache_line) in self.cache_lines.iter().enumerate() {
                    if range.contains(&index) {
                        continue;
                    }

                    set.push(*cache_line);
                }

                // Measure the time it takes to load the victim after accessing
                // the current eviction set.
                let mut timings = vec![0u64; samples];

                let timing = EvictionSet::evict_and_time(
                    rng,
                    timer,
                    victim,
                    &mut set,
                    &mut timings,
                );

                // Skip the eviction set if the timing got fast, since it means
                // we probably filtered out too many important elements.
                if timing < threshold {
                    continue;
                }

                if timing > best_timing {
                    // We found a higher timing. Keep track of this bin.
                    best_timing = timing;
                    best_ranges = vec![range.clone()];
                } else if timing == best_timing {
                    // We found the same timing. Keep track of this bin.
                    best_ranges.push(range.clone());
                }
            }

            // At this point we tested all of the possible eviction sets.
            if best_ranges.len() > 0 {
                // We found bins that do not contribute to the eviction set.
                // Thus we can simply remove them.
                for best_range in best_ranges.iter().rev() {
                    for index in best_range.clone().rev() {
                        let cache_line = self.cache_lines.remove(index);
                        reserve.push(cache_line);
                    }
                }
            } else {
                // We did not find any bins, which means that the eviction sets
                // all resulted in an access time that was too fast. It is very
                // likely that we removed crucial elements in a previous step.
                // Therefore, we add in cache lines back from the reserve until
                // the eviction set is double the size of what it currently is.
                reserve.shuffle(rng);

                for _ in 0..self.cache_lines.len() {
                    if let Some(cache_line) = reserve.pop() {
                        self.cache_lines.push(cache_line);
                    }
                }
            }

            // println!("found eviction set of {} elements", self.cache_lines.len());

            let mut timings = vec![0u64; samples];

            let timing = EvictionSet::evict_and_time(
                rng,
                timer,
                victim,
                &mut self.cache_lines,
                &mut timings,
            );

            // println!("tested eviction set = {}", timing);//timings[timings.len() / 2]);

            // Test if this eviction set is still able to evict.
            evicts = timing >= threshold;
        }

        CacheLineSet {
            cache_lines: reserve,
        }
    }

    pub fn create_eviction_set<'a>(&'a self) -> EvictionSet<'a> {
        EvictionSet::new(&self.cache_lines)
    }
}
