#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "eviction_set_generation.h"
#include "eviction_set.h"
#include "sys_utils.h"
#include "../basics/arch.h"
#include "../basics/allocator.h"
#include "../basics/cache_line_set.h"
#include "../basics/math_utils.h"


cache_line_set_t* find_L1_eviction_set(uint8_t* victim_addr) {

    uint64_t page_offset = (uint64_t)victim_addr % PAGE_SIZE;
    allocator_t* allocator = create_allocator(page_offset, PAGE_SIZE);

    cache_line_set_t* congruent_cache_lines = build_empty_cache_line_set(allocator);

    for (int i = 0; i < L1_NWAYS; i++) {
        allocate_page(allocator);
        size_t congruent_addr = allocator->pages[i] + page_offset;
        push_cache_line_to_set(congruent_cache_lines, congruent_addr);
    }

    assert (congruent_cache_lines->num_cache_lines == L1_NWAYS);

    return congruent_cache_lines;
}


cache_line_set_t* build_l2_eviction_set_superset(allocator_t* allocator, uint8_t* victim_addr, int threshold) {
    cache_line_set_t* candidate_cache_line_set = build_empty_cache_line_set(allocator);

    while (1) {
        int num_cache_lines_to_add = max(16, candidate_cache_line_set->num_cache_lines);

        for (int i = 0; i < num_cache_lines_to_add; i++) {
            // pick a cache line from the allocated cache line pool
            size_t cache_line_candidate = pop_cache_line_from_allocator(allocator);

            // add this cache line to the superset
            push_cache_line_to_set(candidate_cache_line_set, cache_line_candidate);
        }

        int timing = evict_and_time(victim_addr, candidate_cache_line_set);
        _dprintf("latency = %d, candidate_cache_line_set size=%ld\n", timing, candidate_cache_line_set->num_cache_lines);

        if (timing > threshold)
            break; // we found the superset of eviction set
    }

    return candidate_cache_line_set;
}


void reduce_l2_eviction_set_superset(cache_line_set_t* eviction_set_superset, uint8_t* victim_addr, int threshold) {
    cache_line_set_t reserved_cache_line_set;
    reserved_cache_line_set.num_cache_lines = 0;

    int max_wait = 20; // we want to at most spend 20 seconds doing the search
    time_t start, end;
    time(&start);

    int evicted = 0;

    // we want the result to be an eviction set with exactly L2_NWAYS elements
    // and the victim_addr can be stably evicted by the eviction set we found
    while (eviction_set_superset->num_cache_lines != L2_NWAYS || !evicted) {
        _dprintf("eviction set superset size: %ld, evicted: %d\n", eviction_set_superset->num_cache_lines, evicted);

        // the reduction process should be fairly quick (less than 10 seconds).
        // We halt if it takes too long (> 20 seconds)
        time(&end);
        int sec = difftime(end, start);
        if (sec > max_wait) {
            fprintf(stderr, "PANIC: takes >20 seconds reducing the eviction set. STOP.\n");
            exit(1);
        }

        // if we drop too many cache lines s.t. the number of cache lines is fewer
        // than the number of ways, we need to stay back and get more cache lines
        if (eviction_set_superset->num_cache_lines < L2_NWAYS) {

            shuffle(reserved_cache_line_set.cache_lines, reserved_cache_line_set.num_cache_lines, sizeof(size_t));

            _dprintf("before poping from reserved: %ld\n", reserved_cache_line_set.num_cache_lines);
            for (int i = eviction_set_superset->num_cache_lines; i < 2 * L2_NWAYS; i++) {
                size_t reserved_cache_line = pop_cache_line_from_set(&reserved_cache_line_set);
                push_cache_line_to_set(eviction_set_superset, reserved_cache_line);
            }
            _dprintf("after poping from reserved: %ld\n", reserved_cache_line_set.num_cache_lines);
        }

        // We split the eviction set into #ways + 1 bins of equal size.
        // We then construct an eviction set excluding one of the bins at a time,
        // and check how well each of the eviction sets performs.
        // We then pick those bins that ended up having the highest timings, as it indicates that
        // the eviction set without the bin is still capable of evicting the victim address,
        // i.e. the bin is not necessary

        // create L2_NWAYS+1 bins of indices
        int start_indices[L2_NWAYS+1];
        int end_indices[L2_NWAYS+1];
        for (int i = 0; i < L2_NWAYS+1; i++) {
            start_indices[i] = eviction_set_superset->num_cache_lines / (L2_NWAYS+1) * i;
            end_indices[i] = eviction_set_superset->num_cache_lines / (L2_NWAYS+1) * (i+1);
        }
        end_indices[L2_NWAYS] = eviction_set_superset->num_cache_lines;

        int best_timing = 0; // we want to find the L2_NWAYS bins that yield the max access latency
        int insignificant_bin = -1;

        for (int i = 0; i < L2_NWAYS+1; i++) {
            // create an eviction set that does not contain the i-th bin
            cache_line_set_t eviction_set_reduced;
            eviction_set_reduced.num_cache_lines = 0;

            int start_index = start_indices[i];
            int end_index = end_indices[i];
            for (int j = 0; j < eviction_set_superset->num_cache_lines; j++) {
                if (start_index <= j && j < end_index)
                    continue;
                push_cache_line_to_set(&eviction_set_reduced, eviction_set_superset->cache_lines[j]);
            }

            // measure the time it takes to load the victim after accessing eviction_set_reduced
            int timing = evict_and_time(victim_addr, &eviction_set_reduced);

            // skip this reduced eviction set if the timing is too fast, indicating that
            // we probably filtered out too many important cache lines
            if (timing < threshold)
                continue;

            // if the latency is greater than threshold, the bin we exclude in the current round of
            // evict_and_time is probably insignificant thus can be discarded
            if (timing >= best_timing) {
                // we found a higher timing. The current bin is more insignificant
                best_timing = timing;
                insignificant_bin = i;
            }
        }

        _dprintf("find insignificant bin = %d [%d-%d]\n", insignificant_bin, start_indices[insignificant_bin], end_indices[insignificant_bin]);
        _dprintf("current superset size = %ld\n", eviction_set_superset->num_cache_lines);

        // At this point we tested all bins
        if (insignificant_bin >= 0) {
            // We found a bin that doesn't contribute to the eviction set.  Remove this bin
            // First, move the bin to reserved
            for (int x = start_indices[insignificant_bin]; x != end_indices[insignificant_bin]; x++)
                push_cache_line_to_set(&reserved_cache_line_set, eviction_set_superset->cache_lines[x]);

            // Second, remove the bin
            for (int x = start_indices[insignificant_bin], y = end_indices[insignificant_bin];
                y < eviction_set_superset->num_cache_lines;
                x++, y++)  {
                // remove the x-th cache line
                eviction_set_superset->cache_lines[x] = eviction_set_superset->cache_lines[y];
            }
            eviction_set_superset->num_cache_lines -= (end_indices[insignificant_bin] - start_indices[insignificant_bin]);
            _dprintf("after removing insignificant_bin %d, eviction set superset size = %ld, reserved set size = %ld\n", 
                    insignificant_bin, eviction_set_superset->num_cache_lines, reserved_cache_line_set.num_cache_lines);
        }
        else {
            // we cannot find any insignificant bin. This means all combination of bins cannot
            // constitute an eviction set. This is very likely that we removed some crucial elements
            // in a previous step. Thus we add the cache lines back from reserved_cache_line_set
            // until the eviction set size is doubled
            shuffle(reserved_cache_line_set.cache_lines, reserved_cache_line_set.num_cache_lines, sizeof(size_t));

            int num_reserved_cache_lines_to_add = eviction_set_superset->num_cache_lines;

            _dprintf("before poping reserved: %ld\n", reserved_cache_line_set.num_cache_lines);
            for (int i = 0; i < num_reserved_cache_lines_to_add && reserved_cache_line_set.num_cache_lines > 0; i++) {
                size_t reserved_cache_line = pop_cache_line_from_set(&reserved_cache_line_set);
                push_cache_line_to_set(eviction_set_superset, reserved_cache_line);
            }
            _dprintf("after poping reserved: %ld\n", reserved_cache_line_set.num_cache_lines);

            _dprintf("after adding reserved lines. eviction set superset size = %ld\n", eviction_set_superset->num_cache_lines);
        }

        // After we removed a bin, test the victim address again and see if the rest is an eviction set
        int timing = evict_and_time(victim_addr, eviction_set_superset);
        evicted = timing >= threshold;
        _dprintf("after removing insignificant_bin, timing = %d, evicted = %d\n", timing, evicted);
    }
}

cache_line_set_t* find_L2_eviction_set_using_timer(uint8_t* victim_addr) {

    cache_line_set_t* evset_cache_lines;

    uint64_t page_offset = (uint64_t)victim_addr % PAGE_SIZE;
    allocator_t *allocator = create_allocator(page_offset, PAGE_SIZE);

    // find the eviction set for victim_addr
    while (1) {
        evset_cache_lines = build_l2_eviction_set_superset(allocator, victim_addr, L2_MISS_MIN_LATENCY);

        // print the measured time when using the superset to evict victim_addr
        int timing_evicted = evict_and_time(victim_addr, evset_cache_lines);
        printf("try evicting %p with generated eviction set superset: latency = %d\n", victim_addr, timing_evicted);

        // reduce the superset into L2_NWAYS number of cache lines
        reduce_l2_eviction_set_superset(evset_cache_lines, victim_addr, L2_MISS_MIN_LATENCY);

        break;
    }

    return evset_cache_lines;
}


