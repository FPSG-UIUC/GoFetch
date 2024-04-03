#ifndef __EVICTION_SET_GENERATION_H__
#define __EVICTION_SET_GENERATION_H__

#include <stdint.h>
#include "../basics/cache_line_set.h"
// #define DEBUG

#ifdef DEBUG
#define _dprintf printf
#else
#define _dprintf(...)
#endif
// Find L1 eviction set by ensuring congruent page offsets
cache_line_set_t* find_L1_eviction_set(uint8_t* victim_addr);
// this function outputs a set of cache lines (with size = set_size) that map to the same L1 set as victim_addr
cache_line_set_t* find_L1_congruent_cache_lines(uint8_t* victim_addr, int set_size);

// this function outputs a set of cache lines that map to the same L2 set as victim_addr, using the classic algorithm
// the output set is a good eviction set for victim_addr, and the set size is exactly L2_NWAYS
cache_line_set_t* find_L2_eviction_set_using_timer(uint8_t* victim_addr);
#endif
