#ifndef __EVICTION_SET_H__
#define __EVICTION_SET_H__

#include "../basics/allocator.h"
#include "../basics/cache_line_set.h"
#include "../basics/linked_list.h"

#include <stdint.h>

#define NUM_TESTS 100

// the eviction set consists of a linked list of cache lines
// that can be traversed multiple times in an attempt to evict 
// certain cache lines
typedef struct {
    linked_list_t* list_of_cachelines;
} eviction_set_t;

extern uint8_t global_junk;

eviction_set_t* create_eviction_set(cache_line_set_t* cache_line_set);

void delete_eviction_set(eviction_set_t* eviction_set);

void print_eviction_set(eviction_set_t* eviction_set);

void add_line_to_eviction_set(eviction_set_t* eviction_set, size_t cache_line_addr);

uint8_t traverse_eviction_set(eviction_set_t* eviction_set);

uint64_t evict_and_time(uint8_t* victim_addr, cache_line_set_t* cache_line_set);

#endif
