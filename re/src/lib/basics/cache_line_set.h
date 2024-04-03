#ifndef __CACHE_LINE_SET_H__
#define __CACHE_LINE_SET_H__

#include <stdlib.h>
#include <stdint.h>

#include "allocator.h"

#define MAX_CACHELINES_IN_SET 0x100000

typedef struct {
    int64_t num_cache_lines;
    size_t cache_lines[MAX_CACHELINES_IN_SET];
    allocator_t* allocator;
} cache_line_set_t;

cache_line_set_t* build_empty_cache_line_set(allocator_t* allocator);

void delete_cache_line_set(cache_line_set_t* cache_line_set);

int is_in_cache_line_set(cache_line_set_t* cache_line_set, size_t addr, size_t cache_line_size);

cache_line_set_t* merge_cache_line_sets(int num_sets, cache_line_set_t** sets);

void push_cache_line_to_set(cache_line_set_t* cache_line_set, size_t cache_line);

size_t pop_cache_line_from_set(cache_line_set_t* cache_line_set);

size_t pop_cache_line_from_set_by_index(cache_line_set_t* cache_line_set, int index);

cache_line_set_t* copy_cache_line_set(cache_line_set_t* cache_line_set_to_copy, size_t page_offset);

cache_line_set_t* reduce_cache_line_set(cache_line_set_t* orig_cache_line_set, int num_elem);

void sort_cache_line_set(cache_line_set_t* cache_line_set);

void shuffle_cache_line_set(cache_line_set_t* cache_line_set);

void print_cache_line_set(cache_line_set_t* cache_line_set);

#endif
