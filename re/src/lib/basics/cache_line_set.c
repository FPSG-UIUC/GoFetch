#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "allocator.h"
#include "cache_line_set.h"
#include "math_utils.h"
#include "arch.h"

cache_line_set_t* build_empty_cache_line_set(allocator_t* allocator) {
    cache_line_set_t* cache_line_set = (cache_line_set_t*)malloc(sizeof(cache_line_set_t));
    cache_line_set->num_cache_lines = 0;
    cache_line_set->allocator = allocator;

    if (allocator)
        allocator->ref_count++;
    return cache_line_set;
}

void delete_cache_line_set(cache_line_set_t* cache_line_set) {

    if (cache_line_set->allocator) {
        assert (cache_line_set->allocator->ref_count > 0);
        cache_line_set->allocator->ref_count--;

        if (cache_line_set->allocator->ref_count == 0)
            delete_allocator(cache_line_set->allocator);
    }

    free(cache_line_set);

}

int is_in_cache_line_set(cache_line_set_t* cache_line_set, size_t addr, size_t cache_line_size) {
    for (int i = 0; i < cache_line_set->num_cache_lines; i++)
        if ((addr / cache_line_size) == (cache_line_set->cache_lines[i] / cache_line_size))
            return 1;
    return 0;
}

void push_cache_line_to_set(cache_line_set_t* cache_line_set, size_t cache_line) {
    if ( __builtin_expect(cache_line_set->num_cache_lines == MAX_CACHELINES_IN_SET, 0) ) {
        fprintf(stderr, "ERROR: cannot add cache line to a full cache line set.\n");
        exit(1);
    }
    cache_line_set->cache_lines[cache_line_set->num_cache_lines] = cache_line;
    cache_line_set->num_cache_lines++;
}

size_t pop_cache_line_from_set(cache_line_set_t* cache_line_set) {
    if ( __builtin_expect(cache_line_set->num_cache_lines == 0, 0) ) {
        fprintf(stderr, "ERROR: cannot pop cache line from an empty cache line set.\n");
        exit(1);
    }
    cache_line_set->num_cache_lines--;
    return cache_line_set->cache_lines[cache_line_set->num_cache_lines];
}

size_t pop_cache_line_from_set_by_index(cache_line_set_t *cache_line_set, int index) {
    if ( __builtin_expect(index < 0 || index >= cache_line_set->num_cache_lines, 0) ) {
        fprintf(stderr, "ERROR: cannot pop index %d from cache line set of size %lld\n", index, cache_line_set->num_cache_lines);
        exit(1);
    }

    size_t cache_line_to_ret = cache_line_set->cache_lines[index];

    for (int i = index; i < cache_line_set->num_cache_lines-1; i++)
        cache_line_set->cache_lines[i] = cache_line_set->cache_lines[i+1];

    cache_line_set->num_cache_lines--;

    return cache_line_to_ret;
}

cache_line_set_t* copy_cache_line_set(cache_line_set_t* cache_line_set_to_copy, size_t page_offset) {

    cache_line_set_t* new_cache_line_set = build_empty_cache_line_set(cache_line_set_to_copy->allocator);

    new_cache_line_set->num_cache_lines = cache_line_set_to_copy->num_cache_lines;

    for (int i = 0; i < new_cache_line_set->num_cache_lines; i++)
        new_cache_line_set->cache_lines[i] = (cache_line_set_to_copy->cache_lines[i] & 0xffffffffffffc000) + page_offset;

    return new_cache_line_set;
}

cache_line_set_t* reduce_cache_line_set(cache_line_set_t* orig_cache_line_set, int num_elem) {

    if ( __builtin_expect(num_elem > orig_cache_line_set->num_cache_lines, 0) ) {
        fprintf(stderr, "ERROR: cannot reduce a cache line set of size %lld into %d size!\n", orig_cache_line_set->num_cache_lines, num_elem);
        exit(1);
    }

    cache_line_set_t* reduced_cache_line_set = build_empty_cache_line_set(orig_cache_line_set->allocator);

    for (int i = 0; i < num_elem; i++)
        push_cache_line_to_set(reduced_cache_line_set, orig_cache_line_set->cache_lines[i]);

    return reduced_cache_line_set;
}

cache_line_set_t* merge_cache_line_sets(int num_sets, cache_line_set_t** sets) {
    cache_line_set_t* merged_cache_line_set = build_empty_cache_line_set(NULL);

    for (int i = 0; i < num_sets; i++)
        for (int j = 0; j < sets[i]->num_cache_lines; j++)
            push_cache_line_to_set(merged_cache_line_set, sets[i]->cache_lines[j]);

    return merged_cache_line_set;
}

void sort_cache_line_set(cache_line_set_t *cache_line_set) {
    sort(cache_line_set->cache_lines, cache_line_set->num_cache_lines, sizeof(size_t));
}

void shuffle_cache_line_set(cache_line_set_t *cache_line_set) {
    shuffle(cache_line_set->cache_lines, cache_line_set->num_cache_lines, sizeof(size_t));
}

void print_cache_line_set(cache_line_set_t* cache_line_set) {
    printf("cache line set size: %lld\n", cache_line_set->num_cache_lines);
    for (int i = 0; i < cache_line_set->num_cache_lines; i++)
        printf("cache line #%d: 0x%lx  |xxx|0x%llx|0x%llx|0x%llx|\n", 
                i, cache_line_set->cache_lines[i],
                HPO((uint64_t)cache_line_set->cache_lines[i]),
                RPO((uint64_t)cache_line_set->cache_lines[i]),
                CLO((uint64_t)cache_line_set->cache_lines[i])
                );
}
