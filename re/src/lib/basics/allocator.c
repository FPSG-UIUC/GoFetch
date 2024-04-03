#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <time.h>

#include "allocator.h"
#include "math_utils.h"
#include "arch.h"

#define _dprintf(...)

allocator_t* create_allocator(int offset, int stride) {
    allocator_t* new_allocator = (allocator_t*)malloc(sizeof(allocator_t));

    new_allocator->num_pages = 0;
    new_allocator->num_cache_lines = 0;

    new_allocator->offset = offset;
    new_allocator->stride = stride;
    new_allocator->ref_count = 0;

    return new_allocator;
}

void delete_allocator(allocator_t* allocator) {
    // free up the allocated pages
    for (int i = 0; i < allocator->num_pages; i++) {
        munmap((void*)allocator->pages[i], PAGE_SIZE);
    }

    // free up the allocator
    free(allocator);
}

void allocate_page(allocator_t* allocator) {
    size_t page = (size_t)mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0);
    assert (page);
    assert (page % PAGE_SIZE == 0);
    if (__builtin_expect(allocator->num_pages == MAX_PAGES_IN_ALLOCATOR, 0)) {
        fprintf(stderr, "ERROR: allocator has max page number!\n");
        exit(1);
    }
    allocator->pages[allocator->num_pages] = page;
    allocator->num_pages++;

    memset((void*)page, 0x01, PAGE_SIZE);

    size_t cache_line_addr = page + allocator->offset;
    while (cache_line_addr < page + PAGE_SIZE) {
        if ( __builtin_expect(allocator->num_cache_lines == MAX_CACHELINES_IN_ALLOCATOR, 0) ) {
            fprintf(stderr, "ERROR: allocator has max cache lines!\n");
            exit(1);
        }
        allocator->cache_lines[allocator->num_cache_lines] = cache_line_addr;
        allocator->num_cache_lines++;
        cache_line_addr += allocator->stride;
    }

    // shuffle the cache lines
    shuffle(allocator->cache_lines, allocator->num_cache_lines, sizeof(size_t));
}

size_t pop_cache_line_from_allocator(allocator_t* allocator) {
    if (allocator->num_cache_lines == 0)
        allocate_page(allocator);

    allocator->num_cache_lines--;
    return allocator->cache_lines[allocator->num_cache_lines];
}
