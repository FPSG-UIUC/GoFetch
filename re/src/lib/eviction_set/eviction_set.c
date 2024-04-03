#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "eviction_set.h"
#include "sys_utils.h"

#include "../basics/arch.h"
#include "../basics/allocator.h"
#include "../basics/cache_line_set.h"
#include "../basics/linked_list.h"
#include "../basics/math_utils.h"

uint8_t global_junk = 0;

eviction_set_t* create_eviction_set(cache_line_set_t* cache_line_set) {
    eviction_set_t* new_eviction_set = (eviction_set_t*)malloc(sizeof(eviction_set_t));
    new_eviction_set->list_of_cachelines = create_linked_list();

    // when we create an eviction set with a list of congruent addresses, each eviction set element
    // is a linked_list_t node. Each node is 0x10 (16) byte, containing one forward pointer and backward pointer
    // so we want each node to be L1 cache line aligned

    for (int i = 0; i < cache_line_set->num_cache_lines; i++)  {
        /*size_t l1_line_aligned_addr = cache_line_set->cache_lines[i] - */
                                      /*(cache_line_set->cache_lines[i] % L1_LINE_SIZE);*/
        size_t l1_line_aligned_addr = cache_line_set->cache_lines[i] -
                                      (cache_line_set->cache_lines[i] % sizeof(node_t));
        /*size_t l1_line_aligned_addr = cache_line_set->cache_lines[i];*/
        add_preallocated_node_to_linked_list(new_eviction_set->list_of_cachelines, (node_t*)l1_line_aligned_addr);
    }

    return new_eviction_set;
}

void delete_eviction_set(eviction_set_t *eviction_set) {
    delete_linked_list(eviction_set->list_of_cachelines);
    free(eviction_set);
}

void print_eviction_set(eviction_set_t* eviction_set) {
    int num_nodes = eviction_set->list_of_cachelines->num_nodes;
    printf("# cache lines: %d\n", num_nodes);
    if (num_nodes == 0)
        return;

    node_t* head = eviction_set->list_of_cachelines->head;
    node_t* tail = eviction_set->list_of_cachelines->tail;
    node_t* node = head;
    int i = 0;
    while (1) {
        printf("%d: addr: %p (%p, %p), next: %p, last: %p\n", 
                i, node, &(node->next), &(node->last), node->next, node->last);
        if (node == tail)
            break;
        node = node->next;
        i = i + 1;
    }
}

uint8_t traverse_eviction_set(eviction_set_t *eviction_set) {
    if ( __builtin_expect(!eviction_set->list_of_cachelines->head, 0) )
        return 0;

    volatile node_t* iter;
    volatile node_t* lagging_iter;
    int64_t num_cache_lines;
    node_t* head = eviction_set->list_of_cachelines->head;
    node_t* tail = eviction_set->list_of_cachelines->tail;
    int num_nodes = eviction_set->list_of_cachelines->num_nodes;

    for (int i = 0; i < 2; i++) {
        // Perform a forward traversal over two linked lists with one cursor
        // lagging behind n steps to perform dual-chasing
        iter = head;
        lagging_iter = head;
        num_cache_lines = num_nodes;

        // repeat "iter = iter->next" 8 times
        asm volatile (
            "LDR %[iter], [%[iter]]\n\t"    // 1st
            "LDR %[iter], [%[iter]]\n\t"    // 2nd
            "LDR %[iter], [%[iter]]\n\t"
            "LDR %[iter], [%[iter]]\n\t"
            "LDR %[iter], [%[iter]]\n\t"
            "LDR %[iter], [%[iter]]\n\t"
            "LDR %[iter], [%[iter]]\n\t"
            "LDR %[iter], [%[iter]]\n\t"    // 8th
            : [iter] "+r" (iter)
            : : );

        /*asm volatile ("isb\n\t"); // this isb seems to be critical*/
        asm volatile ("dsb sy\n\t");

        // iterate over eviction set using iter and lagging iter
        asm volatile (
            "L_fwd_traverse%=:\n\t"
            "LDR %[lagging_iter], [%[lagging_iter]]\n\t"
            "CBZ %[iter], L_skip_iter_in_fwd%=\n\t" // if iter reaches the end
            "LDR %[iter], [%[iter]]\n\t"
            "L_skip_iter_in_fwd%=:\n\t"
            "SUB %[num_cache_lines], %[num_cache_lines], #1\n\t"
            "CBNZ %[num_cache_lines], L_fwd_traverse%=\n\t"
            : [iter] "+r" (iter), [lagging_iter] "+r" (lagging_iter),
              [num_cache_lines] "+r" (num_cache_lines)
            : : );

        asm volatile ("dsb sy\n\t");

        // Perform a backward traversal over two linked lists with one cursor
        // lagging behind n steps to perform dual-chasing
        iter = tail;
        lagging_iter = tail;
        num_cache_lines = num_nodes;

        // repeat "iter = iter->last" 8 times
        asm volatile (
            "LDR %[iter], [%[iter], #8]\n\t" // 1st
            "LDR %[iter], [%[iter], #8]\n\t" // 2nd
            "LDR %[iter], [%[iter], #8]\n\t"
            "LDR %[iter], [%[iter], #8]\n\t"
            "LDR %[iter], [%[iter], #8]\n\t"
            "LDR %[iter], [%[iter], #8]\n\t"
            "LDR %[iter], [%[iter], #8]\n\t"
            "LDR %[iter], [%[iter], #8]\n\t" // 8th
            : [iter] "+r" (iter)
            : : );

        /*asm volatile ("isb\n\t"); // this isb seems to be critical*/
        asm volatile ("dsb sy\n\t");

        // iterater over eviction set with iter and lagging_iter
        asm volatile (
            "L_bwd_traverse%=:\n\t"
            "LDR %[lagging_iter], [%[lagging_iter], #8]\n\t"
            "CBZ %[iter], L_skip_iter_in_bwd%=\n\t" // if iter reaches the end
            "LDR %[iter], [%[iter], #8]\n\t"
            "L_skip_iter_in_bwd%=:\n\t"
            "SUB %[num_cache_lines], %[num_cache_lines], #1\n\t"
            "CBNZ %[num_cache_lines], L_bwd_traverse%="
            : [iter] "+r" (iter), [lagging_iter] "+r" (lagging_iter),
              [num_cache_lines] "+r" (num_cache_lines)
            : : );

        asm volatile ("dsb sy\n\t");
    }

    return 0;
}

static inline uint64_t evict_and_time_once(uint8_t* victim_addr, eviction_set_t* eviction_set) {
    // preload the victim_addr
    uint64_t latency;
    volatile uint8_t junk = 0;
    asm volatile (
            "dsb sy\n\t"
            "ldrb %w[out], [%[addr]]\n\t"
            "dsb sy\n\t"
            : [out] "=r" (junk)
            : [addr] "r" (victim_addr));

    asm volatile ("dsb sy\n\t");
    junk ^= traverse_eviction_set(eviction_set);
    asm volatile ("dsb sy\n\t");

    kpc_time_load(victim_addr, latency, junk);

    global_junk ^= junk;
    return latency;
}

uint64_t evict_and_time(uint8_t* victim_addr, cache_line_set_t* cache_line_set) {

    uint64_t timings[NUM_TESTS];

    for (int i = 0; i < NUM_TESTS; i++) {
        // Randomize the set of cache lines
        shuffle(cache_line_set->cache_lines, cache_line_set->num_cache_lines, sizeof(size_t));

        // Construct an eviction set. allocator field is ignored
        eviction_set_t* eviction_set = create_eviction_set(cache_line_set);
        /*print_eviction_set(eviction_set);*/

        // Evict and time the victim access
        timings[i] = evict_and_time_once(victim_addr, eviction_set);

        delete_eviction_set(eviction_set);
    }

    sort(timings, NUM_TESTS, sizeof(uint64_t));

    return timings[NUM_TESTS / 2];
}
