#include <sys/mman.h>
#include <time.h>
#include "dmp.h"
#include "lib/eviction_set/sys_utils.h"
#include "lib/basics/arch.h"
#include "lib/basics/math_utils.h"
#include "lib/eviction_set/eviction_set_generation.h"
#include "lib/basics/cache_line_set.h"
#include "lib/eviction_set/eviction_set.h"

#define REPETITIONS 100


int main() {
    // pin core
    pin_cpu(4);

    // set up kpc
    init_kpc();
#ifdef __APPLE__
    configure_kpc();
#endif
    // allocate memory
    uint64_t* victim_addr = 
        mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, 
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    uint64_t *thrash_arr =
        mmap(0, SIZE_THRASH_ARRAY, PROT_READ | PROT_WRITE,
                MAP_ANON | MAP_PRIVATE, -1, 0);

    // Fill data array with random data
    srand(time(NULL));
    for (int i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++) {
        victim_addr[i] = rand() & (MSB_MASK - 1);
    }

    // Fill thrash array with random data
    for (int i = 0; i < SIZE_THRASH_ARRAY / sizeof(uint64_t); i++) {
        thrash_arr[i] = rand() & (MSB_MASK - 1);
    }

    // Initial latency record array
    uint64_t timer_overhead[REPETITIONS] = {0};
    uint64_t l1_hit[REPETITIONS] = {0};
    uint64_t l2_hit[REPETITIONS] = {0};
    uint64_t l2_miss[REPETITIONS] = {0};
    uint64_t dram_hit[REPETITIONS] = {0};

    // Trash variable
    uint64_t trash = 0;
    uint64_t latency = 0;

    // Test timer overhead
    printf("[+] Testing timer overhead\n");
    for(int i=0; i<REPETITIONS; i++) {
        trash = busy_wait(100, trash);
#ifdef __APPLE__
        MEM_BARRIER;
        latency = get_kpc_time();
        MEM_BARRIER;
        MEM_BARRIER;
        latency = get_kpc_time() - latency;
        MEM_BARRIER;
#else
        asm volatile(
            "dsb sy\n\t"
            "isb\n\t"
            "mrs x9, S3_2_c15_c0_0\n\t"
            "isb\n\t"
            "isb\n\t"
            "mrs x10, S3_2_c15_c0_0\n\t"
            "sub %[delay], x10, x9\n\t"
            : [delay] "=r" (latency)
            :
            : "x9", "x10");
#endif
        timer_overhead[i] = latency;
    }
    printf("[++] done\n");

    // Test L1 hit
    printf("[+] Testing L1 hit\n");
    for(int i=0; i<REPETITIONS; i++) {
        // access
        mem_access(victim_addr, trash);
        trash = busy_wait(100, trash);
        kpc_time_load(victim_addr, latency, trash);
        l1_hit[i] = latency;
    }
    printf("[++] done\n");

    // Test L2 hit
    printf("[+] Testing L2 hit\n");
    // Build Eviction Set
    cache_line_set_t* evset_line_l1 = NULL;
    eviction_set_t* evset_l1 = NULL;
    evset_line_l1 = find_L1_eviction_set((uint8_t*) victim_addr);
    evset_l1 = create_eviction_set(evset_line_l1);
    printf("[++] L1 Evset Generation Complete\n");
    for(int i=0; i<REPETITIONS; i++) {
        // evict
        traverse_eviction_set(evset_l1);
        trash = busy_wait(100, trash);
        kpc_time_load(victim_addr, latency, trash);
        l2_hit[i] = latency;
    }
    printf("[++] done\n");

    // Test L2 miss
    printf("[+] Testing L2 miss\n");
    // Build Eviction Set
    cache_line_set_t* evset_line_l2 = NULL;
    eviction_set_t* evset_l2 = NULL;
    evset_line_l2 = find_L2_eviction_set_using_timer((uint8_t*) victim_addr);
    evset_l2 = create_eviction_set(evset_line_l2);
    printf("[++] L2 Evset Generation Complete\n");
    for(int i=0; i<REPETITIONS; i++) {
        // evict
        traverse_eviction_set(evset_l2);
        trash = busy_wait(100, trash);
        kpc_time_load(victim_addr, latency, trash);
        l2_miss[i] = latency;
    }
    printf("[++] done\n");

    // Test DRAM hit
    printf("[+] Testing DRAM hit\n");
    for(int i=0; i<REPETITIONS; i++) {
        // evict
        trash = thrash_array(thrash_arr, SIZE_THRASH_ARRAY, trash);
        trash = busy_wait(100, trash);
        kpc_time_load(victim_addr, latency, trash);
        dram_hit[i] = latency;
    }
    printf("[++] done\n");

    // analyze data
    printf("---------Results---------\n");
    uint64_t timer_overhead_median = median_8B(timer_overhead, REPETITIONS);
    uint64_t timer_overhead_max = max_8B(timer_overhead, REPETITIONS);
    uint64_t timer_overhead_min = min_8B(timer_overhead, REPETITIONS);
    printf("[+] Timer overhead:\n");
    printf("[++] Median: %llu\n", timer_overhead_median);
    printf("[++] Max: %llu\n", timer_overhead_max);
    printf("[++] Min: %llu\n", timer_overhead_min);
    uint64_t l1_hit_median = median_8B(l1_hit, REPETITIONS);
    uint64_t l1_hit_max = max_8B(l1_hit, REPETITIONS);
    uint64_t l1_hit_min = min_8B(l1_hit, REPETITIONS);
    printf("[+] L1 hit:\n");
    printf("[++] Median: %llu\n", l1_hit_median);
    printf("[++] Max: %llu\n", l1_hit_max);
    printf("[++] Min: %llu\n", l1_hit_min);
    uint64_t l2_hit_median = median_8B(l2_hit, REPETITIONS);
    uint64_t l2_hit_max = max_8B(l2_hit, REPETITIONS);
    uint64_t l2_hit_min = min_8B(l2_hit, REPETITIONS);
    printf("[+] L2 hit:\n");
    printf("[++] Median: %llu\n", l2_hit_median);
    printf("[++] Max: %llu\n", l2_hit_max);
    printf("[++] Min: %llu\n", l2_hit_min);
    uint64_t l2_miss_median = median_8B(l2_miss, REPETITIONS);
    uint64_t l2_miss_max = max_8B(l2_miss, REPETITIONS);
    uint64_t l2_miss_min = min_8B(l2_miss, REPETITIONS);
    printf("[+] L2 miss:\n");
    printf("[++] Median: %llu\n", l2_miss_median);
    printf("[++] Max: %llu\n", l2_miss_max);
    printf("[++] Min: %llu\n", l2_miss_min);
    uint64_t dram_hit_median = median_8B(dram_hit, REPETITIONS);
    uint64_t dram_hit_max = max_8B(dram_hit, REPETITIONS);
    uint64_t dram_hit_min = min_8B(dram_hit, REPETITIONS);
    printf("[+] DRAM hit:\n");
    printf("[++] Median: %llu\n", dram_hit_median);
    printf("[++] Max: %llu\n", dram_hit_max);
    printf("[++] Min: %llu\n", dram_hit_min);
    return 0;
}