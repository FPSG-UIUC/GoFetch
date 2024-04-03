#include <sys/mman.h>
#include <time.h>
#include <assert.h>
#include "dmp.h"
#include "lib/eviction_set/sys_utils.h"
#include "lib/basics/arch.h"
#include "lib/basics/math_utils.h"
#include "lib/eviction_set/eviction_set_generation.h"
#include "lib/basics/cache_line_set.h"
#include "lib/eviction_set/eviction_set.h"

#define REPETITIONS 512


int main(int argc, char** argv) {
    /*
    argv[1]: core_id (0-3 e core, 4-7 p core)
    argv[2]: test ptr idx
    argv[3]: number of unique pointers
    argv[4]: L1 / L2 evict for aop (1: L1, 2: L2)
    argv[5]: pre-cached to L2 cache (0: no, 1: yes)
    */
    // read arguments
    int core_id;
    sscanf(argv[1], "%d", &core_id);
    int test_idx;
    sscanf(argv[2], "%d", &test_idx);
    int num_unique_ptr;
    sscanf(argv[3], "%d", &num_unique_ptr);
    int evict_aop_flag;
    sscanf(argv[4], "%d", &evict_aop_flag);
    int L2_pre_cached;
    sscanf(argv[5], "%d", &L2_pre_cached);

    // pin to core
    pin_cpu((size_t)core_id);

    // set up kpc
    init_kpc();

    // Allocate memory for data array
    uint64_t* data_buf_addr = 
        mmap(NULL, SIZE_DATA_ARRAY, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // Allocate memory for aop array (one page)
    uint64_t* aop_addr = 
        mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // Allocate memory for reset array (one page)
    uint64_t* reset_addr = 
        mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // Allocate memory for thrash array
    uint64_t *thrash_arr = mmap(0, SIZE_THRASH_ARRAY, PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE, -1, 0);

    printf("[+] data_buf_addr: %p\n", data_buf_addr);
    printf("[+] aop_addr: %p\n", aop_addr);
    assert(ADDR_CHECK((uintptr_t)data_buf_addr,(uintptr_t)aop_addr));

    // Fill data array with random data
    srand(time(NULL));
    for (int i = 0; i < SIZE_DATA_ARRAY / sizeof(uint64_t); i++) {
        data_buf_addr[i] = rand() & (MSB_MASK - 1);
    }
    // Fill aop array with random data
    for (int i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++) {
        aop_addr[i] = rand() & (MSB_MASK - 1);
    }
    // Fill reset array with random data
    for (int i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++) {
        reset_addr[i] = rand() & (MSB_MASK - 1);
    }
    // Fill thrash array with random data
    for (int i = 0; i < SIZE_THRASH_ARRAY / sizeof(uint64_t); i++) {
        thrash_arr[i] = rand() & (MSB_MASK - 1);
    }

    // avoid reset and aop array belong to same set
    reset_addr = &reset_addr[16 * 8];
    printf("[+] reset_addr: %p\n", reset_addr);
    assert(ADDR_CHECK((uintptr_t)data_buf_addr, (uintptr_t)reset_addr));

    // Initial latency record array
    uint64_t latency_ptr_atk_array[REPETITIONS];
    uint64_t latency_aop_atk_array[REPETITIONS];

    // Test target setting
    uint64_t trash = 0;
    uint64_t rnd_idx = RND_INIT;
    for(int i=0; i<test_idx; i++) {
        rnd_idx = prng(rnd_idx);
    }
    uint64_t test_offset = L2_LINE_SIZE * rnd_idx / sizeof(uint64_t);
    printf("[+] test ptr: %p\n", &data_buf_addr[test_offset]);
    uint64_t reset_offset;

    // Evset generation
    // Build Eviction Set
    cache_line_set_t* evset_line_ptr = NULL;
    eviction_set_t* evset_ptr = NULL;
    cache_line_set_t* evset_line_aop_lower = NULL;
    eviction_set_t* evset_aop_lower = NULL;
    cache_line_set_t* evset_line_aop_upper = NULL;
    eviction_set_t* evset_aop_upper = NULL;
    cache_line_set_t* evset_line_reset = NULL;
    eviction_set_t* evset_reset = NULL;
    // Evset for aop
    if(evict_aop_flag == 1) {
        printf("[+] Evict aop out of L1\n");
        evset_line_aop_lower = find_L1_eviction_set((uint8_t*) aop_addr);
        evset_aop_lower = create_eviction_set(evset_line_aop_lower);
    } else if (evict_aop_flag == 2) {
        printf("[+] Evict aop out of L2\n");
        evset_line_aop_lower = find_L2_eviction_set_using_timer((uint8_t*) aop_addr);
        evset_aop_lower = create_eviction_set(evset_line_aop_lower);
        evset_line_aop_upper = copy_cache_line_set(evset_line_aop_lower, ((size_t) aop_addr & 0x3f80) + 64);
        evset_aop_upper = create_eviction_set(evset_line_aop_upper);
    } else {
        printf("[+] Only L1 or L2 evict options\n");
        exit(1);
    }
    // Evset for ptr
    evset_line_ptr = find_L2_eviction_set_using_timer((uint8_t*) &data_buf_addr[test_offset]);
    evset_ptr = create_eviction_set(evset_line_ptr);
    // Evset for reset
    evset_line_reset = find_L2_eviction_set_using_timer((uint8_t*) reset_addr);
    evset_reset = create_eviction_set(evset_line_reset);

    // Test history table
    uint64_t latency_ptr = 0;
    uint64_t latency_aop = 0;
    uint64_t latency_ptr_dummy = 0;
    uint64_t latency_aop_dummy = 0;
    aop_addr[0] = (uint64_t)(&data_buf_addr[test_offset]);
    if(L2_pre_cached == 1) {
        printf("[+] Pre-cached to L2 cache\n");
    }
    printf("[+] Num of dummy ptr: %d\n", num_unique_ptr);
    printf("[+] Measurement Start!\n");
    int max_wait = 60; // we want to at most spend 20 seconds to get enough number of activation
    time_t start, end;
    time(&start);
    trash = thrash_array(thrash_arr, SIZE_THRASH_ARRAY, trash);
    trash = busy_wait(10000, trash);
    for(int i=0; i<REPETITIONS; i++) {
        // evict aop
        if(evict_aop_flag == 1) {
            MEM_BARRIER;
            traverse_eviction_set(evset_aop_lower);
            MEM_BARRIER;
        } else {
            MEM_BARRIER;
            traverse_eviction_set(evset_aop_lower);
            traverse_eviction_set(evset_aop_upper);
            MEM_BARRIER;
        }

        if(L2_pre_cached == 1) {
            asm volatile("isb sy\n\t");
            mem_access(&aop_addr[8 | (trash & MSB_MASK)], trash);
            asm volatile("isb sy\n\t");
        }

        // evict ptr
        MEM_BARRIER;
        traverse_eviction_set(evset_ptr);
        MEM_BARRIER;

        // reset
        int num_reset = 0;
        while(num_reset < num_unique_ptr) {
            rnd_idx = prng(rnd_idx | (trash & MSB_MASK));
            reset_offset = L2_LINE_SIZE * rnd_idx / sizeof(uint64_t);
            *reset_addr = (uint64_t)(&data_buf_addr[reset_offset | (trash & MSB_MASK)]);
            MEM_BARRIER;
            traverse_eviction_set(evset_reset);
            MEM_BARRIER;
            trash = busy_wait(100000, trash);
            mem_access(&data_buf_addr[(reset_offset+128) | (trash & MSB_MASK)], trash);
            kpc_time_load(&reset_addr[0 | (trash & MSB_MASK)], latency_aop_dummy, trash);
            trash = busy_wait(1000, trash);
            kpc_time_load(&data_buf_addr[reset_offset | (trash & MSB_MASK)], latency_ptr_dummy, trash);
            asm volatile("isb sy\n\t");
            if((latency_ptr_dummy < L2_MISS_MIN_LATENCY) && (latency_aop_dummy > L2_MISS_MIN_LATENCY)) {
                num_reset++;
            }
            // printf("[+] reset %d: ptr->%llu, aop->%llu\n", num_reset, latency_ptr_dummy, latency_aop_dummy);
            time(&end);
            int sec = difftime(end, start);
            if (sec > max_wait) {
                fprintf(stderr, "PANIC: takes >60 seconds reducing the eviction set. STOP.\n");
                exit(1);
            }
        }

        // access aop
        trash = busy_wait(100000, trash);
        // bring TLB entry
        mem_access(&data_buf_addr[(test_offset+128) | (trash & MSB_MASK)], trash);
        kpc_time_load(&aop_addr[0 | (trash & MSB_MASK)], latency_aop, trash);
        trash = busy_wait(1000, trash);

        // time access ptr
        kpc_time_load(&data_buf_addr[test_offset | (trash & MSB_MASK)], latency_ptr, trash);

        latency_ptr_atk_array[i] = latency_ptr;
        latency_aop_atk_array[i] = latency_aop;
        // printf("[+] ATK: %d, latency_ptr: %llu, latency_aop: %llu\n", i, latency_ptr, latency_aop);
    }

    // Store measurements
    FILE *output_file_atk = fopen("./out/atk.txt", "w");
    if (output_file_atk == NULL) {
            perror("output files");
    }
    fprintf(output_file_atk, "ptr,aop\n");
    for(int i=0; i<REPETITIONS; i++) {
        fprintf(output_file_atk, "%llu,%llu\n",
            latency_ptr_atk_array[i], latency_aop_atk_array[i]);
    }

    // Clean up
    fclose(output_file_atk);

    // Print result
    int num_l2_hit = 0;
    for(int i=0; i<REPETITIONS; i++) {
        if(latency_ptr_atk_array[i] < L2_MISS_MIN_LATENCY) {
            num_l2_hit++;
        }
    }

    uint64_t ptr_atk_min = min_8B(latency_ptr_atk_array, REPETITIONS);
    uint64_t ptr_atk_median = median_8B(latency_ptr_atk_array, REPETITIONS);
    printf("[+] ATK PTR:\n");
    printf("[++] MIN: %llu\n", ptr_atk_min);
    printf("[++] MEDIAN: %llu\n", ptr_atk_median);
    printf("[++] NUM L2 HIT: %d\n", num_l2_hit);
    uint64_t aop_atk_min = min_8B(latency_aop_atk_array, REPETITIONS);
    uint64_t aop_atk_median = median_8B(latency_aop_atk_array, REPETITIONS);
    printf("[+] ATK AOP:\n");
    printf("[++] MIN: %llu\n", aop_atk_min);
    printf("[++] MEDIAN: %llu\n", aop_atk_median);
    return 0;
}