#include <sys/mman.h>
#include <time.h>
#include <assert.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#include <stdbool.h>
#endif
#include "dmp.h"
#include "lib/eviction_set/sys_utils.h"
#include "lib/basics/arch.h"
#include "lib/basics/math_utils.h"
#include "lib/eviction_set/eviction_set_generation.h"
#include "lib/basics/cache_line_set.h"
#include "lib/eviction_set/eviction_set.h"

#define REPETITIONS 512

#ifdef __APPLE__
bool is_DIT_supported(void) {
    static int has_DIT = -1;
    if (has_DIT == -1) {
        size_t has_DIT_size = sizeof(has_DIT);
        if (sysctlbyname("hw.optional.arm.FEAT_DIT", &has_DIT, &has_DIT_size, NULL, 0) == -1) {
            has_DIT = 0;
        }
    }
    return has_DIT;
}

bool get_DIT_enabled(void) {
    return (__builtin_arm_rsr64("dit") >> 24) & 1;
}
#endif

int main(int argc, char** argv) {
    /*
    argv[1]: DIT set (0 - unset, 1 - set)
    */
    // read arguments
    int dit;
    sscanf(argv[1], "%d", &dit);

#ifdef __APPLE__
    if (is_DIT_supported()) {
        printf("[+] DIT is supported.\n");
        if(dit == 1) {
            printf("Setting DIT\n");
            __builtin_arm_wsr64("DIT", 1);
        } else if (dit == 0) {
            printf("Clearing DIT\n");
            __builtin_arm_wsr64("DIT", 0);
        } else {
            printf("Invalid flag\n");
            return 1;
        }
        assert(get_DIT_enabled() == dit);   
    } else {
        printf("[+] DIT is not supported.\n");
    }
#else
    printf("Platforms other than macOS.\n");
#endif

    // pin to core
    pin_cpu(4);

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
    // Fill thrash array with random data
    for (int i = 0; i < SIZE_THRASH_ARRAY / sizeof(uint64_t); i++) {
        thrash_arr[i] = rand() & (MSB_MASK - 1);
    }

    // Initial latency record array
    uint64_t latency_ptr_atk_array[REPETITIONS];
    uint64_t latency_aop_atk_array[REPETITIONS];

    // Test target setting
    uint64_t trash = 0;
    uint64_t rnd_idx = RND_INIT;
    uint64_t test_offset;

    // Evset generation
    // Build Eviction Set
    cache_line_set_t* evset_line_aop = NULL;
    eviction_set_t* evset_aop = NULL;
    // Evset for aop
    evset_line_aop = find_L2_eviction_set_using_timer((uint8_t*) aop_addr);
    evset_aop = create_eviction_set(evset_line_aop);

    // Test history table
    uint64_t latency_ptr = 0;
    uint64_t latency_aop = 0;
    printf("[+] Measurement Start!\n");
    trash = thrash_array(thrash_arr, SIZE_THRASH_ARRAY, trash);
    trash = busy_wait(10000, trash);
    for(int i=0; i<REPETITIONS; i++) {
        test_offset = L2_LINE_SIZE * rnd_idx / sizeof(uint64_t);
        *aop_addr = (uint64_t)(&data_buf_addr[test_offset | (trash & MSB_MASK)]);
        MEM_BARRIER;
        traverse_eviction_set(evset_aop);
        MEM_BARRIER;
        trash = busy_wait(100000, trash);
        mem_access(&data_buf_addr[(test_offset+128) | (trash & MSB_MASK)], trash);
        kpc_time_load(&aop_addr[0 | (trash & MSB_MASK)], latency_aop, trash);
        trash = busy_wait(10000, trash);
        kpc_time_load(&data_buf_addr[test_offset | (trash & MSB_MASK)], latency_ptr, trash);
        asm volatile("isb sy\n\t");

        latency_ptr_atk_array[i] = latency_ptr;
        latency_aop_atk_array[i] = latency_aop;
        rnd_idx = prng(rnd_idx | (trash & MSB_MASK));
        // printf("[+] ATK: %d, latency_ptr: %llu, latency_aop: %llu\n", i, latency_ptr, latency_aop);
    }

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
    if ((aop_atk_min > L2_MISS_MIN_LATENCY) && (ptr_atk_median < L2_MISS_MIN_LATENCY)) {
        printf("Detect DMP signals!!\n");
    } else if (aop_atk_min < L2_MISS_MIN_LATENCY) {
        printf("AoP is not successfully evicted, retry.\n");
    } else {
        printf("No DMP signals!!\n");
    }
    return 0;
}