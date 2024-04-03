#include <sys/mman.h>
#include <time.h>
#include <assert.h>
#include "dmp.h"
#include "lib/eviction_set/sys_utils.h"
#include "lib/basics/arch.h"
#include "lib/basics/math_utils.h"

#define REPETITIONS 32


int main(int argc, char** argv) {
    /*
    argv[1]: core_id (0-3 e core, 4-7 p core)
    argv[2]: size of the victim array
    argv[3]: training length
    argv[4]: test ptr idx
    */
    // read arguments
    int core_id;
    sscanf(argv[1], "%d", &core_id);
    size_t victim_size;
    sscanf(argv[2], "%zu", &victim_size);
    int training_length;
    sscanf(argv[3], "%d", &training_length);
    int test_idx;
    sscanf(argv[4], "%d", &test_idx);

    // pin to core
    pin_cpu((size_t)core_id);
    printf("[+] core_id: %d\n", core_id);

    // set up kpc
    init_kpc();

    // Allocate memory for data array
    uint64_t* data_buf_addr = 
        mmap(NULL, SIZE_DATA_ARRAY, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("[+] data_buf_addr: %p\n", data_buf_addr);

    // Allocate memory for aop array
    char victim_size_str[10];
    return_size(victim_size_str, victim_size*sizeof(uint64_t));
    uint64_t* aop_addr = 
        mmap(NULL, victim_size*sizeof(uint64_t), PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("[+] aop_addr: %p\n", aop_addr);
    assert(ADDR_CHECK((uintptr_t)data_buf_addr, (uintptr_t)aop_addr));

    // Allocate memory for thrash array
    uint64_t *thrash_arr = mmap(0, SIZE_THRASH_ARRAY, PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE, -1, 0);

    // Fill data array with random data
    srand(time(NULL));
    for (int i = 0; i < SIZE_DATA_ARRAY / sizeof(uint64_t); i++) {
        data_buf_addr[i] = rand() & (MSB_MASK - 1);
    }
    // Fill aop array with random data
    for (int i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++) {
        aop_addr[i] = rand() & (MSB_MASK - 1);
    }
    // Fill thrash array with zeros
    for (int i = 0; i < SIZE_THRASH_ARRAY / sizeof(uint64_t); i++) {
        thrash_arr[i] = rand() & (MSB_MASK - 1);
    }

    // Test target setting
    printf("[+] Test target setting:\n");
    uint64_t trash = 0;
    uint64_t rnd_idx = RND_INIT;
    for(int i=0; i<victim_size; i++) {
        aop_addr[i] = (uint64_t)&data_buf_addr[rnd_idx*L2_LINE_SIZE/sizeof(uint64_t)];
        rnd_idx = prng(rnd_idx);
    }
    printf("[+++] test_idx: %d\n", test_idx);
    rnd_idx = RND_INIT;
    for(int i=0; i<test_idx+training_length; i++) {
        rnd_idx = prng(rnd_idx);
    }
    uint64_t test_offset = L2_LINE_SIZE * rnd_idx / sizeof(uint64_t);
    printf("[+++] test ptr: %#llx\n", (uint64_t)&data_buf_addr[test_offset]);

    // Initial latency record array
    uint64_t latency_ptr_base_array[REPETITIONS];
    uint64_t latency_ptr_atk_array[REPETITIONS];

    // Measurement start
    uint64_t latency_ptr = 0;
    uint64_t mode = 0;
    printf("[+] AoP setting:\n");
    printf("[+++] victim_size: %zu entries (%s)\n", victim_size, victim_size_str);
    printf("[+++] Training length: %d\n", training_length);
    for(int i=0; i<REPETITIONS*2; i++) {
        if(mode == 0) {
            // atk mode
            rnd_idx = RND_INIT;
            // skip training
            for(int aop_idx=0; aop_idx<victim_size; aop_idx++) {
                if(aop_idx >= training_length) {
                    aop_addr[aop_idx] = (uint64_t)&data_buf_addr[rnd_idx*L2_LINE_SIZE/sizeof(uint64_t)];
                }
                rnd_idx = prng(rnd_idx);
            }
        } else {
            // base mode
            for(int aop_idx=0; aop_idx<victim_size; aop_idx++) {
                if(aop_idx >= training_length) {
                    aop_addr[aop_idx] = rand() & (MSB_MASK - 1);
                }
            }
        }

        // flush cache
        trash = thrash_array(thrash_arr, SIZE_THRASH_ARRAY, trash);
        trash = busy_wait(10000, trash);

        // bring TLB entry
        mem_access(&data_buf_addr[(test_offset+128) | (trash & MSB_MASK)], trash);

        // aop access pattern
        trash = aopstream_array(aop_addr, training_length, trash);

        // wait for DMP
        trash = busy_wait(1000, trash);

        // time access ptr
        kpc_time_load(&data_buf_addr[test_offset | (trash & MSB_MASK)], latency_ptr, trash);

        if(mode == 0) {
            // atk mode
            latency_ptr_atk_array[i/2] = latency_ptr;
        } else {
            // base mode
            latency_ptr_base_array[i/2] = latency_ptr;
        }
        mode = !(mode | (trash & MSB_MASK));
    }

    // Store measurements
    FILE *output_file_baseline = fopen("./out/base.txt", "w");
    FILE *output_file_aop = fopen("./out/atk.txt", "w");
    if (output_file_baseline == NULL || output_file_aop == NULL) {
            perror("output files");
    }
    fprintf(output_file_baseline, "test\n");
    fprintf(output_file_aop, "test\n");
    for(int i=0; i<REPETITIONS; i++) {
        fprintf(output_file_baseline, "%llu\n",
            latency_ptr_base_array[i]);
        fprintf(output_file_aop, "%llu\n",
            latency_ptr_atk_array[i]);
    }

    // Clean up
    fclose(output_file_baseline);
    fclose(output_file_aop);

    // Print result
    printf("[+] Result:\n");
    uint64_t ptr_atk_min = min_8B(latency_ptr_atk_array, REPETITIONS);
    uint64_t ptr_atk_median = median_8B(latency_ptr_atk_array, REPETITIONS);
    printf("[+++] ATK:\n");
    printf("[+++++] MIN: %llu\n", ptr_atk_min);
    printf("[+++++] MEDIAN: %llu\n", ptr_atk_median);
    uint64_t ptr_base_min = min_8B(latency_ptr_base_array, REPETITIONS);
    uint64_t ptr_base_median = median_8B(latency_ptr_base_array, REPETITIONS);
    printf("[+++] BASE:\n");
    printf("[+++++] MIN: %llu\n", ptr_base_min);
    printf("[+++++] MEDIAN: %llu\n", ptr_base_median);
    return 0;
}