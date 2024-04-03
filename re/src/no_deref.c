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
    argv[3]: number of pointers
    argv[4]: pointer start
    argv[5]: test ptr idx
    argv[6]: test offset
    argv[7]: set bit position
    argv[8]: number of touched entries
    argv[9]: start touched entry
    */
    // read arguments
    int core_id;
    sscanf(argv[1], "%d", &core_id);
    size_t victim_size;
    sscanf(argv[2], "%zu", &victim_size);
    int num_ptr;
    sscanf(argv[3], "%d", &num_ptr);
    int ptr_start;
    sscanf(argv[4], "%d", &ptr_start);
    int test_idx;
    sscanf(argv[5], "%d", &test_idx);
    int test_offset_p;
    sscanf(argv[6], "%d", &test_offset_p);
    int set_bit_pos;
    sscanf(argv[7], "%d", &set_bit_pos);
    size_t num_touch;
    sscanf(argv[8], "%zu", &num_touch);
    int touch_start;
    sscanf(argv[9], "%d", &touch_start);

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
    for (int i = 0; i < victim_size; i++) {
        aop_addr[i] = rand() & (MSB_MASK - 1);
    }
    // Fill thrash array with zeros
    for (int i = 0; i < SIZE_THRASH_ARRAY / sizeof(uint64_t); i++) {
        thrash_arr[i] = rand() & (MSB_MASK - 1);
    }

    // Test target setting
    printf("[+] Test target setting:\n");
    printf("[+++] test_idx: %d\n", test_idx);
    uint64_t trash = 0;
    uint64_t rnd_idx = RND_INIT;
    for(int i=0; i<test_idx; i++) {
        rnd_idx = prng(rnd_idx);
    }
    uint64_t test_offset = L2_LINE_SIZE * rnd_idx / sizeof(uint64_t);
    uint64_t bit_flip_mask = 0;
    if(set_bit_pos <= 63) {
        bit_flip_mask = 0x1LLU << set_bit_pos;
        printf("[+++] Position of bit flip: %d\n", set_bit_pos);
    } else {
        printf("[+++] No bit flip\n");
    }
    printf("[+++] test offset: %d L2 lines\n", test_offset_p);
    printf("[+++] stored ptr: %#llx\n", (uint64_t)&data_buf_addr[test_offset] | bit_flip_mask);
    printf("[+++] test ptr: %#llx\n", (uint64_t)&data_buf_addr[test_offset + test_offset_p*L2_LINE_SIZE/sizeof(uint64_t)]);

    // Initial latency record array
    uint64_t latency_ptr_base_array[REPETITIONS];
    uint64_t latency_ptr_atk_array[REPETITIONS];

    // Measurement start
    uint64_t latency_ptr = 0;
    uint64_t mode = 0;
    printf("[+] AoP setting:\n");
    printf("[+++] victim_size: %zu entries (%s)\n", victim_size, victim_size_str);
    printf("[+++] Number of pointers: %d\n", num_ptr);
    printf("[+++] Pointer start idx: %d\n", ptr_start);
    printf("[+++] Number of touched entries: %zu\n", num_touch);
    printf("[+++] Start touched entry: %d\n", touch_start);
    for(int i=0; i<REPETITIONS*2; i++) {
        if(mode == 0) {
            // atk mode
            rnd_idx = RND_INIT;
            for(int aop_idx=0; aop_idx<num_ptr; aop_idx++) {
                aop_addr[aop_idx+ptr_start] = (uint64_t)&data_buf_addr[rnd_idx*L2_LINE_SIZE/sizeof(uint64_t)] | bit_flip_mask;
                rnd_idx = prng(rnd_idx);
            }
        } else {
            // base mode
            for(int aop_idx=0; aop_idx<num_ptr; aop_idx++) {
                aop_addr[aop_idx+ptr_start] = rand() & (MSB_MASK - 1);
            }
        }

        // flush cache
        trash = thrash_array(thrash_arr, SIZE_THRASH_ARRAY, trash);
        trash = busy_wait(10000, trash);

        // bring TLB entry
        mem_access(&data_buf_addr[(test_offset+128) | (trash & MSB_MASK) + test_offset_p*L2_LINE_SIZE/sizeof(uint64_t)], trash);

        // aop access pattern
        trash = datastream_array(&aop_addr[touch_start | (trash & MSB_MASK)], num_touch, trash);

        // wait for DMP
        trash = busy_wait(1000, trash);

        // time access ptr
        kpc_time_load(&data_buf_addr[test_offset | (trash & MSB_MASK) + test_offset_p*L2_LINE_SIZE/sizeof(uint64_t)], latency_ptr, trash);

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
    assert(ptr_base_min > L2_MISS_MIN_LATENCY);
    return 0;
}