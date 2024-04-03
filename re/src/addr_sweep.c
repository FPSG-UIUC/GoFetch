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
    argv[2]: stride
    argv[3]: sweep times
    argv[4]: buffer boundary
    */
    // read arguments
    int core_id;
    sscanf(argv[1], "%d", &core_id);
    uint64_t stride;
    sscanf(argv[2], "%llx", &stride);
    size_t sweep_times;
    sscanf(argv[3], "%zu", &sweep_times);
    uint64_t buffer_boundary;
    sscanf(argv[4], "%llx", &buffer_boundary);

    // pin to core
    pin_cpu((size_t)core_id);
    printf("[+] core_id: %d\n", core_id);

    // set up kpc
    init_kpc();

    // Allocate memory for unify array
    printf("[+] stride: %#llx\n", stride);
    printf("[+] sweep_times: %zu\n", sweep_times);
    printf("[+] buffer_boundary: %#llx\n", buffer_boundary);
    size_t unify_size = stride * sweep_times + 2*MB;
    size_t unify_offset = 2*MB/sizeof(uint64_t);
    char unify_size_str[10];
    return_size(unify_size_str, unify_size);
    uint64_t* unify_buf_addr = 
        mmap((void*)buffer_boundary, unify_size, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert((uint64_t)unify_buf_addr == buffer_boundary);
    printf("[+] unify_buf_addr: %p (%s)\n", unify_buf_addr, unify_size_str);

    // Allocate memory for thrash array
    uint64_t *thrash_arr = mmap(0, SIZE_THRASH_ARRAY, PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE, -1, 0);

    // Fill data array with random data
    srand(time(NULL));
    for (int i = 0; i < unify_size / sizeof(uint64_t); i++) {
        unify_buf_addr[i] = rand() & (MSB_MASK - 1);
    }
    // Fill thrash array with zeros
    for (int i = 0; i < SIZE_THRASH_ARRAY / sizeof(uint64_t); i++) {
        thrash_arr[i] = rand() & (MSB_MASK - 1);
    }

    // Initial latency record array
    uint64_t latency_ptr_base_array[REPETITIONS];
    uint64_t latency_ptr_atk_array[REPETITIONS];

    // Measurement start
    uint64_t trash = 0;
    uint64_t latency_ptr = 0;
    for(int aop_idx=0; aop_idx<sweep_times; aop_idx++) {
        for(int target_idx=0; target_idx<sweep_times; target_idx++) {
            // skip conflict
            if(aop_idx == target_idx) {
                continue;
            }
            size_t aop_offset = unify_offset + aop_idx * stride / sizeof(uint64_t);
            size_t target_offset = unify_offset + target_idx * stride / sizeof(uint64_t);
            printf("[*] aop addr: %p (%d), target addr: %p (%d)\n", 
                &unify_buf_addr[aop_offset], aop_idx, 
                &unify_buf_addr[target_offset], target_idx);
            uint64_t mode = 0;
            for(int i=0; i<REPETITIONS*2; i++) {
                if(mode == 0) {
                    // atk mode
                    unify_buf_addr[aop_offset] = (uint64_t)&unify_buf_addr[target_offset];
                } else {
                    // base mode
                    unify_buf_addr[aop_offset] = rand() & (MSB_MASK - 1);
                }

                // flush cache
                trash = thrash_array(thrash_arr, SIZE_THRASH_ARRAY, trash);
                trash = busy_wait(10000, trash);

                // bring TLB entry
                mem_access(&unify_buf_addr[(target_offset+128) | (trash & MSB_MASK)], trash);

                // aop access pattern
                mem_access(&unify_buf_addr[aop_offset | (trash & MSB_MASK)], trash);

                // wait for DMP
                trash = busy_wait(1000, trash);

                // time access ptr
                kpc_time_load(&unify_buf_addr[target_offset | (trash & MSB_MASK)], latency_ptr, trash);

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
            char path_to_file_base[50];
            char path_to_file_atk[50];
            sprintf(path_to_file_base, "./out/base_%d_%d.txt", aop_idx, target_idx);
            sprintf(path_to_file_atk, "./out/atk_%d_%d.txt", aop_idx, target_idx);
            FILE *output_file_baseline = fopen(path_to_file_base, "w");
            FILE *output_file_aop = fopen(path_to_file_atk, "w");
            if (output_file_baseline == NULL || output_file_aop == NULL) {
                    perror("output files");
            }
            fprintf(output_file_baseline, "%p,%p\n", 
                &unify_buf_addr[target_offset], &unify_buf_addr[aop_offset]);
            fprintf(output_file_aop, "%p,%p\n",
                &unify_buf_addr[target_offset], &unify_buf_addr[aop_offset]);
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
        }
    }
    return 0;
}