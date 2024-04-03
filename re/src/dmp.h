#ifndef __DMP_H__
#define __DMP_H__
#include <stdint.h>
#include "lib/basics/arch.h"
#define RND_INIT 8

// Use a Lehmer RNG as PRNG
// https://en.wikipedia.org/wiki/Lehmer_random_number_generator
#define PNRG_a 75
#define PRNG_m 8388617
#define prng(x) ((PNRG_a * x) % PRNG_m)

#define SIZE_DATA_ARRAY (PRNG_m * L2_LINE_SIZE)
#define SIZE_THRASH_ARRAY ((L1_SIZE + L2_SIZE) * 8)

#define ADDR_CHECK(addr1, addr2) ((addr1 >> 32) == (addr2 >> 32))

// define thrash array
// #define thrash_array(size_of_thrash_array, thrash_arr, trash) ({\
//     for (uint32_t thrash_idx = 0; \
//         thrash_idx < size_of_thrash_array / sizeof(uint64_t) - 2; thrash_idx++) { \
//         trash += (thrash_arr[thrash_idx] ^ trash) & 0b1111; \
//         trash += (thrash_arr[thrash_idx + 1] ^ trash) & 0b1111; \
//         trash += (thrash_arr[thrash_idx + 2] ^ trash) & 0b1111; \
//     }\
// })
uint64_t thrash_array(uint64_t* thrash_arr, uint32_t size_of_thrash_array, \
    uint64_t trash) {
    // outer loop for set
    for(uint32_t page_offset=0; page_offset<PAGE_SIZE; \
        page_offset+=L1_LINE_SIZE) {
        // inner loop for ways
        for(uint32_t page_idx=0; page_idx<(size_of_thrash_array - 2*PAGE_SIZE); page_idx+=PAGE_SIZE) {
            trash += (thrash_arr[(page_idx+page_offset)/sizeof(uint64_t)] ^ trash) & 0b1111;
            trash += (thrash_arr[(page_idx+page_offset+PAGE_SIZE)/sizeof(uint64_t)] ^ trash) & 0b1111;
            trash += (thrash_arr[(page_idx+page_offset+2*PAGE_SIZE)/sizeof(uint64_t)] ^ trash) & 0b1111;
        }
    }
    return trash;
}

// data stream access pattern
uint64_t datastream_array(uint64_t* victim_addr, \
    size_t victim_size, uint64_t trash) {

    volatile uint64_t *victim_array = victim_addr;

    for(size_t i=0; i<victim_size; i++) {
        trash += victim_array[i % victim_size] & MSB_MASK;  // mask to guarantee zero
    }

    return trash;
}

// aop stream access pattern (augury)
uint64_t aopstream_array(uint64_t* aop_addr, \
    int num_of_train_pointers, uint64_t trash) {

    volatile uint64_t **aop = (uint64_t**)aop_addr;

    // Training loop
    for (int j = 0; j < num_of_train_pointers; j++) {
        trash += *aop[j % num_of_train_pointers] & MSB_MASK;
    }

    return trash;
}

#endif // __DMP_H__