#ifndef _C_AUGURY_H
#define _C_AUGURY_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>


void constant_time_cond_swap_64(uint64_t mask, uint64_t *a,
                                uint64_t *b);

void pin_cpu(size_t core_ID);

uint64_t c_sleep(uint64_t duration, uint64_t __trash);

uint64_t c_thrash_cache(uint64_t* thrash_addr, \
    uint32_t size_of_thrash_array, uint64_t __trash);

uint64_t flush_evset(uint64_t* evset_start, uint32_t num_of_ptrs);

#endif // _C_AUGURY_H