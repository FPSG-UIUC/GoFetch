#ifndef __SYS_UTILS_H__
#define __SYS_UTILS_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "../basics/arch.h"

#ifdef __APPLE__
void configure_kpc(void);
uint64_t get_kpc_time(void);
#endif

void init_kpc(void);

uint64_t get_time_mach(uint64_t zero_dependency);

void pin_cpu(size_t core_ID);

uint64_t busy_wait(uint64_t iter, uint64_t trash);

void return_size(char* output, size_t bytes);

#define INST_SYNC asm volatile("ISB")
#define DATA_SYNC asm volatile("DSB SY")

#define MEM_BARRIER \
	DATA_SYNC;      \
	INST_SYNC

#define mem_access(addr, junk) ({\
        asm volatile( \
            "ldrb %w[trash], [%[victim_addr]]\n\t" \
            : [trash] "=r" (junk) \
            : [victim_addr] "r" (addr) \
            : ); \
})

#ifdef __linux__
#define kpc_time_load(addr, latency, junk) ({\
        asm volatile( \
            "dsb sy\n\t" \
            "isb\n\t" \
            "mrs x9, S3_2_c15_c0_0\n\t" \
            "isb\n\t" \
            "ldrb %w[trash], [%[victim_addr]]\n\t" \
            "isb\n\t" \
            "mrs x10, S3_2_c15_c0_0\n\t" \
            "sub %[delay], x10, x9\n\t" \
            : [delay] "=r" (latency), [trash] "=r" (junk) \
            : [victim_addr] "r" (addr) \
            : "x9", "x10"); \
})
#else
#define kpc_time_load(addr, latency, junk) ({\
    MEM_BARRIER; \
    latency = get_kpc_time(); \
    MEM_BARRIER; \
    mem_access(addr, junk); \
    MEM_BARRIER; \
    latency = get_kpc_time() - latency; \
    MEM_BARRIER; \
})

#endif

#endif
