#ifndef __ARCH_H__
#define __ARCH_H__

// uncomment below for M2 and M3
// #define M2 0

#define KB 1024ULL
#define MB (1024*KB)

#define PAGE_SIZE               (16 * KB)

#define M1_L2_NWAYS     12
#define M2_L2_NWAYS     16
#define M1_L2_SIZE      (12 * MB)
#define M2_L2_SIZE      (16 * MB)

#define L1_NWAYS        8
#define L1_LINE_SIZE    64
#ifdef M2
#define L2_NWAYS        M2_L2_NWAYS // M2 or M3
#define L2_SIZE         M2_L2_SIZE // M2 or M3
#else
#define L2_NWAYS        M1_L2_NWAYS // M1
#define L2_SIZE         M1_L2_SIZE // M1
#endif
#define L2_LINE_SIZE    128
#define L1_SIZE         (128 * KB)

#define MASK(x)     ((1 << x) - 1)
#define MSB_MASK    0x8000000000000000ULL

#define HPO_nbits   11
#define RPO_nbits   7
#define CLO_nbits   7

#define HPO(vaddr)  ( (vaddr >> (CLO_nbits + RPO_nbits)) & MASK(HPO_nbits) )
#define RPO(vaddr)  ( (vaddr >> CLO_nbits) & MASK(CLO_nbits) )
#define CLO(vaddr)  ( (vaddr) & MASK(CLO_nbits) )


#ifdef __linux__
#define L1_HIT_MAX_LATENCY  65
#define L2_MISS_MIN_LATENCY 200
#else
#define L1_HIT_MAX_LATENCY  224
#define L2_MISS_MIN_LATENCY 300
#endif

#endif
