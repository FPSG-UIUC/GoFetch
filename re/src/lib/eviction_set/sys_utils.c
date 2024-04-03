#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "sys_utils.h"
#include "../basics/arch.h"

#ifdef __linux__
#include <sys/resource.h>
#include <sched.h>
void pin_cpu(size_t core_ID)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(core_ID, &set);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &set) < 0) {
		printf("Unable to Set Affinity\n");
		exit(EXIT_FAILURE);
	}

	// Set the scheduling priority to high to avoid interruptions
	// (lower priorities cause more favorable scheduling, and -20 is the max)
	setpriority(PRIO_PROCESS, 0, -20);
}

void init_kpc() {
        /*
            From userspace:
            Enable PMU #0 (FIXED_CYCLES).
            SYS_APL_PMCR0_EL1 bit 0 nust be set.
            ([7:0] Counter enable for PMC #7-0)
        */
        uint64_t PMCR0_EL1 = 0;
        asm volatile(
            "mrs %[PMCR0_EL1], S3_1_c15_c0_0\n\t"
            : [PMCR0_EL1] "=r" (PMCR0_EL1)
            : :);
        
        PMCR0_EL1 |= 1 << 0;
        asm volatile(
            "msr S3_1_c15_c0_0, %[PMCR0_EL1]\n\t"
            "isb sy\n\t"
            : : [PMCR0_EL1] "r" (PMCR0_EL1)
            :);

        /*
            SYS_APL_PMCR1_EL1: bit 8 must be set
            to enable EL0 A64 counts on PMU #0.
            ([15:8] EL0 A64 enable PMC #0-7)
        */
        uint64_t PMCR1_EL1 = 1 << 8;
        asm volatile(
            "msr S3_1_c15_c1_0, %[PMCR1_EL1]\n\t"
            "isb sy\n\t"
            : : [PMCR1_EL1] "r" (PMCR1_EL1)
            :);
}

uint64_t get_time_mach(uint64_t zero_dependency)
{
	struct timespec ts;
	ts.tv_nsec = (zero_dependency);
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return 1000000000 * ts.tv_sec + (uint64_t)ts.tv_nsec;
}

#else

#define KPERF_LIST                               \
    /*  ret, name, params */                     \
    F(int, kpc_get_counting, void)               \
    F(int, kpc_force_all_ctrs_set, int)          \
    F(int, kpc_set_counting, uint32_t)           \
    F(int, kpc_set_thread_counting, uint32_t)    \
    F(int, kpc_set_config, uint32_t, void *)     \
    F(int, kpc_get_config, uint32_t, void *)     \
    F(int, kpc_set_period, uint32_t, void *)     \
    F(int, kpc_get_period, uint32_t, void *)     \
    F(uint32_t, kpc_get_counter_count, uint32_t) \
    F(uint32_t, kpc_get_config_count, uint32_t)  \
    F(int, kperf_sample_get, int *)              \
    F(int, kpc_get_thread_counters, int, unsigned int, void *)

#define F(ret, name, ...)                \
    typedef ret name##proc(__VA_ARGS__); \
    static name##proc *name;
KPERF_LIST
#undef F

#define CFGWORD_EL0A32EN_MASK (0x10000)
#define CFGWORD_EL0A64EN_MASK (0x20000)
#define CFGWORD_EL1EN_MASK (0x40000)
#define CFGWORD_EL3EN_MASK (0x80000)
#define CFGWORD_ALLMODES_MASK (0xf0000)

#define CPMU_NONE 0
#define CPMU_CORE_CYCLE 0x02
#define CPMU_INST_A64 0x8c
#define CPMU_INST_BRANCH 0x8d
#define CPMU_SYNC_DC_LOAD_MISS 0xbf
#define CPMU_SYNC_DC_STORE_MISS 0xc0
#define CPMU_SYNC_DTLB_MISS 0xc1
#define CPMU_SYNC_ST_HIT_YNGR_LD 0xc4
#define CPMU_SYNC_BR_ANY_MISP 0xcb
#define CPMU_FED_IC_MISS_DEM 0xd3
#define CPMU_FED_ITLB_MISS 0xd4

#define KPC_CLASS_FIXED (0)
#define KPC_CLASS_CONFIGURABLE (1)
#define KPC_CLASS_POWER (2)
#define KPC_CLASS_RAWPMU (3)
#define KPC_CLASS_FIXED_MASK (1u << KPC_CLASS_FIXED)
#define KPC_CLASS_CONFIGURABLE_MASK (1u << KPC_CLASS_CONFIGURABLE)
#define KPC_CLASS_POWER_MASK (1u << KPC_CLASS_POWER)
#define KPC_CLASS_RAWPMU_MASK (1u << KPC_CLASS_RAWPMU)

#define COUNTERS_COUNT 10
#define CONFIG_COUNT 8
#define KPC_MASK (KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_FIXED_MASK)
uint64_t g_counters[COUNTERS_COUNT];
uint64_t g_config[COUNTERS_COUNT];

void configure_kpc(void)
{
    g_config[0] = CPMU_CORE_CYCLE | CFGWORD_EL0A64EN_MASK;
    if (kpc_set_config(KPC_MASK, g_config))
    {
        printf("kpc_set_config failed\n");
        return;
    }

    if (kpc_force_all_ctrs_set(1))
    {
        printf("kpc_force_all_ctrs_set failed\n");
        return;
    }

    if (kpc_set_counting(KPC_MASK))
    {
        printf("kpc_set_counting failed\n");
        return;
    }

    if (kpc_set_thread_counting(KPC_MASK))
    {
        printf("kpc_set_thread_counting failed\n");
        return;
    }
}

void init_kpc(void)
{
    void *kperf = dlopen(
        "/System/Library/PrivateFrameworks/kperf.framework/Versions/A/kperf",
        RTLD_LAZY);
    if (!kperf)
    {
        printf("kperf = %p\n", kperf);
        return;
    }
#define F(ret, name, ...)                         \
    name = (name##proc *)(dlsym(kperf, #name));   \
    if (!name)                                    \
    {                                             \
        printf("%s = %p\n", #name, (void *)name); \
        return;                                   \
    }
    KPERF_LIST
#undef F
}

uint64_t get_kpc_time(void)
{
    if (kpc_get_thread_counters(0, COUNTERS_COUNT, g_counters))
    {
        printf("kpc_get_thread_counters failed\n");
        return 1;
    }
    return g_counters[2];
}

void pin_cpu(size_t core_no)
{
	if (core_no <= 3) { // ICESTORM
		pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0);
	} else if (core_no <= 7) { // FIRESTORM
		pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
	} else {
		assert(0 && "error! make sure 0 <= core_no <= 7");
	}
}


uint64_t (*ns_ptr)(clockid_t) = &clock_gettime_nsec_np;

uint64_t get_time_mach(uint64_t zero_dependency)
{
	uint64_t t = zero_dependency;
    t += (*(ns_ptr + zero_dependency))(CLOCK_UPTIME_RAW);
	return t;
}
#endif

uint64_t busy_wait(uint64_t iter, uint64_t trash) {
    // multiplication loop
    for (uint64_t i=0; i<iter; i++) {
        trash = (trash + 1) & 0xffff;
        asm volatile(
            "mul %[trash], %[trash], %[trash]\n\t"
            : [trash] "+r" (trash)
            : :
        );
    }
    return trash;
}

void return_size(char* output, size_t bytes) {
    if (bytes <= KB) {
        sprintf(output, "%lluB", (uint64_t)bytes);
    } else if (bytes <= MB) {
        sprintf(output, "%lluKB", bytes / KB);
    } else {
        sprintf(output, "%lluMB", bytes / MB);
    }
}


