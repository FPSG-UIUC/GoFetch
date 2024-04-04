# GoFetch
This repository is the open-source code for our USENIX Security 2024 paper: *GoFetch: Breaking Constant-Time Cryptographic Implementations Using Data Memory-Dependent Prefetchers*.
Please check our [website](https://gofetch.fail/) for more information.

## Introduction
GoFetch is a microarchitectural side-channel attack that can extract secret keys from constant-time cryptographic implementations via data memory-dependent prefetchers (DMPs).

We show that DMPs are present in many Apple CPUs and pose a real threat to multiple cryptographic implementations, allowing us to extract keys from OpenSSL Diffie-Hellman, Go RSA, as well as CRYSTALS Kyber and Dilithium.

## Source Code Overview
This repository comprises the following artifacts:
```
.
|-- linuxsetup: kernel module to set up performance counter access in Asahi Linux.
|-- re: reverse engineering experiments.
|-- poc: proof-of-concept attacks.
```

## Reverse Engineering DMPs

### Set up Environment
The high-resolution timing source used for reverse engineering experiments comes from performance counters. To configure and access the performance counter, in macOS, we load the dynamic library named `kperf`. In Asahi Linux, [extra actions](#set-up-asahi-linux-performance-counters) should be taken before go to the `init.sh`.

M2 and M3 have different L2 cache configurations. For M2 and M3 machines, go to `src/lib/basics/arch.h` and uncomment the M2 macro.

```
// uncomment below for M2 and M3
// #define M2 0
```

Run `init.sh` script to set up the timer and use it to profile the latency of accessing data from L1, L2, DRAM (also the overhead of the measurement). You need to re-do the timer set up every time you reboot the machine.

#### Set up Asahi Linux Performance Counters
To enable userspace access to performance counters, we need to load a kernel module and set a system register (SYS_APL_PMCR0_EL1 [30]).

*Build and load kernel module*
```
cd linuxsetup
cd kmod
make
sudo insmod kmod.ko
```
*Enable userspace access*
```
# Install Rust required
cd pmuctl
cargo b -r
sudo ./target/release/pmuctl
```


### DIT Bit Test (Quick Test)
Run `quick_check.out` to check whether setting the data independent timing bit ([DIT](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms#Enable-DIT-for-constant-time-cryptographic-operations)) turns off the DMP. Argument `set_dit` is used to set (`set_dit=1`) or unset (`set_dit=0`) the DIT bit.

```
sudo ./src/quick_check.out <set_dit>
```

### Examine Access Patterns
**Reproduce the [Augury](https://www.prefetchers.info) access pattern:** Augury access pattern is the access pattern described in the prior work. Basically, when the program loads and dereferences each entry of an array of pointers (aop), `*aop[0] ... *aop[N-1]`, the DMP will set out to prefetch `*aop[N] ... *aop[M-1]`. Run `./aopstream.sh 264 256 <trial>` to create a 264 entries aop, perform access+dereference to the first 256 entries, and see the DMP dereferences pointers in the next 8 entries.

**Avoiding architectural pointer dereferencing:** We take off the dereference operations in the program and find that the traversal access pattern `aop[0] ... aop[N-1]` can trigger the stride (or stream) prefetcher to bring `aop[N] ... aop[M-1]` and the DMP dereferences pointers brought in by the stride prefetcher. Run `./noderef.sh 264 8 256 256 <trial>` to create a 264 entries aop, fill the first 256 entries with dummy value and the next 8 entries with pointers. Traversing first 256 entries results in DMP derefercing the next 8 pointers.

**In-bounds DMP dereferencing:** This time we put the pointers to entries the program is going to traverse. Run `./noderef.sh 8 8 0 8 <trial>` to create an 8 entries aop filled with pointers. Traversing these 8 entries results in DMP dereferencing corresponding 8 pointers.

**One load:** Run `./noderef.sh 8 8 0 1 <trial>`. The same aop configuration as above, but the program only touches the first entry. We find that all 8 pointers are still dereferenced by the DMP, when they are in the same L1 cache (the aop is L1 line aligned).

### DMP Activation Criteria
**History filter:** Run `./history.sh <trial>` to examine how many DMP dereferences is required to let the DMP dereference the same pointer again.

**L1 and L2 cache fills:** Run `./dmpline.sh <trial>`. Create an aop fitting a L2 cache line (128 bytes) with 16 pointers. First 8 entries locate in the lower L1 cache line (64 bytes), while the next 8 entries corresponds to the upper L1 cache line (64 bytes). If we only touch one of L1 lines, then only the touched line will be cached in L1. Meanwhile, only pointers in the touched L1 line are dereferenced by the DMP. This shows that the DMP monitors L1 cache fills.

**Do-not-scan hint:** Run `./l2l1fetch.sh <trial>`. We load a pointer from the L2 cache and differentiate where this pointer comes from. We find that if the pointer comes from L1 cache (L1->L2) then it will *not* be dereferenced, if it comes from DRAM (DRAM->L2), it will be dereferenced. The reason is that the pointer comes from L1 is likely to be inspected before, and the DMP tries to avoid redundant inspection.

### Restrictions on dereferenced Pointers
**4GByte prefetch region:** Run `./addrsweep.sh 0x10000000 16 0x380000000 <trial>`. Create a big buffer across the 4GByte boundary. Here, we start the buffer from 0x380000000 and select 16 candidate addresses with a fixed stride 0x10000000. Every time we pick two addresses from the 16 candidates, one is selected as the pointer value, the other one is the location we put the selected pointer value. We find that these two should be in the same 4GByte region to activate the DMP.

**Top byte ignore:** Run `./tbi.sh <trial>`. Select a pointer as the test pointer, flip one of upper bits of it and then place it in the aop. We trigger the DMP on the flipped pointer to see if the DMP can still dereference the original pointer. We find that the DMP ignore the bit flip of the upper 8 bits.

**Auxiliary next-line prefetch:** Run `nextline.sh <trial>`. We trigger the DMP on a specific pointer and find that not only the cache line pointed by the pointer is prefetched by the DMP, but the next line is also prefetched.

## Constant-Time Cryptography PoCs
To be released soon.

## Common Errors and Fixes
1. Segmentation Fault

Segmentation fault happens when the size of stack is not big enough to perform the eviction set generation algorithm. Run `ulimit -s 65520` to increase the stack size.

2. Assertion failed: ADDR_CHECK

To successfully dereference a pointer by the DMP, the pointer's position (where the pointer lives) and the pointer's target (where the pointer points to) should locate in the same 4Gbyte memory region. Assertion fails means the OS does not allocate memory satisfying above requirement. Just re-run the program.