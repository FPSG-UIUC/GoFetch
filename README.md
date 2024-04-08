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

### Restrictions on Dereferenced Pointers
**4GByte prefetch region:** Run `./addrsweep.sh 0x10000000 16 0x380000000 <trial>`. Create a big buffer across the 4GByte boundary. Here, we start the buffer from 0x380000000 and select 16 candidate addresses with a fixed stride 0x10000000. Every time we pick two addresses from the 16 candidates, one is selected as the pointer value, the other one is the location we put the selected pointer value. We find that these two should be in the same 4GByte region to activate the DMP.

**Top byte ignore:** Run `./tbi.sh <trial>`. Select a pointer as the test pointer, flip one of upper bits of it and then place it in the aop. We trigger the DMP on the flipped pointer to see if the DMP can still dereference the original pointer. We find that the DMP ignore the bit flip of the upper 8 bits.

**Auxiliary next-line prefetch:** Run `nextline.sh <trial>`. We trigger the DMP on a specific pointer and find that not only the cache line pointed by the pointer is prefetched by the DMP, but the next line is also prefetched.

## Constant-Time Cryptography PoCs
From the understanding of how the DMP works, we develop a new type of chosen-input attack framework, where the attacker engineers a secret-dependent pointer value in victim's memory (by giving the victim a chosen input to process) and exploit the DMP to deduce the secret from it. To this end, the attacker has to inspect the victim program:

* Spot the mixture of secret data and chosen input. Since the DMP only leaks pointer values, the attacker should have enough control over the mixture, such that the mixture could be a valid pointer value depending on the secret data.
* To confirm the DMP scanning over the mixture, one eviction set is required to evict the mixture (later on the victim reloads it from the memory) and the attacker needs the other eviction set to monitor whether the DMP dereferences the secret-dependent pointer (Prime+Probe channel). To get both of them,
    * The page offset of mixture address should be stable across runs and the space of eviction set candidates can shrink.
    * Cold, valid pages locating in the same 4GByte region as the mixture should be stable across runs. And the attacker will search the DMP prefetch target (pointed by the secret-dependent pointer) within these pages.
    * Having pre-knowledge in hand (page offset of mixture's address, address range to pick as secret-dependent pointer), the attacker has to force the mixture as the pointer (secret-independent) and try different combination of eviction sets until detect the DMP signal.

To show the idea, we build end-to-end key extraction PoCs for constant-time cryptographic implementations on Apple M1 machines running macOS.

### Constant-Time Conditional Swap
Constant-time conditional swap performs a swap between two arrays, `a` and `b`, depending on the secret `s` (`s=1` swap, `s=0` no swap). The attacker places the pointer in one of arrays (`a`), and target the other one (`b`) to see if the content of it triggers the DMP dereferencing the pointer, in other words, whether the swap happens.

**Determine the address of dyld cache:** the location of the dyld shared library is randomized for each boot time, so we need to run `dyld_search` every time reboot the machine.
```
cd crypto_attacker
cargo b -r --example dyld_search
./target/release/examples/dyld_search
```

**Run experiments:** Run the attacker and victim separately. The victim has one input argument, `<secret>`, it could be set as 1 or 0. The attacker has three arguments. In our example, we configure the attacker measures 32 samples for each chosen input, set the threshold of the Prime+Probe channel as 680 ticks and group 8 standard eviction sets as the eviction set for the mixture.

```
# attacker
cd crypto_attacker
cargo b -r --example ctswap_attacker
./target/release/examples/ctswap_attacker 32 680 8
# victim
cd crypto_victim
cargo b -r --example ctswap_victim
./target/release/examples/ctswap_victim <secret>
```

**Analyze leakage result:** The attacker records the time consumption of each stage in `ctswap_bench.txt` and Prime+Probe latency samples depending on victim's secret in `ctswap.txt`. Four real cryptographic examples below also record above benchmarking results.


### Go's RSA Encryption
Go's RSA implementation adopts Chinese Remainder Theorem to accelerate the decryption. One necessary step in the decryption procedure is a modular operation between chosen cipher `c` and secret prime `p` (or `q`), `c mod p`. By placing a pointer value in `c`, the mixture `c mod p` contains a secret-dependent pointer value.

**Run experiments:** Run the attacker and victim separately. Apart from the same three arguments as in [constant-time conditional swap](#constant-time-conditional-swap), the attacker has four additional inputs. In our example, we configure the attacker to search for target pointer from 0x14000400000 to 0x14000590000, determine one bit of guess after observing 3 positive DMP signals or 10 negative DMP signals.

```
# attacker
cd crypto_attacker
cargo b -r --example rsa_attacker --features rsa
./target/release/examples/rsa_attacker 32 680 8 0x14000400000 0x14000590000 3 10
# victim
cd crypto_victim
cargo b -r --example rsa_victim --features rsa
./target/release/examples/rsa_victim
```

**Analyze leakage result:** Run `python crypto_accuracy.py --crypto rsa` to analyze Prime+Probe latency of positive/negative DMP signals, and the accuracy of our attack. Also, the Coppersmith algorithm (`coppersmith.sage.py`) is called to recover the whole secret prime. We borrow the Coppersmith implementation from [link](https://github.com/mimoo/RSA-and-LLL-attacks).

### OpenSSL Diffie-Hellman Key Exchange
OpenSSL DHKE implementation utilizes a window-based exponentiation algorithm. The intermediate state of each iteration depends on the secret prefix, which allows the attacker to craft a public key to guess/examine the secret window by window.

**Determine the address of dyld cache:** Navigate to [link](#constant-time-conditional-swap).

**Run experiments:** Run the attacker and victim separately. The attacker has the same arguments as in [constant-time conditional swap](#constant-time-conditional-swap)

```
# attacker
cd crypto_attacker
cargo b -r --example dh_attacker --features dh
./target/release/examples/dh_attacker 32 680 8
# victim
cd crypto_victim
cargo b -r --example dh_victim --features dh
./target/release/examples/dh_victim
```

**Analyze leakage result:** Run `python crypto_accuracy.py --crypto dh` to analyze Prime+Probe latency of positive/negative DMP signals, and the accuracy of our attack.

### CRYSTALS-Kyber (ML-KEM)
Kyber's inside public key encryption scheme is vulnerable to Key Mismatch Attack. Although the Fujisaki-Okamoto transformation prevent mismatch information from Kyber's output, the DMP can examine the intermediate state to learn the mismatch information and re-enable the Key Mismatch Attack. We refer the Key Mismatch Attack implementation from [link](https://github.com/AHaQY/Key-Mismatch-Attack-on-NIST-KEMs).

**Determine the address of dyld cache:** Navigate to [link](#constant-time-conditional-swap).

**Run experiments:** Run the attacker and victim separately. Apart from the same three arguments as in [constant-time conditional swap](#constant-time-conditional-swap), the attacker has one additional input. In our example, we configure the attacker to determine one coefficient of guess after observing 5 positive signals.

```
# attacker
cd crypto_attacker
cargo b -r --example kyber_attacker --features kyber
./target/release/examples/kyber_attacker 32 680 8 5
# victim
cd crypto_victim
cargo b -r --example kyber_victim --features kyber
./target/release/examples/kyber_victim
```

**Analyze leakage result:** Run `python crypto_accuracy.py --crypto kyber` to analyze Prime+Probe latency of positive/negative DMP signals, and the accuracy of our attack. Also, the lattice reduction tool (`kyber_reduction.py`) is called to recover the whole secret. We borrow the lattice reduction tool from [link](https://github.com/juliannowakowski/lwe_with_hints).

### CRYSTALS-Dilithium (ML-DSA)
Dilithium is a digital signature scheme. In the sign function, there is an equation `z=y+cs1`, where `s1` is the secret, `z` and `c` are exposed through the output signature. By leveraging the DMP to leak `y`, the attacker can collect linear equations with regard to the secret and further use the lattice reduction tool to recover the secret.

**Offline signature collection:** Navigate to `poc/dilithium_data` to proceed.

**Run experiments:** Run the attacker and victim separately. Apart from the same three arguments as in [constant-time conditional swap](#constant-time-conditional-swap), the attacker has four additional inputs. In our example, we offline collect signatures that inject `z` with pointer `ptr` such that `ptr & 0xffffc000 = 0x10000` (same page frame number pointers to ease eviction set generation), configure the attacker to determine one equation of guess after observing 10 positive DMP signals, online collect 256 signatures per secret polynomial. Finally, 1 refers to the attempt id (running the online stage multiple times and doing intersection can increase the success rate).

```
# attacker
cd crypto_attacker
cargo b -r --example dilithium_attacker --features dilithium
./target/release/examples/dilithium_attacker 32 680 8 0x10000 10 256 1
# victim
cd crypto_victim
cargo b -r --example dilithium_victim --features dilithium
./target/release/examples/dilithium_victim
```

**Analyze leakage result:** Run `python crypto_accuracy.py --crypto dilithium` to analyze Prime+Probe latency of positive/negative DMP signals, and the accuracy of our attack. Also, the lattice reduction tool (`dilithium_reduction.py`) is called to recover the whole secret. We borrow the lattice reduction tool from [link](https://github.com/juliannowakowski/lwe_with_hints).

## Common Errors and Fixes
1. Segmentation Fault

Segmentation fault happens when the size of stack is not big enough to perform the eviction set generation algorithm. Run `ulimit -s 65520` to increase the stack size.

2. Assertion failed: ADDR_CHECK

To successfully dereference a pointer by the DMP, the pointer's position (where the pointer lives) and the pointer's target (where the pointer points to) should locate in the same 4Gbyte memory region. Assertion fails means the OS does not allocate memory satisfying above requirement. Just re-run the program.