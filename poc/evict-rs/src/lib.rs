pub mod allocator;
pub mod cache_line;
pub mod eviction_set;
pub mod timer;
pub mod multithread_counter;

use mmap_rs::MmapOptions;
use libc;
use rand::thread_rng;
pub use allocator::{Allocator, CacheLineSet};
pub use cache_line::CacheLine;
pub use eviction_set::EvictionSet;
pub use timer::Timer;
pub use crate::multithread_counter::CounterTimer as MyTimer;


// Fine-tuned settings for the Apple M1.
pub const THRESHOLD: u64 = 200;
pub const SAMPLES: usize = 100;

// Hardware setting
pub const L1_CACHE_WAYS: usize = 8;
pub const L2_CACHE_WAYS: usize = 12;
pub const CACHE_LINE_SIZE_L2: usize = 128;
pub const NATIVE_PAGE_SIZE: usize = 16 * 1024;
pub const MSB_MASK: u64 = 0x8000000000000000;
const KB: usize = 1024;
const MB: usize = 1024 * 1024;

/* pin cpu */
pub unsafe fn pin_cpu(cpu_id: usize) {
    if cpu_id <= 3 {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_BACKGROUND, 0);
    } else if cpu_id <= 7 {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0);
    } else {
        panic!("error! make sure 0 <= core_no <= 7");
    }
}

/* L2 Eviction Set Generation Algorithm set */
pub fn eviction_set_generation<T: Timer>(
    target: *mut u8, 
    allocator: &mut Allocator,
    timer: &T
) -> Result<CacheLineSet, String> {
    let mut rng = thread_rng();
    loop {

        let mut eviction_set = allocator.inflate::<_, T>(
            &mut rng,
            timer,
            target,
            8192,
            SAMPLES,
            THRESHOLD,
        );

        let mut timings = vec![0u64; SAMPLES];
        let timing = EvictionSet::evict_and_time(
            &mut rng,
            timer,
            target,
            &mut [],
            &mut timings,
        );

        println!("cached: {}", timing);

        let timing = EvictionSet::evict_and_time(
            &mut rng,
            timer,
            target,
            &mut eviction_set.cache_lines,
            &mut timings,
        );

        println!("evicted: {}", timing);

        let _ = eviction_set.reduce::<_, T>(
            &mut rng,
            timer,
            target,
            SAMPLES,
            THRESHOLD,
            L2_CACHE_WAYS,
        );

        let mut count: u32 = 0;
        let mut timings = vec![0u64; SAMPLES];

        for _ in 0..SAMPLES {
            let timing = EvictionSet::evict_and_time(
                &mut rng,
                timer,
                target,
                &mut eviction_set.cache_lines,
                &mut timings,
            );

            if timing >= THRESHOLD {
                count += 1;
            }
        }

        println!("eviction rate: {:.2}%", count as f64);

        // Return Eviction Set
        if (count == 100) && (eviction_set.cache_lines.len() == L2_CACHE_WAYS) {
            return Ok(eviction_set);
        } else {
            return Err("Reduction Fail".to_string());
        }
    }
}

/* Generate 64 unique eviction sets */
pub fn eviction_set_gen64(mut allocator: &mut Allocator, 
    victim_array_cache_lines: &mut Vec<*mut u8>,
    timer: &MyTimer
) {
    let mut num_valid_evset = 0;
    // Allocate the victim that resides in different set
    let victim_size: usize = (12*MB + 128*KB) * 8;
    let mut victim = MmapOptions::new(victim_size + CACHE_LINE_SIZE_L2)
    .map_mut()
    .unwrap();

    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
        victim.as_mut_ptr() as *mut u8,
        victim.len(),
        )
    };

    bytes.fill(0xff);
    let mut victim_ptr = victim.as_mut_ptr() as *mut u8;
    let victim_bound: u64 = victim_ptr as u64 + victim_size as u64;

    let mut timings = vec![0u64; SAMPLES];
    loop {
        if victim_array_cache_lines.len() != 0 {
            victim_ptr = unsafe {victim_ptr.add(MmapOptions::page_size().1)};
            println!("Size of conflict set: {}", victim_array_cache_lines.len());
            // Construct an eviction set.
            let eviction_set = EvictionSet::new(&victim_array_cache_lines);

            loop {
                for index in 0..timings.len() {
                    // Evict and time the victim access.
                    timings[index] = eviction_set.evict_and_time_once(timer, victim_ptr);
                }
                timings.sort();

                if timings[timings.len() - 1] < THRESHOLD {
                    println!("Maximum load latency for new victim: {}", timings[timings.len() - 1]);
                    break;
                } else {
                    victim_ptr = unsafe {victim_ptr.add(MmapOptions::page_size().1)};
                    if victim_ptr as u64 > victim_bound {
                        panic!("Exceed evset group pool!");
                    }
                    continue;
                }
            }
        }
        println!("[+] Find one target with different set at {:?}", victim_ptr);

        let mut counter: usize = 0;
        let mut victim_ptr_tmp = victim_ptr;
        let mut dup_flag = 0;

        loop {
            allocator.set_offset(victim_ptr_tmp as usize & 0x3fff);
            let mut eviction_set = match eviction_set_generation(victim_ptr_tmp, &mut allocator, timer) {
                Ok(result) => result,
                Err(_) => {
                    // hot line skip
                    counter += 1;
                    if counter * CACHE_LINE_SIZE_L2 >= MmapOptions::page_size().1 {
                        break;
                    }
                    unsafe {victim_ptr_tmp = victim_ptr.add(CACHE_LINE_SIZE_L2 * counter % MmapOptions::page_size().1);}
                    continue;
                },
            };

            // Duplication refers to bad eviction set
            for i in 0..eviction_set.cache_lines.len() {
                eviction_set.cache_lines[i] = ((eviction_set.cache_lines[i] as u64) & 0xffffffffffffc000) as *mut u8;
                for j in 0..victim_array_cache_lines.len() {
                    if eviction_set.cache_lines[i] == victim_array_cache_lines[j] {
                        println!("[+] Found Duplication!!");
                        dup_flag = 1;
                        break;
                    }
                }
                if dup_flag == 1 {
                    break;
                }
            }
            if dup_flag == 1 {
                break;
            }
            victim_array_cache_lines.append(&mut eviction_set.cache_lines);
            num_valid_evset += 1;
            println!("[+] Get the eviction set {}", num_valid_evset);
            break;
        }
        // if got 64 evsets already, exit
        if num_valid_evset == 64 {
            break;
        }
    }
    println!("[+] Finish generating 64 frame evset!");
}

pub fn evset_vec_to_evset(
    vec_evset: & Vec<*mut u8>, 
    result_evset: &mut Vec<*mut u8>,
    evset_size: usize,
    page_offset: usize,
    evset_index: usize
) {
    let num_of_evsets: usize = vec_evset.len() / evset_size;

    if evset_index >= num_of_evsets {
        // exceed boundary
        panic!("Out of boudary of vec_evset {}", num_of_evsets);
    }
    // range of pick up addr
    let start_idx = evset_size * evset_index;

    for i in 0..evset_size {
        result_evset.push(unsafe{vec_evset[start_idx + i].add(page_offset)});
    }
    // for i in 0..result_evset.len() {
    //     println!("{:p}", result_evset[i]);
    // }
}

pub fn evset_vec_to_linked_list(
    vec_evset: & Vec<*mut u8>, 
    evset_size: usize,
    page_offset: usize,
    evset_index: usize
) -> u64 {
    let num_of_evsets: usize = vec_evset.len() / evset_size;

    if evset_index >= num_of_evsets {
        // exceed boundary
        panic!("Out of boudary of vec_evset {}", num_of_evsets);
    }
    // range of pick up addr
    let start_idx = evset_size * evset_index;

    let mut flush_cache_start: u64 = 0x0000000000000000;
    let mut offset_mode: u64 = 0;
    let mut cache_start: *mut u64 = unsafe{ vec_evset[start_idx].add(page_offset) as *mut u64 };
    for i in 0..evset_size {
        if i == 0 {
            flush_cache_start = cache_start as u64;
        } else {
            let mut cur_l2_ptr: *mut u64 = unsafe{ vec_evset[start_idx+i].add(page_offset) as *mut u64 };
            if offset_mode == 0 {
                unsafe {cur_l2_ptr = cur_l2_ptr.add(8);}
            }
            unsafe {*cache_start = cur_l2_ptr as u64;}
            cache_start = cur_l2_ptr;
            unsafe {*cache_start = 0x0000000000000000;}
            offset_mode = !offset_mode;
        }
    }
    flush_cache_start
}

pub fn evset_vec_set_offset(
    vec_evset: & Vec<*mut u8>, 
    evset_size: usize,
    page_offset: usize,
    group_index: usize,
    group_size: usize,
    dst_array: *mut u64
) {
    let num_of_evsets: usize = vec_evset.len() / evset_size;
    let num_of_groups: usize = num_of_evsets / group_size;

    if group_index >= num_of_groups {
        // exceed boundary
        panic!("Out of boudary of vec_evset {}", num_of_evsets);
    }
    
    let base_index = group_index * group_size * evset_size;
    for evset_index in 0..group_size {
        let dst_array_start = evset_size * evset_index;
        let start_idx = evset_size * evset_index + base_index;
        let mut offset_mode: u64 = 0;
        for i in 0..evset_size {
            let mut cur_l2_ptr: *mut u64 = unsafe{ vec_evset[start_idx+i].add(page_offset) as *mut u64 };
            if offset_mode == 0 {
                unsafe {cur_l2_ptr = cur_l2_ptr.add(8);}
            }
            unsafe{ *dst_array.add(dst_array_start+i) = cur_l2_ptr as u64; }
            offset_mode = !offset_mode;
        }
    }
}

pub fn prime_with_dependencies(evictor: &EvictionSet, mut __trash: u64) -> u64 {
    evictor.access();
    __trash |  (__trash & MSB_MASK)
}

pub fn probe_with_dependencies<T: Timer>(
    timer: &T,
    evictor: &EvictionSet,
    mut __trash: u64 
) -> u64 {
    timer.time(|| {
        evictor.access()
    }) | (__trash & MSB_MASK)
}
