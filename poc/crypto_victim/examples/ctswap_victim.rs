use libaugury_ffi_sys::{pin_cpu, constant_time_cond_swap_64, c_sleep};
use crypto_victim::*;
// std lib
use std::env::args;
use std::io::{Write, Read};
use std::mem::size_of;
// random value lib
use rand::{Rng, thread_rng};
// mem lib
use mmap_rs::MmapOptions;
// network lib
use std::net::{TcpListener, TcpStream};


fn ctswap_handler(
    mut stream: TcpStream,
    sk: u64
) {
    let mut input_data = [0u8; 128];  // src <- input; dst <- input+8*64bit
    let mut msg_data = [0u8; 1]; // !0 - start, 0 - finish
    let input_data_ptr = input_data.as_mut_ptr() as *mut u64;
    // Get Mask from secret key
    let mask: u64 = (!sk).wrapping_add(0x1);

    // Allocate the Source and Destination
    let mut dst_data = MmapOptions::new(MmapOptions::page_size().1)
        .map_mut()
        .unwrap();
    dst_data.fill(0x00);
    let dst_data_ptr: *mut u64 = dst_data.as_mut_ptr() as *mut u64;
    let mut src_data = MmapOptions::new(MmapOptions::page_size().1)
        .map_mut()
        .unwrap();
    src_data.fill(0x00);
    let src_data_ptr: *mut u64 = unsafe{src_data.as_mut_ptr().add(0x1234)} as *mut u64;
    println!("dst_data addr: {:p}", dst_data_ptr);
    println!("src_data addr: {:p}", src_data_ptr);
    println!("input_data addr: {:p}", input_data_ptr);

    // main loop
    loop {
        // Receive Client Request (Synchronize each logical transaction)
        stream.read_exact(&mut msg_data).unwrap();
        // print!("[+] Start -> ");
        if msg_data[0] == 0 {
            println!("Finish task for {}", stream.peer_addr().unwrap());
            break;
        }
        // Send Public Key (Attacker won't use Victim pubkey
        // to simplify, just send anything)
        stream.write_all(&msg_data).unwrap();

        // Receive CC
        stream.read_exact(&mut input_data).unwrap();

        // prepare data
        for i in 0..8 {
            unsafe{*src_data_ptr.add(i) = *input_data_ptr.add(i);}
            unsafe{*dst_data_ptr.add(i) = *input_data_ptr.add(8+i);}
        }

        // CT SWAP
        for i in 0..8 {
            unsafe{constant_time_cond_swap_64(mask, src_data_ptr.add(i), dst_data_ptr.add(i));}
            // add delay
            unsafe{*src_data_ptr = *src_data_ptr | (c_sleep(15000, *src_data_ptr) & MSB_MASK);}
        }

        for i in 0..8 {
            unsafe{*src_data_ptr.add(i) = 0;}
            unsafe{*dst_data_ptr.add(i) = 0;}
        }


        // Send FIN
        // clean dst_data and src_data
        msg_data[0] = (unsafe{*src_data_ptr} & MSB_MASK) as u8;
        stream.write_all(&msg_data).unwrap();
        // println!("[+] End");
        // stream.flush().unwrap();
    }
}

fn main() {
    let sk = args().nth(1).expect("Enter <secret key 0 or 1>");
    let sk = sk.parse::<u64>().unwrap();
    println!("[+] Secret Key: {}", sk);
    // pin to performance core
    unsafe{ pin_cpu(7); }

    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Weak CTSWAP Server listening on port 3333");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());

                // connection succeeded
                // Call Constant Time Swap handler
                ctswap_handler(stream, sk);
            },
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        };
    }

    // close the socket server
    drop(listener);
}