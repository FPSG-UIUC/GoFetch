use libaugury_ffi_sys::pin_cpu;
use libkyber_ffi_sys::{pqcrystals_kyber512_ref_keypair, pqcrystals_kyber512_ref_dec,
    pqcrystals_kyber512_ref_indcpa_get_sk_coef, CRYPTO_PUBLICKEYBYTES, 
    CRYPTO_SECRETKEYBYTES, CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, KYBER_N};
// std lib
use std::os::raw::c_uchar;
use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};


fn handle_client(
    mut stream: TcpStream,
) {
    let mut msg_data = [0u8; 1]; // !0 - start, 0 - finish
    let mut ct: [u8; CRYPTO_CIPHERTEXTBYTES as usize] = [0u8; CRYPTO_CIPHERTEXTBYTES as usize];

    // kyber
    let mut ss1: [u8; CRYPTO_BYTES as usize] = [0; CRYPTO_BYTES as usize];
    let mut pk: [u8; CRYPTO_PUBLICKEYBYTES as usize] = [0; CRYPTO_PUBLICKEYBYTES as usize];
    let mut sk: [u8; CRYPTO_SECRETKEYBYTES as usize] = [0; CRYPTO_SECRETKEYBYTES as usize];
    // Generate the public/private keypair
    unsafe {
        match pqcrystals_kyber512_ref_keypair(pk.as_mut_ptr() as *mut c_uchar, sk.as_mut_ptr() as *mut c_uchar) {
            0 => println!("[+] PK/SK are successfully generated!"),
            _ => panic!("Fail to generate PK/SK!")
        };
    };
    // Store the sk coefficients
    let mut coeffs_vec: [i16; 2*KYBER_N as usize] = [0; 2*KYBER_N as usize];
    unsafe{ pqcrystals_kyber512_ref_indcpa_get_sk_coef(sk.as_ptr() as *const c_uchar, coeffs_vec.as_mut_ptr() as *mut i16); }

    // Store the private key
    let sk_file_path: &str = "kyber.txt";
    let mut sk_file: File = File::create(sk_file_path).unwrap();
    for i in 0..2*KYBER_N as usize{
        write!(sk_file, "{}\n", coeffs_vec[i]).unwrap();
    }

    // Get shared secret
    loop {
        // Receive Client Request (Synchronize each logical transaction)
        stream.read_exact(&mut msg_data).unwrap();
        if msg_data[0] == 0 {
            println!("Finish task for {}", stream.peer_addr().unwrap());
            break;
        }
        // print!("[+] Start -> ");
        // Send Public Key
        stream.write_all(&pk).unwrap();
        // print!("Send PbKey -> ");

        // Receive Public Key
        stream.read_exact(&mut ct).unwrap();
        // println!("Receive cipher text");

        let flag = unsafe {
            pqcrystals_kyber512_ref_dec(ss1.as_mut_ptr() as *mut c_uchar, 
            ct.as_ptr() as *const c_uchar, 
            sk.as_ptr() as *const c_uchar)
        };

        // print!("Shared Secret: [");
        // for ss_idx in 0..CRYPTO_BYTES as usize {
        //     print!(" {:02x}", ss1[ss_idx]);
        // }
        // println!("]");

        // Send FIN
        msg_data[0] = flag as u8;
        stream.write_all(&msg_data).unwrap();
        // println!("[+] End");
    }
}

fn main() {
 
    unsafe{ pin_cpu(7) };

    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Weak Kyber Server listening on port 3333");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());

                // connection succeeded
                // Call Kyber handler
                handle_client(stream);
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