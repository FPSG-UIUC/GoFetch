use libaugury_ffi_sys::pin_cpu;
use libdilithium_ffi_sys::{Init, GoSlice, Victim};
// std lib
use std::os::raw::c_void;
use std::io::{Write, Read};
// network lib
use std::net::{TcpListener, TcpStream};


fn dilithium_handler(
    mut stream: TcpStream,
) {
    let mut big_data = [0u8; 8];
    let mut msg_data = [0u8; 1]; // !0 - start, 0 - finish
    let sig_msg: GoSlice = GoSlice {data: big_data.as_mut_ptr() as *mut c_void, len: 8, 
        cap: 8};
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
        // print!("Send PbKey -> ");
        // stream.flush().unwrap();

        // Receive Public Key
        stream.read_exact(&mut big_data).unwrap();
        // println!("Receive PbKey");

        // Decryption
        let result = unsafe{Victim(sig_msg)};

        // Send FIN
        msg_data[0] = result as u8;
        stream.write_all(&msg_data).unwrap();
        // println!("[+] End");
        // stream.flush().unwrap();
    }
}

fn main() {
    // pin to performance core
    unsafe{ pin_cpu(7); }

    // initial RSA private key
    unsafe{Init();}
    println!("[+] Finish Generate Private Key!");

    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Weak Dilithium Server listening on port 3333");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());

                // connection succeeded
                // Call Dilithium handler
                dilithium_handler(stream);
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