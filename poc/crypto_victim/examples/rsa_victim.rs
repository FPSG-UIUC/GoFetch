use libaugury_ffi_sys::pin_cpu;
use librsa_ffi_sys::{Init, GoSlice, Display_PQ, Victim};
// std lib
use std::os::raw::c_void;
use std::io::{Write, Read};
// network lib
use std::net::{TcpListener, TcpStream};


fn rsa_handler(
    mut stream: TcpStream,
) {
    let mut big_data = [0u8; 256];
    let mut msg_data = [0u8; 1]; // !0 - start, 0 - finish
    let cc: GoSlice = GoSlice {data: big_data.as_mut_ptr() as *mut c_void, len: 256, 
        cap: 256};
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
        let result = unsafe{Victim(cc)};
        // match result {
        //     1 => {println!("[+] Decryption succeeds!");},
        //     0 => {println!("[+] Decryption fails!");},
        //     _ => {panic!("Unknown error for Decrytion!");},
        // };

        // Send FIN
        msg_data[0] = result as u8;
        stream.write_all(&msg_data).unwrap();
        // println!("[+] End");
        // stream.flush().unwrap();
    }
    unsafe{Display_PQ();}
}

fn main() {
    // pin to performance core
    unsafe{ pin_cpu(7); }

    // initial RSA private key
    unsafe{Init(2048);}
    println!("[+] Finish Generate Private Key!");
    unsafe{Display_PQ();}

    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Weak RSA Server listening on port 3333");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());

                // connection succeeded
                // Call RSA handler
                rsa_handler(stream);
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