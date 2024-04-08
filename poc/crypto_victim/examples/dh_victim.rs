use libaugury_ffi_sys::pin_cpu;
// file lib
use std::fs::{File, read};
use std::io::{Write, Read};
// network lib
use std::net::{TcpListener, TcpStream};
// opessl lib
use openssl::bn::{BigNum, BigNumRef};
use openssl::dh::Dh;
use openssl::pkey::Private;


fn dh_handler(
    mut stream: TcpStream,
    dh_victim: &Dh<Private>
) {
    let mut big_data = [0u8; 256];
    let mut msg_data = [0u8; 1]; // !0 - start, 0 - finish
    let dh_public_key = dh_victim.public_key();
    let pk_msg = dh_public_key.to_vec();
    loop {
        // Receive Client Request (Synchronize each logical transaction)
        stream.read_exact(&mut msg_data).unwrap();
        // print!("[+] Start -> ");
        if msg_data[0] == 0 {
            println!("Finish task for {}", stream.peer_addr().unwrap());
            break;
        }
        // Send Public Key
        stream.write_all(&pk_msg).unwrap();
        // print!("Send PbKey -> ");
        // stream.flush().unwrap();

        // Receive Public Key
        stream.read_exact(&mut big_data).unwrap();
        // println!("Receive PbKey");

        let client_public_key = BigNum::from_slice(&big_data).unwrap();

        let shared_secret:Vec<u8> = match dh_victim.compute_key(&client_public_key) {
            Ok(secret) => secret,
            Err(error) => panic!("Compute the shared secret: {}", error)
        };

        // print!("Shared Secret: [");
        // for element in shared_secret.into_iter() {
        //     print!(" {:02x}", element)
        // }
        // println!("]");

        // Send FIN
        msg_data[0] = shared_secret.len() as u8;
        stream.write_all(&msg_data).unwrap();
        // println!("[+] End");
        // stream.flush().unwrap();
    }

}

fn main() {
    // pin to performance core
    unsafe{ pin_cpu(7); }

    // generate private key 
    let dh_params_pem = read("./dh_params.pem").expect("Unable to read dh parameter");
    let dh_params = Dh::params_from_pem(&dh_params_pem).unwrap();

    // generate new key
    let dh_victim = dh_params.generate_key().unwrap();
    let dh_private_key: &BigNumRef = dh_victim.private_key();

    // save private key in dh.txt
    let mut private_key_file = File::create("dh.txt").unwrap();
    let private_key_vec = dh_private_key.to_vec();
    for element in &private_key_vec {
        write!(private_key_file, "{element:02x}").unwrap();
    }
    println!("[+] Finish Generate Private Key!");

    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("DH Server listening on port 3333");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());

                // connection succeeded
                // Call DH handler
                dh_handler(stream, &dh_victim);
            }
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        };
    }

    // close the socket server
    drop(listener);
}