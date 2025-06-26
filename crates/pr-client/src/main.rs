// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

mod cli;
mod stream;

use aes_gcm::{Aes256Gcm, KeyInit};
use common::cipher::send_encrypted_packet;
use common::codes::Codes;
use common::packet::{Packet, deserialize_packet, get_packet_length, serialize_packet};
use common::rw::get_input;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn print_options() {
    println!("\nOptions:");
    println!("1 - Add connection to a server");
    println!("2 - Disconnect from a server");
    println!("3 - Switch to a different connexion");
    println!("4 - List all connections");
}

#[tokio::main]
async fn main() {
    let mut connections: HashMap<String, stream::Stream> = HashMap::new();

    loop {
        print_options();

        if let Ok(choice) = get_input("> ").trim().parse::<u8>() {
            match choice {
                1 => {
                    let address = get_input("Enter the server address: ");
                    if address.is_empty() {
                        println!("No address provided.");
                        continue;
                    }
                    let address = address.trim();

                    let port = get_input("Enter the port to listen on (default 1736) : ");
                    let port = port.trim().parse::<u16>().unwrap_or(1736);

                    connexion(&mut connections, address.to_string(), port.to_string())
                        .await
                        .unwrap_or_else(|e| {
                            println!("Error connecting: {}", e);
                        });
                }
                2 => {
                    if connections.is_empty() {
                        println!("No connections available to disconnect from.");

                        let name = get_input("Enter the name of the connection to disconnect: ");
                        if let Some(mut stream) = connections.remove(&name) {
                            if let Err(e) = stream.stream.shutdown().await {
                                println!("Failed to disconnect from {} : {}", name, e);
                            } else {
                                println!("Disconnected from {}", name);
                            }
                        }
                    }
                }
                3 => {
                    if connections.is_empty() {
                        println!("No connections available to switch to.");
                        continue;
                    }

                    let name = get_input("Switch to connection: ");
                    if let Some(stream) = connections.get_mut(&name) {
                        // TODO: Add the ability to choose the channel ID
                        let chan_id = 0;
                        if let Err(e) = communication(stream, chan_id).await {
                            println!("Failed to communicate on {}: {}", name, e);
                        }
                    } else {
                        println!("No connection found with the name '{}'.", name);
                    }
                }
                4 => {
                    if connections.is_empty() {
                        println!("No connections available.");
                    } else {
                        for (name, stream) in &connections {
                            println!(
                                "- {} : {}",
                                name,
                                stream
                                    .stream
                                    .peer_addr()
                                    .expect("Failed to get peer address")
                            );
                        }
                    }
                }
                _ => {
                    println!("Invalid option, please choose a number between 1 and 4.");
                    continue;
                }
            }
        } else {
            println!("Invalid input, please enter a number between 1 and 4.");
            continue;
        }
    }
}

async fn connexion(
    connections: &mut HashMap<String, stream::Stream>,
    address: String,
    port: String,
) -> io::Result<()> {
    match TcpStream::connect(format!("{}:{}", address, port)).await {
        Ok(stream) => {
            let name = loop {
                let input = get_input("Enter a name for this connection : ");
                if input.is_empty() {
                    println!("Name cannot be empty. Please enter a valid name.");
                    continue;
                }
                break input;
            };

            let secure_stream = setup_secure_connection(stream).await?;

            connections.insert(name.trim().to_string(), secure_stream);

            // TODO: If a connection is already established with the same name, increment the channel ID by one (we thus create a new shell on the remote machine)
            let chan_id = 0;

            // authentification().await?;

            if let Some(stream_ref) = connections.get_mut(&name.trim().to_string()) {
                communication(stream_ref, chan_id).await?;
            }

            println!("Connected to server at {}:{}", address, port);
        }
        Err(e) => {
            println!("Failed to connect to server: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

async fn setup_secure_connection(mut stream: TcpStream) -> io::Result<stream::Stream> {
    let stream_ref = &mut stream;

    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let pub_key = PublicKey::from(&ephemeral_secret);

    let packet = Packet::new(
        0,
        1,
        Codes::PUBLIC_KEY_REQUEST,
        0,
        [0; 12],
        pub_key.as_bytes().to_vec(),
        vec![],
    );

    let serialized_packet = serialize_packet(&packet)?;

    // We send the length of the packet "as is" without encryption before the package
    let packet_len = serialized_packet.len() as u32;
    stream_ref.write_all(&packet_len.to_be_bytes()).await?;

    stream_ref.write_all(&serialized_packet).await?;

    // We get the length of the response packet
    let response_len = get_packet_length(stream_ref).await?;

    let mut response_buf = vec![0u8; response_len];
    stream_ref.read_exact(&mut response_buf).await?;

    let response_packet = deserialize_packet(&response_buf)?;

    if response_packet.code != Codes::PUBLIC_KEY_RESPONSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unexpected code in response",
        ));
    }

    // 32 bytes it the length of a public key in X25519
    if response_packet.ciphertext.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid public key length",
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&response_packet.ciphertext);
    let server_pub_key = PublicKey::from(key_bytes);

    let shared_secret = ephemeral_secret.diffie_hellman(&server_pub_key);

    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    let encryption_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to initialize cipher"))?;

    let persistent_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let persistent_public = PublicKey::from(&persistent_secret);

    let secure_stream = stream::Stream {
        stream,
        priv_key: persistent_secret,
        pub_key: persistent_public,
        rem_pub_key: server_pub_key,
        cipher,
    };

    println!(
        "Secure connection established with server at {}",
        secure_stream.stream.peer_addr()?
    );

    Ok(secure_stream)
}

async fn authentification() -> io::Result<()> {
    todo!();
}

async fn communication(stream: &mut stream::Stream, chan_id: u32) -> io::Result<()> {
    loop {
        let message = get_input("Enter a message: ");
        if message.is_empty() {
            break Ok(());
        } else if let Err(e) = send_encrypted_packet(
            &mut stream.stream,
            &stream.cipher,
            Codes::COMMAND,
            chan_id,
            &message,
        )
        .await
        {
            println!("Failed to send message: {}. Try again.", e);
            continue;
        }
    }
}
