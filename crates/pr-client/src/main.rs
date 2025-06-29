// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

mod cli;
mod cmdpr;
mod stream;

use aes_gcm::{Aes256Gcm, KeyInit};
use common::cipher::{decrypt_message, send_encrypted_packet};
use common::codes::Codes;
use common::packet::{Packet, read_next_packet, serialize_packet};
use common::rw::get_input;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Write};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[tokio::main]
async fn main() {
    // Connection name -> Stream
    let mut connections: HashMap<String, stream::Stream> = HashMap::new();

    cmdpr::clear_screen();

    loop {
        match cmdpr::prompt(&connections) {
            Ok(action) => match action {
                cmdpr::Actions::AddConnection {
                    name,
                    address,
                    port,
                } => {
                    if let Err(_) = add_connection(&mut connections, name, address, port).await {
                        cmdpr::show_message_and_wait("Connection failed");
                    }
                }
                cmdpr::Actions::ListConnections => cmdpr::print_connections(&connections),
                cmdpr::Actions::RemoveConnection(name) => {
                    remove_connection(&mut connections, name).await
                }
                cmdpr::Actions::SwitchConnection(name) => {
                    if let Some(stream) = connections.get_mut(&name) {
                        if let Err(_) = communication(stream).await {}
                    }
                }
                cmdpr::Actions::Quit => {
                    break;
                }
            },
            Err(_) => {
                continue;
            }
        }
    }
}

async fn add_connection(
    connections: &mut HashMap<String, stream::Stream>,
    name: String,
    address: String,
    port: u16,
) -> io::Result<()> {
    // Try to connect to the server
    match TcpStream::connect(format!("{}:{}", address, port)).await {
        Ok(stream) => {
            // If the connection is successful, we set up a secure connection
            let secure_stream = setup_secure_connection(stream).await?;
            connections.insert(name, secure_stream);
        }
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Connection failed",
            ));
        }
    }
    Ok(())
}

async fn remove_connection(connections: &mut HashMap<String, stream::Stream>, name: String) {
    if let Some(mut stream) = connections.remove(&name) {
        // If the connection is removed, we shutdown the stream
        let _ = stream.stream.shutdown().await;
    }
}

async fn setup_secure_connection(mut stream: TcpStream) -> io::Result<stream::Stream> {
    let stream_ref = &mut stream;

    // Generate an ephemeral secret key for the client and derive the public key from it
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let pub_key = PublicKey::from(&ephemeral_secret);

    // We create a packet containing the client's public key asking for the server's public key
    let packet = Packet::new(
        Codes::PublicKeyRequest,
        [0; 12],
        pub_key.as_bytes().to_vec(),
    );

    let serialized_packet = serialize_packet(&packet)?;

    // We send the length of the packet "as is" without encryption before the package
    let packet_len = serialized_packet.len() as u32;
    stream_ref.write_all(&packet_len.to_be_bytes()).await?;

    // Send the serialized packet itself
    stream_ref.write_all(&serialized_packet).await?;

    // We get the length of the response packet
    let response_packet = read_next_packet(stream_ref).await?;

    // Check if the response is the public key of the server
    if response_packet.code != Codes::PublicKeyResponse {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unexpected code in response",
        ));
    }

    // 32 bytes is the length of a public key in X25519
    if response_packet.ciphertext.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid public key length",
        ));
    }

    // Convert the response ciphertext to a PublicKey (the one from the server)
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&response_packet.ciphertext);
    let server_pub_key = PublicKey::from(key_bytes);

    // Derive the shared secret using Diffie-Hellman
    let shared_secret = ephemeral_secret.diffie_hellman(&server_pub_key);

    // Create a SHA-256 hash of the shared secret to use as the encryption key
    let mut hasher = Sha256::default();
    hasher.update(shared_secret.as_bytes());
    let encryption_key = hasher.finalize();

    // Initialize the AES-256-GCM cipher with the derived encryption key in SHA-256 format
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to initialize cipher"))?;

    let secure_stream = stream::Stream { stream, cipher };

    Ok(secure_stream)
}

async fn communication(stream: &mut stream::Stream) -> io::Result<()> {
    // Send a packet to refresh the session. Allow us to reset the session state on the server side
    send_encrypted_packet(
        &mut stream.stream,
        &stream.cipher,
        Codes::RefreshSession,
        "",
    )
    .await?;

    // Read the initial command output from the server (usually the prompt of the shell)
    loop {
        match read_next_packet(&mut stream.stream).await {
            Ok(packet) => match packet.code {
                Codes::CommandOutput => {
                    if let Some(message) =
                        decrypt_message(&stream.cipher, &packet.nonce, &packet.ciphertext)
                    {
                        print!("{}", message);
                        std::io::stdout().flush().unwrap();
                    }
                }
                Codes::CommandEnd => {
                    break;
                }
                _ => {}
            },
            Err(_) => break,
        }
    }

    // Main loop for sending commands to the server
    loop {
        // Get the command input from the user
        let command = get_input("").trim().to_string();

        if command.is_empty() {
            continue;
        }

        if command == "%" {
            // Exit command
            break;
        }

        // Send the command to the server
        send_encrypted_packet(&mut stream.stream, &stream.cipher, Codes::Command, &command).await?;

        // Wait for the command output from the server
        loop {
            // Either get the next packet or wait for a 50ms
            // YOU MIGHT NEED TO INCREASE THE TIMEOUT DEPENDING ON YOUR NETWORK CONDITIONS
            let packet_result = tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(50)) => continue,
                packet = read_next_packet(&mut stream.stream) => packet
            };

            match packet_result {
                Ok(packet) => match packet.code {
                    Codes::CommandOutput => {
                        if let Some(message) =
                            decrypt_message(&stream.cipher, &packet.nonce, &packet.ciphertext)
                        {   
                            // Print the command output
                            print!("{}", message);
                            std::io::stdout().flush().unwrap();
                        }
                    }
                    Codes::CommandEnd => {
                        // We have reached the end of the command output
                        break;
                    }
                    _ => {}
                },
                Err(_) => {
                    break;
                }
            }
        }
    }

    Ok(())
}
