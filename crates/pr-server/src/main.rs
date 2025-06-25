// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

pub mod cli;

use aes_gcm::{Aes256Gcm, KeyInit};
use common::packet::{Packet, deserialize_packet, serialize_packet, get_packet_length};
use common::codes::Codes;
use common::cipher::decrypt_message;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};

struct SecureConnection {
    pub stream: TcpStream,
    pub pub_key: PublicKey,
    pub client_pub_key: PublicKey,
    pub cipher: Aes256Gcm,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = cli::main();

    let address = format!("127.0.0.1:{}", args.port);

    let listener = TcpListener::bind(&address).await?;
    println!("Server listening on {}", address);
        
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("New connection from: {}", addr);
                tokio::spawn(async move {
                    match setup_secure_connection(stream).await {
                        Ok(secure_conn) => {
                            if let Err(e) = handle_secure_communication(secure_conn).await {
                                eprintln!("Error during secure communication: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error setting up secure connection : {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("Could not accept connection : {}", e);
            }
        }
    }
}

async fn handle_secure_communication(mut conn: SecureConnection) -> io::Result<()> {
    let stream = &mut conn.stream;

    loop {
        let packet_len = get_packet_length(stream).await?;

        let mut packet_data = vec![0u8; packet_len];
        stream.read_exact(&mut packet_data).await?;

        let packet = deserialize_packet(&packet_data)?;

        match packet.opcode {
            Codes::DISCONNECT => {
                println!("Client requested disconnect");
                return Ok(());
            }
            Codes::COMMAND => {
                if let Some(message) =
                    decrypt_message(&conn.cipher, &packet.nonce, &packet.ciphertext)
                {
                    println!("Received message: {}", message);
                    // todo!("Handle command message");
                }
            }
            _ => {
                println!(
                    "Received packet with unexpected opcode: {:?}",
                    packet.opcode
                );
            }
        }
    }
}

async fn setup_secure_connection(mut stream: TcpStream) -> io::Result<SecureConnection> {
    let stream_ref = &mut stream;

    let packet_len = get_packet_length(stream_ref).await?;

    let mut packet_data = vec![0u8; packet_len];
    stream_ref.read_exact(&mut packet_data).await?;

    let client_packet = deserialize_packet(&packet_data)?;

    if client_packet.opcode != Codes::PUBLIC_KEY_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected PUBLIC_KEY_REQUEST",
        ));
    }

    if client_packet.ciphertext.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid public key length",
        ));
    }

    let mut client_key_bytes = [0u8; 32];
    client_key_bytes.copy_from_slice(&client_packet.ciphertext);
    let client_pub_key = PublicKey::from(client_key_bytes);

    let server_priv_key = EphemeralSecret::random_from_rng(OsRng);
    let server_pub_key = PublicKey::from(&server_priv_key);

    let response_packet = Packet::new(
        0,
        1,
        Codes::PUBLIC_KEY_RESPONSE,
        0,
        [0; 12],
        server_pub_key.as_bytes().to_vec(),
        vec![],
    );

    let serialized_response = serialize_packet(&response_packet)?;

    let response_len = serialized_response.len() as u32;
    stream_ref.write_all(&response_len.to_be_bytes()).await?;
    stream_ref.write_all(&serialized_response).await?;

    let shared_secret = server_priv_key.diffie_hellman(&client_pub_key);

    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    let encryption_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to initialize cipher"))?;

    let secure_conn = SecureConnection {
        stream,
        pub_key: server_pub_key,
        client_pub_key,
        cipher,
    };

    println!("Secure connection established with client.");

    Ok(secure_conn)
}
