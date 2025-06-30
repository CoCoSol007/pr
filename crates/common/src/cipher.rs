// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use super::codes::Codes;
use super::packet::{Packet, serialize_packet};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, Nonce as AeadNonce},
};
use rand::Rng;
use rand::rngs::OsRng;
use std::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub fn encrypt_message(cipher: &Aes256Gcm, message: &str) -> io::Result<(Vec<u8>, [u8; 12])> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes); // Fill the nonce with random bytes
    let nonce = AeadNonce::<Aes256Gcm>::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, message.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt_message(
    cipher: &Aes256Gcm,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Option<String> {
    let nonce = AeadNonce::<Aes256Gcm>::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => match String::from_utf8(plaintext) {
            Ok(message) => Some(message),
            Err(_) => {
                println!("Received binary data, not UTF-8 text");
                None
            }
        },
        Err(_) => {
            println!("Failed to decrypt message");
            None
        }
    }
}

pub async fn send_encrypted_packet(
    stream: &mut TcpStream,
    cipher: &Aes256Gcm,
    code: Codes,
    message: &str,
) -> io::Result<()> {
    let (ciphertext, nonce) = encrypt_message(cipher, message)?;

    let packet = Packet::new(code, nonce, ciphertext);

    let serialized_packet = serialize_packet(&packet)?;
    let packet_len = serialized_packet.len() as u32;

    // Send the length of the packet first
    stream.write_all(&packet_len.to_be_bytes()).await?;

    // Then send the serialized packet
    stream.write_all(&serialized_packet).await?;

    stream.flush().await?;

    Ok(())
}
