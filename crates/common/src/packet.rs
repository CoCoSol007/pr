// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use super::codes::Codes;
use bincode::{self, config};
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

#[derive(Debug, Encode, Decode, Serialize, Deserialize)]
pub struct Packet {
    pub code: Codes,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl Packet {
    pub fn new(
        code: Codes,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            code,
            nonce,
            ciphertext
        }
    }
}

pub async fn read_next_packet(stream: &mut TcpStream) -> io::Result<Packet> {
    let packet_len = get_packet_length(stream).await?;
    let mut packet_data = vec![0u8; packet_len];
    stream.read_exact(&mut packet_data).await?;
    deserialize_packet(&packet_data)
}

pub async fn get_packet_length(stream: &mut TcpStream) -> Result<usize, std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    Ok(u32::from_be_bytes(len_buf) as usize)
}

pub fn deserialize_packet(data: &[u8]) -> Result<Packet, std::io::Error> {
    Ok(bincode::decode_from_slice(&data, config::standard())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Deserialization error: {}", e),
            )
        })?
        .0)
}

pub fn serialize_packet(packet: &Packet) -> Result<Vec<u8>, std::io::Error> {
    bincode::encode_to_vec(packet, config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Serialization error: {}", e)))
}
