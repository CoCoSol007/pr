// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use super::codes::Codes;
use bincode::{self, config};
use bincode::{Decode, Encode};
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::io;

pub struct Stream {
    pub recive_stream: RecvStream,
    pub send_stream: SendStream,
}

#[derive(Debug, Encode, Decode, Serialize, Deserialize)]
pub struct Packet {
    pub code: Codes,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl Packet {
    pub fn new(code: Codes, nonce: [u8; 12], ciphertext: Vec<u8>) -> Self {
        Self {
            code,
            nonce,
            ciphertext,
        }
    }
}

pub async fn read_next_packet(stream: &mut Stream) -> io::Result<Packet> {
    let packet_len = get_packet_length(stream).await?;
    let mut packet_data = vec![0u8; packet_len];

    // Read the exact number of bytes specified by packet_len
    stream.recive_stream.read_exact(&mut packet_data).await;
    deserialize_packet(&packet_data)
}

// Reads the first 4 bytes from the stream to determine the length of the packet
pub async fn get_packet_length(stream: &mut Stream) -> Result<usize, std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream.recive_stream.read_exact(&mut len_buf).await;
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
