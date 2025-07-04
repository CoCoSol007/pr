// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use super::codes::Codes;
use bincode::{self, config};
use bincode::{Decode, Encode};
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use std::io;

pub struct Stream {
    pub send_stream: SendStream,
    pub recive_stream: RecvStream,
    pub security_key: String, 
}

#[derive(Debug, Encode, Decode, Serialize, Deserialize)]
pub struct Packet {
    pub code: Codes,
    pub msg: Vec<u8>,
}

impl Packet {
    pub fn new(code: Codes, msg: Vec<u8>) -> Self {
        Self {
            code,
            msg,
        }
    }
}

pub async fn read_next_packet(stream: &mut Stream) -> io::Result<Packet> {
    let packet_len = get_packet_length(stream).await?;
    let mut packet_data = vec![0u8; packet_len];

    // Read the exact number of bytes specified by packet_len
    stream
        .recive_stream
        .read_exact(&mut packet_data)
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Failed to read packet data: {}", e),
            )
        })?;
    deserialize_packet(&packet_data)
}

// Reads the first 4 bytes from the stream to determine the length of the packet
pub async fn get_packet_length(stream: &mut Stream) -> Result<usize, std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream
        .recive_stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Failed to read packet length: {}", e),
            )
        })?;
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

pub async fn send_packet(
    stream: &mut Stream,
    code: Codes,
    msg: &String,
) -> Result<(), std::io::Error> {

    let packet = Packet::new(code, msg.clone().into_bytes());
    
    let serialized_packet = serialize_packet(&packet)?;
    let packet_len = serialized_packet.len() as u32;

    // Send the length of the packet first
    stream.send_stream.write_all(&packet_len.to_be_bytes()).await?;

    // Then send the serialized packet
    stream.send_stream.write_all(&serialized_packet).await?;

    stream.send_stream.flush().await?;

    Ok(())
}