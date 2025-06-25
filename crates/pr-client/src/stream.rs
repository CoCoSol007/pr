// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use aes_gcm::Aes256Gcm;
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct Stream {
    pub stream: TcpStream,
    // pub is_connected: bool,
    pub priv_key: EphemeralSecret,
    pub pub_key: PublicKey,
    pub rem_pub_key: PublicKey,
    pub cipher: Aes256Gcm,
}
