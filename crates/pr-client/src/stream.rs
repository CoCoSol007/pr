// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use aes_gcm::Aes256Gcm;
use tokio::net::TcpStream;

pub struct Stream {
    pub stream: TcpStream,
    pub cipher: Aes256Gcm,
}
