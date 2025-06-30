// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use aes_gcm::Aes256Gcm;
use common::packet::Stream;
use std::collections::HashSet;

pub struct ClientStream {
    pub stream: Stream,
    pub cipher: Aes256Gcm,
    pub tags: HashSet<String>,
}
