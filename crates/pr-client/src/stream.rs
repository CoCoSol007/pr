// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use common::packet::Stream;
use std::collections::HashSet;

pub struct ClientStream {
    pub stream: Stream,
    pub tags: HashSet<String>,
}

impl ClientStream {
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            tags: HashSet::new(),
        }
    }
}