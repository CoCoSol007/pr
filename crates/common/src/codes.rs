// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

#[warn(non_camel_case_types)]

use serde::{Deserialize, Serialize};
use bincode::{Decode, Encode};

#[repr(u8)]
#[derive(Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub enum Codes {
    DISCONNECT = 0x00,
    CONNECT = 0x01,
    AUTH = 0x02,
    PUBLIC_KEY_REQUEST = 0x03,
    PUBLIC_KEY_RESPONSE = 0x04,
    COMMAND = 0x05,
}