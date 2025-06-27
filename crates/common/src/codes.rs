// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub enum Codes {
    DISCONNECT,
    CONNECT,
    AUTH,
    PUBLIC_KEY_REQUEST,
    PUBLIC_KEY_RESPONSE,
    COMMAND,
    COMMAND_RESPONSE,
    REFRESH_SESSION
}
