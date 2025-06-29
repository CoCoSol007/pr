// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub enum Codes {
    Disconnect,
    PublicKeyRequest,
    PublicKeyResponse,
    Command,
    CommandOutput,
    CommandEnd,
    RefreshSession,
}
