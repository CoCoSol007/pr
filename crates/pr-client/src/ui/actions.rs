// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use std::collections::HashSet;

/// Actions that can be performed in the client
#[derive(Debug)]
pub enum Actions {
    AddConnection {
        name: String,
        address: String,
        port: u16,
        tags: HashSet<String>,
    },
    ListConnections,
    RemoveConnection(String),
    RenameConnection {
        old_name: String,
        new_name: String,
    },
    SwitchConnection(String),
    AddTags {
        name: String,
        tags: HashSet<String>,
    },
    RemoveTags {
        name: String,
        tags: HashSet<String>,
    },
    RunCommandByTag(String, String), // tag, command
    Quit,
}
