// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use std::collections::HashMap;

use super::helpers::{clear_line, format_tags, print_at};
use super::input::press_any_key;
use crate::stream::ClientStream;

/// Display a message and wait for key press
pub fn show_message_and_wait(message: &str) {
    let (_, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let _ = press_any_key(rows - 1, message);
}

/// Display all connections with their details
pub fn print_connections(connections: &HashMap<String, ClientStream>) {
    if connections.is_empty() {
        return show_message_and_wait("No connections");
    }

    let (width, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let start = rows.saturating_sub((connections.len() + 2) as u16);

    for r in start..rows {
        let _ = clear_line(r);
    }

    let _ = print_at(start, &format!("Connections ({})", connections.len()));

    for (i, (name, stream)) in connections.iter().enumerate() {
        let addr = stream.stream.security_key.to_string(); // Assuming `id()` returns a string representation of the address
        let mut display_line = format!("  {} -> {}", name, addr);

        // Add tags if present
        if !stream.tags.is_empty() {
            let tags_str = format_tags(&stream.tags);

            // Ensure the tags fit in the terminal width
            let max_tag_length = width.saturating_sub(display_line.len() as u16 + 8) as usize;
            let tags_display = if tags_str.len() > max_tag_length {
                format!("{}...", &tags_str[..max_tag_length.saturating_sub(3)])
            } else {
                tags_str
            };

            display_line.push_str(&format!(" [{}]", tags_display));
        }

        let _ = print_at(start + 1 + i as u16, &display_line);
    }

    let _ = press_any_key(start + 1 + connections.len() as u16, "");

    for r in start..=start + 1 + connections.len() as u16 {
        let _ = clear_line(r);
    }
}
