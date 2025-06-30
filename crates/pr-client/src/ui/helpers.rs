// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use crossterm::{
    cursor::MoveTo,
    execute,
    terminal::{Clear, ClearType},
};
use std::collections::{HashMap, HashSet};
use std::io::{self, Write, stdout};

use crate::stream;

/// Clear a single line at the specified row
pub fn clear_line(row: u16) -> io::Result<()> {
    execute!(stdout(), MoveTo(0, row), Clear(ClearType::CurrentLine))?;
    Ok(())
}

/// Clear multiple lines from start_row to end_row (inclusive)
pub fn clear_lines(start_row: u16, end_row: u16) -> io::Result<()> {
    for r in start_row..=end_row {
        clear_line(r)?;
    }
    Ok(())
}

/// Print text at a specific row position
pub fn print_at(row: u16, text: &str) -> io::Result<()> {
    execute!(stdout(), MoveTo(0, row))?;
    print!("{}", text);
    stdout().flush()?;
    Ok(())
}

/// Display all connections with their tags
pub fn display_connections(streams: &HashMap<String, stream::Stream>, row: u16) -> io::Result<u16> {
    let mut curr_row = row;
    for (name, stream) in streams {
        print_at(
            curr_row,
            &format!("{} [{}]", name, format_tags(&stream.tags)),
        )?;
        curr_row += 1;
    }
    Ok(curr_row)
}

/// Format tags into a readable string
pub fn format_tags(tags: &HashSet<String>) -> String {
    if tags.is_empty() {
        "no tags".to_string()
    } else {
        tags.iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Parse comma-separated tags into a HashSet
pub fn parse_tags(tags_str: &str) -> HashSet<String> {
    tags_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Clear the entire screen and move cursor to top-left
pub fn clear_screen() {
    execute!(
        stdout(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        MoveTo(0, 0)
    )
    .unwrap();
}
