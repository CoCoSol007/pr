// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use crossterm::{
    event::{Event, KeyCode, read},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::collections::HashMap;
use std::io::{self, Write, stdout};

use super::helpers::{clear_line, clear_lines, print_at};
use crate::stream;

/// Show an interactive prompt and get user input
pub fn ask(prompt: &str, row: u16) -> io::Result<String> {
    clear_line(row)?;
    print!("{}: ", prompt);
    stdout().flush()?;

    let mut input = String::new();

    enable_raw_mode()?;

    loop {
        match read()? {
            Event::Key(key_event) => match key_event.code {
                KeyCode::Enter => break,
                KeyCode::Esc => {
                    disable_raw_mode()?;
                    clear_line(row)?;
                    return Ok(String::new()); // Empty string indicates cancellation
                }
                KeyCode::Backspace => {
                    if !input.is_empty() {
                        input.pop();
                        clear_line(row)?;
                        print!("{}: {}", prompt, input);
                        stdout().flush()?;
                    }
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    print!("{}", c);
                    stdout().flush()?;
                }
                _ => {}
            },
            _ => {}
        }
    }

    disable_raw_mode()?;
    clear_line(row)?;
    Ok(input)
}

/// Ask for a selection from a list of connections
pub fn select_connection(
    streams: &HashMap<String, stream::Stream>,
    prompt: &str,
    row: u16,
) -> io::Result<String> {
    if streams.is_empty() {
        press_any_key(row, "No connections available")?;
        return Ok(String::new());
    }

    let mut curr_row = row;
    for (name, _) in streams.iter() {
        print_at(curr_row, name)?;
        curr_row += 1;
    }

    let name = ask(prompt, curr_row)?;
    clear_lines(row, curr_row)?;

    if name.is_empty() {
        return Ok(String::new());
    }

    if !streams.contains_key(&name) {
        press_any_key(row, &format!("Connection '{}' not found", name))?;
        return Ok(String::new());
    }

    Ok(name)
}

/// Display a message and wait for any key press
pub fn press_any_key(row: u16, msg: &str) -> io::Result<()> {
    let display_text = if msg.is_empty() {
        String::from("Press any key")
    } else {
        format!("{} - Press any key", msg)
    };

    print_at(row, &display_text)?;

    enable_raw_mode()?;
    let _ = read()?; // Read any key event
    disable_raw_mode()?;

    clear_line(row)?;
    Ok(())
}
