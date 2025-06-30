// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use crossterm::{
    event::{Event, KeyCode, read},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::collections::{HashMap, HashSet};
use std::io::{self, Write, stdout};

use super::actions::Actions;
use super::helpers::{
    clear_line, clear_lines, display_connections, format_tags, parse_tags, print_at,
};
use super::input::{ask, press_any_key, select_connection};
use crate::stream;

/// Display the main menu options
fn show_menu(row: u16) -> io::Result<()> {
    clear_line(row)?;
    print!("[A]dd [L]ist [R]emove [S]witch [M]odify [D]ispatch [Q]uit: ");
    stdout().flush()?;
    Ok(())
}

/// Display the modify submenu options
fn show_modify_menu(row: u16) -> io::Result<()> {
    clear_line(row)?;
    print!("[N]ame [A]dd tag [R]emove tag [B]ack: ");
    stdout().flush()?;
    Ok(())
}

/// Handle adding tags to a connection
pub fn handle_add_tags(
    streams: &HashMap<String, stream::Stream>,
    row: u16,
) -> io::Result<Option<Actions>> {
    let mut curr_row = row;
    curr_row = display_connections(streams, curr_row)?;

    let name = ask("Connection name", curr_row)?;
    if name.is_empty() {
        clear_lines(row, curr_row)?;
        return Ok(None);
    }

    if !streams.contains_key(&name) {
        clear_lines(row, curr_row)?;
        press_any_key(row, &format!("Connection '{}' not found", name))?;
        return Ok(None);
    }

    let tags_str = ask("Tags to add (comma-separated)", curr_row + 1)?;
    clear_lines(row, curr_row + 1)?;

    if tags_str.is_empty() {
        press_any_key(row, "No tags specified")?;
        return Ok(None);
    }

    let tags = parse_tags(&tags_str);
    if tags.is_empty() {
        press_any_key(row, "No valid tags specified")?;
        return Ok(None);
    }

    Ok(Some(Actions::AddTags { name, tags }))
}

/// Handle removing tags from a connection
pub fn handle_remove_tags(
    streams: &HashMap<String, stream::Stream>,
    row: u16,
) -> io::Result<Option<Actions>> {
    let mut curr_row = row;
    curr_row = display_connections(streams, curr_row)?;

    let name = ask("Connection name", curr_row)?;
    if name.is_empty() {
        clear_lines(row, curr_row)?;
        return Ok(None);
    }

    if !streams.contains_key(&name) {
        clear_lines(row, curr_row)?;
        press_any_key(row, &format!("Connection '{}' not found", name))?;
        return Ok(None);
    }

    if let Some(stream) = streams.get(&name) {
        if stream.tags.is_empty() {
            clear_lines(row, curr_row)?;
            press_any_key(row, &format!("Connection '{}' has no tags to remove", name))?;
            return Ok(None);
        }

        print_at(
            curr_row + 1,
            &format!("Available tags: {}", format_tags(&stream.tags)),
        )?;
    }

    let tags_str = ask("Tags to remove (comma-separated)", curr_row + 2)?;
    clear_lines(row, curr_row + 2)?;

    if tags_str.is_empty() {
        press_any_key(row, "No tags specified")?;
        return Ok(None);
    }

    let tags = parse_tags(&tags_str);
    if tags.is_empty() {
        press_any_key(row, "No valid tags specified")?;
        return Ok(None);
    }

    Ok(Some(Actions::RemoveTags { name, tags }))
}

/// Handle dispatching commands to tagged connections
pub fn handle_dispatch(
    streams: &HashMap<String, stream::Stream>,
    row: u16,
) -> io::Result<Option<Actions>> {
    // Collect all unique tags in the system
    let mut all_tags: HashSet<String> = HashSet::new();
    let mut tag_counts: HashMap<String, Vec<String>> = HashMap::new();

    for (name, stream) in streams.iter() {
        for tag in &stream.tags {
            all_tags.insert(tag.clone());
            tag_counts
                .entry(tag.clone())
                .or_insert_with(Vec::new)
                .push(name.clone());
        }
    }

    if all_tags.is_empty() {
        press_any_key(row, "No tags defined in any connections")?;
        return Ok(None);
    }

    // Display available tags
    let mut curr_row = row;
    print_at(curr_row, "Available tags:")?;
    curr_row += 1;

    let mut sorted_tags: Vec<&String> = all_tags.iter().collect();
    sorted_tags.sort();

    for tag in sorted_tags {
        let connections = tag_counts.get(tag).unwrap();
        print_at(
            curr_row,
            &format!(
                "  {} ({} connection{})",
                tag,
                connections.len(),
                if connections.len() == 1 { "" } else { "s" }
            ),
        )?;
        curr_row += 1;
    }

    let tag = ask("Tag (connections to target)", curr_row)?;
    if tag.is_empty() {
        clear_lines(row, curr_row)?;
        return Ok(None);
    }

    if !all_tags.contains(&tag) {
        clear_lines(row, curr_row)?;
        press_any_key(row, &format!("Tag '{}' not found", tag))?;
        return Ok(None);
    }

    if let Some(target_connections) = tag_counts.get(&tag) {
        print_at(
            curr_row + 1,
            &format!("Will dispatch to: {}", target_connections.join(", ")),
        )?;
    }

    let command = ask("Command to dispatch", curr_row + 2)?;
    if command.is_empty() {
        clear_lines(row, curr_row + 2)?;
        return Ok(None);
    }

    clear_lines(row, curr_row + 2)?;
    Ok(Some(Actions::RunCommandByTag(tag, command)))
}

/// Handle the modify menu options
pub fn handle_modify_menu(
    streams: &HashMap<String, stream::Stream>,
    row: u16,
) -> io::Result<Option<Actions>> {
    if streams.is_empty() {
        press_any_key(row, "No connections available")?;
        return Ok(None);
    }

    // Show submenu for modification operations
    show_modify_menu(row)?;

    enable_raw_mode()?;
    let action = match read()? {
        Event::Key(key_event) => {
            disable_raw_mode()?;
            clear_line(row)?;

            match key_event.code {
                KeyCode::Char('b') | KeyCode::Char('B') => {
                    return Ok(None); // Return to main menu
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    // Rename connection
                    let mut curr_row = row;
                    for (name, _) in streams.iter() {
                        print_at(curr_row, name)?;
                        curr_row += 1;
                    }

                    let old_name = ask("Connection to rename", curr_row)?;
                    if old_name.is_empty() {
                        clear_lines(row, curr_row)?;
                        return Ok(None);
                    }

                    if !streams.contains_key(&old_name) {
                        clear_lines(row, curr_row)?;
                        press_any_key(row, &format!("Connection '{}' not found", old_name))?;
                        return Ok(None);
                    }

                    let new_name = ask("New name", curr_row + 1)?;
                    clear_lines(row, curr_row + 1)?;

                    if new_name.is_empty() {
                        return Ok(None);
                    }

                    Some(Actions::RenameConnection { old_name, new_name })
                }
                KeyCode::Char('a') | KeyCode::Char('A') => match handle_add_tags(streams, row)? {
                    Some(action) => Some(action),
                    None => return Ok(None),
                },
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    match handle_remove_tags(streams, row)? {
                        Some(action) => Some(action),
                        None => return Ok(None),
                    }
                }
                _ => return Ok(None),
            }
        }
        _ => {
            disable_raw_mode()?;
            clear_line(row)?;
            return Ok(None);
        }
    };

    Ok(action)
}

/// Main function processing user input and actions
pub fn prompt(streams: &HashMap<String, stream::Stream>) -> io::Result<Actions> {
    let (_, term_rows) = crossterm::terminal::size()?;
    let row = term_rows - 1;

    loop {
        show_menu(row)?;

        enable_raw_mode()?;
        let action = match read()? {
            Event::Key(key_event) => {
                disable_raw_mode()?;
                clear_line(row)?;

                match key_event.code {
                    // Add connection
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        let name = ask("Name", row)?;
                        if name.is_empty() {
                            continue;
                        }

                        let address = ask("Address", row)?;
                        if address.is_empty() {
                            continue;
                        }

                        let port_str = ask("Port (default: 1736)", row)?;
                        let port = if port_str.is_empty() {
                            1736
                        } else {
                            port_str.parse::<u16>().unwrap_or(1736)
                        };

                        let tags_str = ask("Tags (comma-separated, optional)", row)?;
                        let tags = if tags_str.is_empty() {
                            HashSet::new()
                        } else {
                            parse_tags(&tags_str)
                        };

                        Actions::AddConnection {
                            name,
                            address,
                            port,
                            tags,
                        }
                    }
                    KeyCode::Char('l') | KeyCode::Char('L') => Actions::ListConnections,
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        let name = select_connection(streams, "Remove", row)?;
                        if name.is_empty() {
                            continue;
                        }
                        Actions::RemoveConnection(name)
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        let name = select_connection(streams, "Connect to", row)?;
                        if name.is_empty() {
                            continue;
                        }
                        Actions::SwitchConnection(name)
                    }
                    KeyCode::Char('m') | KeyCode::Char('M') => {
                        match handle_modify_menu(streams, row)? {
                            Some(action) => action,
                            None => continue,
                        }
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        match handle_dispatch(streams, row)? {
                            Some(action) => action,
                            None => continue,
                        }
                    }
                    KeyCode::Char('q') | KeyCode::Char('Q') => Actions::Quit,
                    _ => continue,
                }
            }
            _ => {
                disable_raw_mode()?;
                clear_line(row)?;
                continue;
            }
        };

        return Ok(action);
    }
}
