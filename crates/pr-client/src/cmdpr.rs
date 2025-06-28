// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use crate::stream;
use crossterm::{
    cursor::MoveTo,
    event::{Event, KeyCode, read},
    execute,
    terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use std::collections::HashMap;
use std::io::{self, Write, stdout};

pub enum Actions {
    AddConnection {
        name: String,
        address: String,
        port: u16,
    },
    ListConnections,
    RemoveConnection(String),
    SwitchConnection(String),
    Quit,
}

fn reset(row: u16) -> io::Result<()> {
    clear_line(row)?;
    execute!(stdout(), MoveTo(0, row))?;
    Ok(())
}

fn clear_line(row: u16) -> io::Result<()> {
    execute!(stdout(), MoveTo(0, row), Clear(ClearType::CurrentLine))?;
    Ok(())
}

fn ask(prompt: &str, row: u16) -> io::Result<String> {
    reset(row)?;
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
                    reset(row)?;
                    return Ok(String::new()); // in the prompt function, an empty string indicates cancellation
                }
                KeyCode::Backspace => {
                    if !input.is_empty() {
                        input.pop();
                        reset(row)?;
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
    reset(row)?;
    Ok(input)
}

fn show_menu(row: u16) -> io::Result<()> {
    reset(row)?;
    print!("[A]dd [L]ist [R]emove [S]witch [Q]uit: ");
    stdout().flush()?;
    Ok(())
}

pub fn clear_screen() {
    execute!(
        stdout(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        MoveTo(0, 0)
    )
    .unwrap();
}

fn press_any_key(row: u16, msg: &str) -> io::Result<()> {
    execute!(stdout(), MoveTo(0, row))?;
    if msg.is_empty() {
        print!("Press any key");
    } else {
        print!("{} - Press any key", msg);
    }
    stdout().flush()?;

    enable_raw_mode()?;
    let _ = read()?;
    disable_raw_mode()?;
    clear_line(row)?;
    Ok(())
}

pub fn prompt(streams: &HashMap<String, stream::Stream>) -> io::Result<Actions> {
    let (_, term_rows) = crossterm::terminal::size()?;
    let row = term_rows - 1;

    loop {
        show_menu(row)?;

        enable_raw_mode()?;
        match read()? {
            Event::Key(key_event) => {
                disable_raw_mode()?;
                clear_line(row)?;

                match key_event.code {
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

                        return Ok(Actions::AddConnection {
                            name,
                            address,
                            port,
                        });
                    }
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        return Ok(Actions::ListConnections);
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        if streams.is_empty() {
                            press_any_key(row, "No connections available")?;
                            continue;
                        }

                        let mut curr_row = row;
                        for (name, _) in streams.iter() {
                            execute!(stdout(), MoveTo(0, curr_row))?;
                            print!("{}", name);
                            curr_row += 1;
                        }

                        let name = ask("Remove", curr_row)?;
                        for r in row..=curr_row {
                            clear_line(r)?;
                        }

                        if name.is_empty() {
                            continue;
                        } // Annulé
                        return Ok(Actions::RemoveConnection(name));
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        if streams.is_empty() {
                            press_any_key(row, "No connections available")?;
                            continue;
                        }

                        let mut curr_row = row;
                        for (name, _) in streams.iter() {
                            execute!(stdout(), MoveTo(0, curr_row))?;
                            print!("{}", name);
                            curr_row += 1;
                        }

                        let name = ask("Connect to", curr_row)?;
                        for r in row..=curr_row {
                            clear_line(r)?;
                        }

                        if name.is_empty() {
                            continue;
                        } // Annulé
                        return Ok(Actions::SwitchConnection(name));
                    }
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        return Ok(Actions::Quit);
                    }
                    _ => continue,
                }
            }
            _ => {
                disable_raw_mode()?;
                clear_line(row)?;
                continue;
            }
        };
    }
}

pub fn show_message_and_wait(message: &str) {
    let (_, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let _ = press_any_key(rows - 1, message);
}

pub fn print_connections(connections: &HashMap<String, stream::Stream>) {
    if connections.is_empty() {
        return show_message_and_wait("No connections");
    }

    let (_, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let start = rows.saturating_sub((connections.len() + 2) as u16);

    for r in start..rows {
        let _ = clear_line(r);
    }

    execute!(stdout(), MoveTo(0, start)).unwrap();
    print!("Connections ({})", connections.len());
    stdout().flush().unwrap();

    for (i, (name, stream)) in connections.iter().enumerate() {
        execute!(stdout(), MoveTo(0, start + 1 + i as u16)).unwrap();
        let addr = stream
            .stream
            .peer_addr()
            .map_or("disconnected".to_string(), |a| a.to_string());
        print!("  {} -> {}", name, addr);
        stdout().flush().unwrap();
    }

    let _ = press_any_key(start + 1 + connections.len() as u16, "");

    for r in start..=start + 1 + connections.len() as u16 {
        let _ = clear_line(r);
    }
}
