// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

mod stream;
mod ui;

use common::codes::Codes;
use common::packet::{read_next_packet, send_packet, Stream};
use common::rw::get_input;
use iroh::{Endpoint, NodeAddr, NodeId};
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::str::FromStr;
use tokio::io::AsyncWriteExt;

use crate::stream::ClientStream;
use crate::ui::clear_screen;

#[tokio::main]
async fn main() {
    // [Connection name -> Stream]
    let mut connections: HashMap<String, ClientStream> = HashMap::new();

    ui::clear_screen();

    loop {
        match ui::prompt(&connections) {
            Ok(action) => match action {
                ui::Actions::AddConnection { name, key, tags } => {
                    if let Err(_) = add_connection(&mut connections, name, key, tags).await {
                        ui::show_message_and_wait("Connection failed");
                    }
                }
                ui::Actions::ListConnections => ui::print_connections(&connections),
                ui::Actions::RemoveConnection(name) => {
                    remove_connection(&mut connections, name).await
                }
                ui::Actions::SwitchConnection(name) => {
                    if let Some(stream) = connections.get_mut(&name) {
                        if let Err(_) = communication(stream).await {}
                    }
                }
                ui::Actions::RenameConnection { old_name, new_name } => {
                    if connections.contains_key(&new_name) {
                        ui::show_message_and_wait(&format!(
                            "Connection name '{}' already exists",
                            new_name
                        ));
                    } else if let Some(stream) = connections.remove(&old_name) {
                        connections.insert(new_name.clone(), stream);
                        ui::show_message_and_wait(&format!(
                            "Connection renamed from '{}' to '{}'",
                            old_name, new_name
                        ));
                    } else {
                        ui::show_message_and_wait(&format!("Connection '{}' not found", old_name));
                    }
                }
                ui::Actions::AddTags { name, tags } => {
                    if let Some(stream) = connections.get_mut(&name) {
                        let original_count = stream.tags.len();
                        stream.tags.extend(tags.clone());

                        let new_count = stream.tags.len();
                        let new_tags_count = new_count - original_count;

                        if new_tags_count > 0 {
                            ui::show_message_and_wait(&format!(
                                "{} new tag(s) added to {}",
                                new_tags_count, name
                            ));
                        } else {
                            ui::show_message_and_wait(&format!(
                                "All tags already exist for {}",
                                name
                            ));
                        }
                    } else {
                        ui::show_message_and_wait(&format!("Connection {} not found", name));
                    }
                }
                ui::Actions::RemoveTags { name, tags } => {
                    if let Some(stream) = connections.get_mut(&name) {
                        let mut removed_count = 0;
                        let mut not_found = Vec::new();

                        for tag in &tags {
                            if stream.tags.remove(tag) {
                                removed_count += 1;
                            } else {
                                // for tags that don't exist in the actual connection's tags
                                not_found.push(tag);
                            }
                        }

                        if removed_count > 0 {
                            let message = format!("{} tag(s) removed from {}", removed_count, name);
                            if !not_found.is_empty() {
                                let not_found_str = not_found
                                    .iter()
                                    .map(|s| s.as_str())
                                    .collect::<Vec<&str>>()
                                    .join(", ");
                                ui::show_message_and_wait(&format!(
                                    "{}. Tag(s) not found: {}",
                                    message, not_found_str
                                ));
                            } else {
                                ui::show_message_and_wait(&message);
                            }
                        } else {
                            ui::show_message_and_wait(&format!(
                                "No matching tags found for {}",
                                name
                            ));
                        }
                    } else {
                        ui::show_message_and_wait(&format!("Connection {} not found", name));
                    }
                }
                ui::Actions::RunCommandByTag(tag, command) => {
                    // Find all connections with this tag
                    let matching_connections: Vec<String> = connections
                        .iter()
                        .filter_map(|(name, stream)| {
                            if stream.tags.contains(&tag) {
                                Some(name.clone())
                            } else {
                                None
                            }
                        })
                        .collect();

                    if matching_connections.is_empty() {
                        ui::show_message_and_wait(&format!("No connections with tag '{}'", tag));
                        continue;
                    }

                    // Execute the command on all matching connections
                    ui::clear_screen();
                    println!("Executing '{}' on connections with tag '{}':", command, tag);
                    println!(
                        "Targeting {} connection(s): {}",
                        matching_connections.len(),
                        matching_connections.join(", ")
                    );
                    println!("\n--- Command Results ---\n");

                    // Run the command on each connection and collect outputs
                    for name in &matching_connections {
                        if let Some(stream) = connections.get_mut(name) {
                            println!("\n[{}]", name);

                            // We execute the command asynchronously
                            match async {
                                // Send command to the server
                                send_packet(
                                    &mut stream.stream,
                                    Codes::Command,
                                    &command,
                                )
                                .await?;

                                // Wait for the output
                                wait_command_output(stream).await?;

                                Ok::<(), io::Error>(())
                            }
                            .await
                            {
                                Ok(_) => {}
                                Err(err) => println!("Error: {}", err),
                            }
                        }
                    }

                    println!("\n--- End of results ---");

                    // Wait for user input before returning to menu
                    println!("\nPress Enter to continue...");

                    // Wait for any input to continue
                    let _ = std::io::stdin().read_line(&mut String::new());
                    ui::clear_screen();
                }
                ui::Actions::Quit => {
                    break;
                }
            },
            Err(_) => {
                continue;
            }
        }
    }
}

async fn add_connection(
    connections: &mut HashMap<String, ClientStream>,
    name: String,
    security_key: String,
    tags: HashSet<String>,
) -> io::Result<()> {
    let addr = NodeId::from_str(security_key.trim()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid security key format. Please provide a valid NodeId.",
        )
    })?;
    let node = NodeAddr::new(addr);

    let ep = Endpoint::builder().discovery_n0().bind().await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to bind endpoint: {}", e),
        )
    })?;
    let Ok(conn) = ep.connect(node, b"my-alpn").await else {
        println!("Failed to connect to the server. Please check the address and try again.");
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "Connection failed",
        ));
    };

    let current_stream = conn.open_bi().await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("Failed to open bidirectional stream: {}", e),
        )
    })?;
    let stream = Stream {
        security_key: addr.to_string(),
        send_stream: current_stream.0,
        recive_stream: current_stream.1,
    };

    // If the connection is successful, we set up a connection
    let mut stream = ClientStream::new(stream);
    stream.tags = tags;
    connections.insert(name, stream);

    Ok(())
}

async fn remove_connection(connections: &mut HashMap<String, ClientStream>, name: String) {
    if let Some(mut stream) = connections.remove(&name) {
        // If the connection is removed, we shutdown the stream
        stream
            .stream
            .send_stream
            .shutdown()
            .await
            .map_err(|e| {
                eprintln!("Failed to shutdown send stream: {}", e);
            })
            .ok();
        stream
            .stream
            .recive_stream
            .stop(0u32.into())
            .map_err(|e| {
                eprintln!("Failed to stop receive stream: {}", e);
            })
            .ok();
    }
}

async fn wait_command_output(stream: &mut ClientStream) -> io::Result<()> {
    loop {
        let packet_result = read_next_packet(&mut stream.stream).await;

        match packet_result {
            Ok(packet) => match packet.code {
                Codes::CommandOutput => {
                    
                        // Print the command output
                        print!("{}", String::from_utf8(packet.msg).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Received invalid UTF-8 data in command output",
                            )
                        })?);
                        std::io::stdout().flush().unwrap();
                    
                }
                Codes::CommandEnd => {
                    // We have reached the end of the command output
                    return Ok(());
                }
                _ => {}
            },
            Err(e) => {
                // Don't return error for timeout, just continue
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(e);
            }
        }
    }
}

async fn communication(stream: &mut ClientStream) -> io::Result<()> {
    // Initialize session and wait for initial prompt
    initialize_session(stream).await?;

    // Main command processing loop
    command_loop(stream).await?;

    Ok(())
}

async fn initialize_session(stream: &mut ClientStream) -> io::Result<()> {
    // Send a packet to refresh the session. Allow us to reset the session state on the server side
    send_packet(
        &mut stream.stream,
        Codes::RefreshSession,
        &String::new(),
    )
    .await?;

    // Read the initial command output from the server (usually the prompt of the shell)
    wait_for_initial_prompt(stream).await?;

    Ok(())
}

async fn wait_for_initial_prompt(stream: &mut ClientStream) -> io::Result<()> {
    loop {
        match read_next_packet(&mut stream.stream).await {
            Ok(packet) => match packet.code {
                Codes::CommandOutput => {
                    
                        print!("{}", String::from_utf8(packet.msg).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Received invalid UTF-8 data in command output",
                            )
                        })?);
                        std::io::stdout().flush().unwrap();
                    
                }
                Codes::CommandEnd => {
                    break;
                }
                _ => {}
            },
            Err(_) => break,
        }
    }
    Ok(())
}

async fn command_loop(stream: &mut ClientStream) -> io::Result<()> {
    loop {
        // Get the command input from the user
        let command = get_input("").trim().to_string();

        if command.is_empty() {
            continue;
        }

        if command == "%"
        /* Exit command */
        {
            clear_screen();
            break;
        }

        // Send and process the command
        execute_command(stream, &command).await?;
    }
    Ok(())
}

async fn execute_command(stream: &mut ClientStream, command: &str) -> io::Result<()> {
    // Send the command to the server
    send_packet(&mut stream.stream, Codes::Command, &command.to_owned()).await?;

    // Wait for the command output from the server
    wait_command_output(stream).await?;

    Ok(())
}
