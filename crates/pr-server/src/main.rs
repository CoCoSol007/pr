// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

pub mod cli;

use aes_gcm::{Aes256Gcm, KeyInit};
use common::{
    cipher::{decrypt_message, send_encrypted_packet},
    codes::Codes,
    packet::{Packet, Stream, read_next_packet, serialize_packet},
};
use iroh::{Endpoint, SecretKey};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::{
    ForkptyResult::{Child, Parent},
    forkpty,
};
use nix::unistd::{execvp, read, write};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{env, ffi::CString, fs};
use std::io;
use std::os::fd::OwnedFd;
use std::sync::mpsc;
use tokio::task;
use x25519_dalek::{EphemeralSecret, PublicKey};

struct SecureConnection {
    pub stream: Stream,
    pub cipher: Aes256Gcm,
    pub pty_fd: Option<OwnedFd>,
    pub child_fd: Option<nix::unistd::Pid>,
    pub command_sender: Option<mpsc::Sender<String>>,
    pub output_receiver: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
}

#[tokio::main]
async fn main() -> io::Result<()> {

    let path = env::home_dir()
        .expect("Failed to get home directory")
        .join(".pr");
    let file_path = path.join("private_key"); // Utilisez join() au lieu de concaténation

    let save_key = fs::read_to_string(&file_path);

    let secret_key = match save_key {
        Ok(key) => {
            let key = key.trim(); // Supprimez les espaces/retours à la ligne
            let key_bytes = hex::decode(key)
                .expect("Failed to decode private key from hex");
            let key_array: [u8; 32] = key_bytes
                .try_into()
                .expect("Private key must be 32 bytes");
            SecretKey::from_bytes(&key_array)
        }
        Err(_) => {
            eprintln!("No private key found, generating a new one");
            let secret_key = SecretKey::generate(rand::rngs::OsRng);
            
            fs::create_dir_all(&path).expect("Failed to create directory for private key");
            // Sauvegardez en hex pour être cohérent avec la lecture
            let hex_key = hex::encode(secret_key.to_bytes());
            fs::write(&file_path, hex_key).expect("Failed to write private key");
            secret_key
        }
    };

    let created_endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![b"my-alpn".to_vec()])
        .discovery_n0()
        .bind()
        .await;

    let Ok(endpoint) = created_endpoint else {
        eprintln!("Failed to bind endpoint: {:?}", created_endpoint.err());
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to bind endpoint",
        ));
    };

    println!("Public key: {}", endpoint.node_id());

    loop {
        let conn = endpoint
            .accept()
            .await
            .expect("Failed to accept connection")
            .await
            .expect("Failed to accept connection stream");

        let Ok(recv_stream) = conn.accept_bi().await else {
            eprintln!("Failed to accept bidirectional stream");
            continue;
        };

        let stream: Stream = Stream {
            security_key: endpoint.node_id().to_string(),
            send_stream: recv_stream.0,
            recive_stream: recv_stream.1,
        };

        println!("New connection");

        tokio::spawn(async move {
            match setup_secure_connection(stream).await {
                Ok(secure_conn) => {
                    // If the secure connection is established, handle communication
                    if let Err(e) = handle_secure_communication(secure_conn).await {
                        eprintln!("Error during secure communication: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Error setting up secure connection : {}", e);
                }
            }
        });
    }
}

// PTY stands for "pseudo-terminal" and is used to create a terminal interface
fn create_pty() -> io::Result<(OwnedFd, nix::unistd::Pid)> {
    match unsafe { forkpty(None, None).expect("Failed to fork PTY") } {
        // Corresponds to the parent process that creates the PTY
        Parent { child, master } => Ok((master, child)),

        // Corresponds to the child process that executes the shell
        Child => {
            let args = [
                CString::new("/bin/bash").unwrap(),
                CString::new("-l").unwrap(), // Start a login shell
            ];

            // Execute bash in the child process
            let _ = execvp(&args[0], &args);
            eprintln!("Failed to execute shell");
            std::process::exit(1);
        }
    }
}

async fn handle_secure_communication(mut conn: SecureConnection) -> io::Result<()> {
    // Create a PTY and fork the child process
    let (pty_master, child_pid) = create_pty()?;

    // Create a channel for sending commands to the PTY handler
    let (cmd_tx, cmd_rx) = mpsc::channel::<String>();

    conn.pty_fd = Some(pty_master.try_clone()?);
    conn.child_fd = Some(child_pid);
    conn.command_sender = Some(cmd_tx);

    // Start the PTY handler in a separate thread
    start_pty_handler(&mut conn, pty_master, cmd_rx);

    // Allow some time for the PTY handler to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Process incoming commands from the client
    process_client_commands(&mut conn).await?;

    // If we're here it means the client has disconnected or requested a disconnect
    // We terminate the child process gracefully
    if let Some(pid) = conn.child_fd {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
    }

    Ok(())
}

fn start_pty_handler(
    conn: &mut SecureConnection,
    pty_master: OwnedFd,
    cmd_rx: mpsc::Receiver<String>,
) {
    // Allow non-blocking reads the master PTY
    let current_flags = fcntl(&pty_master, FcntlArg::F_GETFL).expect("Failed to get fd flags");
    let new_flags = OFlag::from_bits_truncate(current_flags) | OFlag::O_NONBLOCK;
    fcntl(&pty_master, FcntlArg::F_SETFL(new_flags)).expect("Failed to set fd flags");

    // Create a channel for sending output back to the client
    let (output_tx, output_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    conn.output_receiver = Some(output_rx);

    // Spawn a blocking task to handle the PTY
    task::spawn_blocking(move || {
        // Initialize PTY and send initial prompt
        initialize_pty_and_send_prompt(&pty_master, &output_tx);

        // Main PTY processing loop
        pty_main_loop(pty_master, cmd_rx, output_tx);
    });
}

fn initialize_pty_and_send_prompt(
    pty_master: &OwnedFd,
    output_tx: &tokio::sync::mpsc::UnboundedSender<String>,
) {
    let mut buffer = [0u8; 4096];

    // Clear the PTY
    write(pty_master, "clear\n".as_bytes()).expect("Failed to clear PTY");
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Read the initial prompt after clear
    let mut initial_output = String::new();
    loop {
        match read(pty_master, &mut buffer) {
            Ok(n) if n > 0 => {
                let output = String::from_utf8_lossy(&buffer[0..n]).to_string();
                initial_output.push_str(&output);
            }
            Err(e) if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EWOULDBLOCK => {
                break;
            }
            _ => break,
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Send the initial output to the client (usually the prompt of the shell)
    if !initial_output.is_empty() {
        let _ = output_tx.send(initial_output);
    }
}

fn pty_main_loop(
    pty_master: OwnedFd,
    cmd_rx: mpsc::Receiver<String>,
    output_tx: tokio::sync::mpsc::UnboundedSender<String>,
) {
    let mut buffer = [0u8; 4096];

    loop {
        // Check if there is a command to execute
        if let Ok(cmd) = cmd_rx.try_recv() {
            if cmd == "__REFRESH__" {
                handle_refresh_command(&pty_master, &output_tx, &mut buffer);
            } else {
                execute_command(&pty_master, &cmd, &output_tx, &mut buffer);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn handle_refresh_command(
    pty_master: &OwnedFd,
    output_tx: &tokio::sync::mpsc::UnboundedSender<String>,
    buffer: &mut [u8; 4096],
) {
    // Clear the PTY screen like we do on initial connection
    write(pty_master, "clear\n".as_bytes()).ok();

    // Wait a bit for the clear command to execute
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Read any remaining output including the prompt after clear
    let mut counter = 0;
    let mut refresh_output = String::new();
    while counter < 20 {
        match read(pty_master, buffer) {
            Ok(n) if n > 0 => {
                let output = String::from_utf8_lossy(&buffer[0..n]).to_string();
                refresh_output.push_str(&output);
                counter = 0;
            }
            _ => counter += 1,
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Send the output (which should include the prompt) to show current state
    if !refresh_output.is_empty() {
        let _ = output_tx.send(refresh_output);
    }

    let _ = output_tx.send("__COMMAND_END__".to_string());
}

fn execute_command(
    pty_master: &OwnedFd,
    cmd: &str,
    output_tx: &tokio::sync::mpsc::UnboundedSender<String>,
    buffer: &mut [u8; 4096],
) {
    // Execute the command on the PTY
    if let Err(e) = write(pty_master, format!("{}\n", cmd).as_bytes()) {
        eprintln!("Failed to write command: {}", e);
        return;
    }

    let mut counter = 0;
    let mut skipped = false;

    // Read the output of the command
    while counter < 50 {
        match read(pty_master, buffer) {
            // Successfully read some data
            Ok(n) if n > 0 => {
                let output = String::from_utf8_lossy(&buffer[0..n]).to_string();

                // The first output with at the beginning the command itself
                if !skipped {
                    if let Some(pos) = output.find('\n') {
                        // We remove the command line and send everything that follows
                        let filtered = &output[pos + 1..];
                        if !filtered.is_empty() {
                            let _ = output_tx.send(filtered.to_string());
                        }
                        skipped = true;
                    }
                } else {
                    // After skipping the command line, we send everything directly
                    if !output.is_empty() {
                        let _ = output_tx.send(output);
                    }
                }
                counter = 0;
            }
            // Non-blocking error
            Err(e) if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EWOULDBLOCK => {
                counter += 1;
            }
            // Unrecoverable error
            Err(e) => {
                if e == nix::errno::Errno::EBADF {
                    return;
                }
                break;
            }
            _ => {
                counter += 1;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // If we got here, it means the command has ended
    let _ = output_tx.send("__COMMAND_END__".to_string());
}

// Handle asynchronously sending output from the PTY handler to the client
async fn handle_output_sender(
    mut output_receiver: tokio::sync::mpsc::UnboundedReceiver<String>,
    packet_sender: tokio::sync::mpsc::UnboundedSender<(Codes, String)>,
) {
    // Continuously receive output from the PTY handler and send it to the client
    while let Some(output) = output_receiver.recv().await {
        if output == "__COMMAND_END__" {
            let _ = packet_sender.send((Codes::CommandEnd, String::new()));
        } else {
            let _ = packet_sender.send((Codes::CommandOutput, output));
        }
    }
}

//     A
//     |
//     |
// They are communicating with each other
//     |
//     |
//     v

async fn process_client_commands(conn: &mut SecureConnection) -> io::Result<()> {
    let stream = &mut conn.stream;

    // Create channel for packets to send
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel::<(Codes, String)>();

    // Spawn task to handle output sending
    if let Some(output_receiver) = conn.output_receiver.take() {
        tokio::spawn(handle_output_sender(output_receiver, packet_tx));
    }

    loop {
        tokio::select! {
            // Handle packets to send to client
            Some((code, data)) = packet_rx.recv() => {
                send_encrypted_packet(stream, &conn.cipher, code, &data).await?;
            }

            // Handle incoming packets from client
            packet_result = read_next_packet(stream) => {
                match packet_result {
                    Ok(packet) => match packet.code {
                        Codes::Disconnect => {
                            println!("Client requested disconnect");
                            return Ok(());
                        }
                        Codes::RefreshSession => {
                            if let Some(tx) = &conn.command_sender {
                                let _ = tx.send("__REFRESH__".to_string());
                            }
                        }
                        Codes::Command => {
                            if let Some(cmd) =
                                decrypt_message(&conn.cipher, &packet.nonce, &packet.ciphertext)
                            {
                                if let Some(tx) = &conn.command_sender {
                                    // We send the command to the PTY handler
                                    let _ = tx.send(cmd);
                                }
                            }
                        }
                        _ => {}
                    },
                    Err(e) => {
                        if e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::TimedOut {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

async fn setup_secure_connection(mut stream: Stream) -> io::Result<SecureConnection> {
    let stream_ref = &mut stream;

    // We read the first packet from the client, which should contain the public key request
    let client_packet = read_next_packet(stream_ref).await?;
    if client_packet.code != Codes::PublicKeyRequest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected PUBLIC_KEY_REQUEST",
        ));
    }

    // The client should send his public key of 32 bytes length
    if client_packet.ciphertext.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid public key length",
        ));
    }

    // Convert the client's public key from bytes to a PublicKey
    let mut client_key_bytes = [0u8; 32];
    client_key_bytes.copy_from_slice(&client_packet.ciphertext);
    let client_pub_key = PublicKey::from(client_key_bytes);

    // Generate an ephemeral secret key for the server and derive the public key from it
    let server_priv_key = EphemeralSecret::random_from_rng(OsRng);
    let server_pub_key = PublicKey::from(&server_priv_key);

    // We create the response packet containing the server's public key
    let response_packet = Packet::new(
        Codes::PublicKeyResponse,
        [0; 12],
        server_pub_key.as_bytes().to_vec(),
    );

    // We serialize the response packet
    let serialized_response = serialize_packet(&response_packet)?;
    let response_len = serialized_response.len() as u32;

    // We send the length of the response packet first
    stream_ref
        .send_stream
        .write_all(&response_len.to_be_bytes())
        .await?;

    // Then we send the serialized response packet
    stream_ref
        .send_stream
        .write_all(&serialized_response)
        .await?;

    // Now we can compute the shared secret using Diffie-Hellman
    let shared_secret = server_priv_key.diffie_hellman(&client_pub_key);

    // Hash the shared secret to derive the encryption key, again using SHA-256 (for maximum entropy and constant size)
    let mut hasher = Sha256::default();
    hasher.update(shared_secret.as_bytes());
    let encryption_key = hasher.finalize();

    // Initialize the AES-256-GCM cipher with the derived encryption key
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to initialize cipher"))?;

    // Create the secure connection object
    let secure_conn = SecureConnection {
        stream,
        cipher,
        pty_fd: None,
        child_fd: None,
        command_sender: None,
        output_receiver: None,
    };

    println!("Secure connection established with client");

    Ok(secure_conn)
}
