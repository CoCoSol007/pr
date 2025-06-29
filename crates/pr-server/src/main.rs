// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

pub mod cli;

use aes_gcm::{Aes256Gcm, KeyInit};
use common::{
    cipher::{decrypt_message, send_encrypted_packet},
    codes::Codes,
    packet::{Packet, read_next_packet, serialize_packet},
};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::{
    ForkptyResult::{Child, Parent},
    forkpty,
};
use nix::unistd::{execvp, read, write};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::mpsc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task;
use x25519_dalek::{EphemeralSecret, PublicKey};

struct SecureConnection {
    pub stream: TcpStream,
    pub cipher: Aes256Gcm,
    pub pty_fd: Option<OwnedFd>,
    pub child_fd: Option<nix::unistd::Pid>,
    pub command_sender: Option<mpsc::Sender<String>>,
    pub output_receiver: Option<mpsc::Receiver<String>>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = cli::main();
    let address = format!("127.0.0.1:{}", args.port);
    let listener = TcpListener::bind(&address).await?;
    println!("Server listening on {}", address);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("New connection from: {}", addr);
                tokio::spawn(async move {
                    match setup_secure_connection(stream).await {
                        Ok(secure_conn) => {
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
            Err(e) => {
                eprintln!("Could not accept connection : {}", e);
            }
        }
    }
}

fn create_pty() -> io::Result<(OwnedFd, nix::unistd::Pid)> {
    match unsafe { forkpty(None, None).expect("Failed to fork PTY") } {
        Parent { child, master } => Ok((master, child)),
        Child => {
            let args = [
                CString::new("/bin/bash").unwrap(),
                CString::new("-l").unwrap(),
            ];

            let _ = execvp(&args[0], &args);
            eprintln!("Failed to execute shell");
            std::process::exit(1);
        }
    }
}

async fn handle_secure_communication(mut conn: SecureConnection) -> io::Result<()> {
    let (pty_master, child_pid) = create_pty()?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<String>();

    conn.pty_fd = Some(pty_master.try_clone()?);
    conn.child_fd = Some(child_pid);
    conn.command_sender = Some(cmd_tx);

    start_pty_handler(&mut conn, pty_master, cmd_rx);

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    process_client_commands(&mut conn).await?;

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

    let (output_tx, output_rx) = mpsc::channel::<String>();

    conn.output_receiver = Some(output_rx);

    let mut buffer = [0u8; 4096];
    let mut initial_output = String::new();

    // Clear the PTY
    write(&pty_master, "clear\n".as_bytes()).expect("Failed to clear PTY");

    std::thread::sleep(std::time::Duration::from_millis(200));

    task::spawn_blocking(move || {
        loop {
            // Read essentially the prompt as we just cleared the PTY
            match read(&pty_master, &mut buffer) {
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

        if !initial_output.is_empty() {
            output_tx.send(initial_output).ok();
        }

        loop {
            // Check if there is a command to execute
            if let Ok(cmd) = cmd_rx.try_recv() {
                if cmd.trim().is_empty() {
                    // used to refresh the session
                    let mut counter = 0;
                    while counter < 10 {
                        match read(&pty_master, &mut buffer) {
                            Ok(n) if n > 0 => counter = 0,
                            _ => counter += 1,
                        }
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }

                    output_tx.send("__COMMAND_END__".to_string()).ok();
                    continue;
                }

                // We execute the command on the PTY
                if let Err(e) = write(&pty_master, format!("{}\n", cmd).as_bytes()) {
                    eprintln!("Failed to write command: {}", e);
                    continue;
                }

                let mut counter = 0;
                let mut skipped = false;

                // Read the output of the command
                while counter < 50 {
                    match read(&pty_master, &mut buffer) {
                        Ok(n) if n > 0 => {
                            let output = String::from_utf8_lossy(&buffer[0..n]).to_string();

                            // The first output with at the beginning the command itself
                            if !skipped {
                                if let Some(pos) = output.find('\n') {
                                    // We remove the command line and send everything that follows
                                    let filtered = &output[pos + 1..];
                                    if !filtered.is_empty() {
                                        output_tx.send(filtered.to_string()).ok();
                                    }
                                    skipped = true;
                                }
                            } else {
                                // After skipping the command line, we send everything directly
                                if !output.is_empty() {
                                    output_tx.send(output).ok();
                                }
                            }
                            counter = 0;
                        }
                        // Non-blocking error
                        Err(e)
                            if e == nix::errno::Errno::EAGAIN
                                || e == nix::errno::Errno::EWOULDBLOCK =>
                        {
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
                output_tx.send("__COMMAND_END__".to_string()).ok();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
}

async fn process_client_commands(conn: &mut SecureConnection) -> io::Result<()> {
    let stream = &mut conn.stream;

    loop {
        // ------------------------------------
        // EVENTUALLY READING COMMANDS'S OUTPUT

        // This check shouldn't even be here because it checks whether or not some output is available from previous commands
        if let Some(receiver) = &mut conn.output_receiver {
            while let Ok(output) = receiver.try_recv() {
                // Means that the command has ended, so we warn the client
                if output == "__COMMAND_END__" {
                    send_encrypted_packet(stream, &conn.cipher, Codes::CommandEnd, "").await?;
                } else {
                    send_encrypted_packet(stream, &conn.cipher, Codes::CommandOutput, &output)
                        .await?;
                }
            }
        }

        // ----------------------------
        // WAITING FOR CLIENTS COMMANDS

        // Read packet or timeout after 5ms - whichever comes first
        let packet_result = tokio::select! {
            packet = read_next_packet(stream) => packet,
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(5)) => continue,
        };

        match packet_result {
            Ok(packet) => match packet.code {
                Codes::Disconnect => {
                    println!("Client requested disconnect");
                    return Ok(());
                }
                Codes::RefreshSession => {
                    if let Some(receiver) = &mut conn.output_receiver {
                        while receiver.try_recv().is_ok() {} // Clear the receiver of any previous output
                    }

                    if let Some(tx) = &conn.command_sender {
                        let _ = tx.send("".to_string());
                    }
                }
                Codes::Command => {
                    if let Some(cmd) =
                        decrypt_message(&conn.cipher, &packet.nonce, &packet.ciphertext)
                    {
                        if let Some(tx) = &conn.command_sender {
                            // Send the command the PTY handler
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

async fn setup_secure_connection(mut stream: TcpStream) -> io::Result<SecureConnection> {
    let stream_ref = &mut stream;

    let client_packet = read_next_packet(stream_ref).await?;

    if client_packet.code != Codes::PublicKeyRequest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected PUBLIC_KEY_REQUEST",
        ));
    }

    if client_packet.ciphertext.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid public key length",
        ));
    }

    let mut client_key_bytes = [0u8; 32];
    client_key_bytes.copy_from_slice(&client_packet.ciphertext);
    let client_pub_key = PublicKey::from(client_key_bytes);

    let server_priv_key = EphemeralSecret::random_from_rng(OsRng);
    let server_pub_key = PublicKey::from(&server_priv_key);

    let response_packet = Packet::new(

        Codes::PublicKeyResponse,
        [0; 12],
        server_pub_key.as_bytes().to_vec(),
    );

    let serialized_response = serialize_packet(&response_packet)?;
    let response_len = serialized_response.len() as u32;
    stream_ref.write_all(&response_len.to_be_bytes()).await?;
    stream_ref.write_all(&serialized_response).await?;

    let shared_secret = server_priv_key.diffie_hellman(&client_pub_key);

    let mut hasher = Sha256::default();
    hasher.update(shared_secret.as_bytes());
    let encryption_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to initialize cipher"))?;

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
