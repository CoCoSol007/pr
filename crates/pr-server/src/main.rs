// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

pub mod cli;

use aes_gcm::{Aes256Gcm, KeyInit};
use common::{
    cipher::{decrypt_message, send_encrypted_packet},
    codes::Codes,
    packet::{Packet, serialize_packet, read_next_packet},
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
    pub pub_key: PublicKey,
    pub client_pub_key: PublicKey,
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
            if let Ok(cmd) = cmd_rx.try_recv() {
                if let Err(e) = write(&pty_master, format!("{}\n", cmd).as_bytes()) {
                    eprintln!("Failed to write command: {}", e);
                    continue;
                }

                std::thread::sleep(std::time::Duration::from_millis(100));

                let mut total_output = String::new();
                let mut counter = 0;

                // Read the output of the command
                while counter < 10 {
                    // Read until we get no data for 10 times (arbitrary)
                    match read(&pty_master, &mut buffer) {
                        Ok(n) if n > 0 => {
                            let output = String::from_utf8_lossy(&buffer[0..n]).to_string();
                            total_output.push_str(&output);
                            counter = 0;
                        }
                        Err(e)
                            if e == nix::errno::Errno::EAGAIN
                                || e == nix::errno::Errno::EWOULDBLOCK =>
                        {
                            counter += 1;
                        }
                        Err(e) => {
                            if e == nix::errno::Errno::EBADF {
                                return;
                            }
                            break;
                        }
                        _ => break,
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }

                let lines: Vec<&str> = total_output.lines().collect();
                let mut clean_output = String::new();
                let mut skip_command = false;

                for line in lines {
                    // avoid sending the command itself in the output
                    if !skip_command && line.trim() == cmd.trim() {
                        print!("{}\n", line);
                        skip_command = true;
                        continue;
                    }
                    clean_output.push_str(line);
                    clean_output.push('\n');
                }
                clean_output.pop(); // to get the cursor after the prompt

                print!("{}", clean_output.clone());

                output_tx.send(clean_output).ok();
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
}

async fn process_client_commands(conn: &mut SecureConnection) -> io::Result<()> {
    let stream = &mut conn.stream;

    loop {
        // Check if the output of some previously executed command is available
        if let Some(receiver) = &mut conn.output_receiver {
            while let Ok(output) = receiver.try_recv() {
                // Send the output back to the client
                send_encrypted_packet(stream, &conn.cipher, Codes::COMMAND_RESPONSE, &output)
                    .await?;
            }
        }

        let packet_result = tokio::select! {
            packet = read_next_packet(stream) => packet,
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(5)) => continue,
        };

        match packet_result {
            Ok(packet) => match packet.code {
                Codes::DISCONNECT => {
                    println!("Client requested disconnect");
                    return Ok(());
                }
                Codes::REFRESH_SESSION => {
                    if let Some(receiver) = &mut conn.output_receiver {
                        while receiver.try_recv().is_ok() {} // Clear the output receiver
                    }

                    if let Some(tx) = &conn.command_sender {
                        let _ = tx.send("".to_string());
                    }
                }
                Codes::COMMAND => {
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

    if client_packet.code != Codes::PUBLIC_KEY_REQUEST {
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
        0,
        1,
        Codes::PUBLIC_KEY_RESPONSE,
        [0; 12],
        server_pub_key.as_bytes().to_vec(),
        vec![],
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
        pub_key: server_pub_key,
        client_pub_key,
        cipher,
        pty_fd: None,
        child_fd: None,
        command_sender: None,
        output_receiver: None,
    };

    println!("Secure connection established with client");

    Ok(secure_conn)
}
