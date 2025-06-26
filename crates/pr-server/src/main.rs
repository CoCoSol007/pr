// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

pub mod cli;

use aes_gcm::{Aes256Gcm, KeyInit};
use common::{
    cipher::decrypt_message,
    codes::Codes,
    packet::{Packet, deserialize_packet, get_packet_length, serialize_packet},
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
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    start_pty_handler(pty_master, cmd_rx);

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    process_client_commands(&mut conn).await?;

    if let Some(pid) = conn.child_fd {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
    }

    Ok(())
}

fn start_pty_handler(pty_master: OwnedFd, cmd_rx: mpsc::Receiver<String>) {
    // Allow non-blocking reads the master PTY
    let current_flags = fcntl(&pty_master, FcntlArg::F_GETFL).expect("Failed to get fd flags");
    let new_flags = OFlag::from_bits_truncate(current_flags) | OFlag::O_NONBLOCK;
    fcntl(&pty_master, FcntlArg::F_SETFL(new_flags)).expect("Failed to set fd flags");

    task::spawn_blocking(move || {
        let mut buffer = [0u8; 1024];

        loop {
            if let Ok(cmd) = cmd_rx.try_recv() {
                if let Ok(n) = read(&pty_master, &mut buffer) {
                    print!("{}", String::from_utf8_lossy(&buffer[0..n]));
                }

                if let Err(e) = write(&pty_master, format!("{}\r\n", cmd).as_bytes()) {
                    eprintln!("Failed to write command to PTY: {}", e);
                }

                std::thread::sleep(std::time::Duration::from_millis(200));

                match read(&pty_master, &mut buffer) {
                    Ok(n) if n > 0 => {
                        print!("{}", String::from_utf8_lossy(&buffer[0..n]));
                        io::stdout().flush().unwrap();
                    }
                    Err(e) => {
                        eprintln!("Error reading from PTY: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
}

async fn process_client_commands(conn: &mut SecureConnection) -> io::Result<()> {
    let stream = &mut conn.stream;

    loop {
        let packet_len = get_packet_length(stream).await?;
        let mut packet_data = vec![0u8; packet_len];
        stream.read_exact(&mut packet_data).await?;

        let packet = deserialize_packet(&packet_data)?;

        match packet.code {
            Codes::DISCONNECT => {
                println!("Client requested disconnect");
                return Ok(());
            }
            Codes::COMMAND => {
                if let Some(message) =
                    decrypt_message(&conn.cipher, &packet.nonce, &packet.ciphertext)
                {
                    if let Some(tx) = &conn.command_sender {
                        if let Err(e) = tx.send(message) {
                            eprintln!("Failed to forward command to PTY: {}", e);
                        }
                    } else {
                        eprintln!("Command channel not initialized");
                    }
                }
            }
            _ => {
                println!("Received packet with unexpected code : {:?}", packet.code);
            }
        }
    }
}

async fn setup_secure_connection(mut stream: TcpStream) -> io::Result<SecureConnection> {
    let stream_ref = &mut stream;

    let packet_len = get_packet_length(stream_ref).await?;
    let mut packet_data = vec![0u8; packet_len];
    stream_ref.read_exact(&mut packet_data).await?;

    let client_packet = deserialize_packet(&packet_data)?;

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
        0,
        [0; 12],
        server_pub_key.as_bytes().to_vec(),
        vec![],
    );

    let serialized_response = serialize_packet(&response_packet)?;
    let response_len = serialized_response.len() as u32;
    stream_ref.write_all(&response_len.to_be_bytes()).await?;
    stream_ref.write_all(&serialized_response).await?;

    let shared_secret = server_priv_key.diffie_hellman(&client_pub_key);

    let mut hasher = Sha256::new();
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
    };

    println!("Secure connection established with client");

    Ok(secure_conn)
}
