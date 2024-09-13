# RustgreSSHion

## Overview

**RustgreSSHion** is a Rust-based tool designed to exploit a known vulnerability in certain versions of OpenSSH. The vulnerability is related to a **race condition** in the SSH banner exchange, which can be manipulated to trigger a specific heap-based memory flaw, leading to potential remote code execution.

This project is created for educational and legal penetration testing purposes. It allows you to attempt an exploit on vulnerable SSH servers, particularly targeting specific OpenSSH versions, by sending crafted packets and interacting with the server.

---

### Vulnerability

This vulnerability affects certain versions of OpenSSH (e.g., 8.5 - 9.7) where a race condition in the SSH banner exchange phase can be exploited. The attacker can manipulate memory to force the SSH daemon into an unstable state, eventually allowing arbitrary code execution.

This project utilizes **heap manipulation** techniques to simulate a crafted file structure in memory, sending malformed SSH packets that exploit the vulnerable versions of OpenSSH.

---

## Running RustgreSSHion

### Requirements

1. **Rust**: Ensure that you have the latest stable version of Rust installed.
   - [Installation Instructions](https://www.rust-lang.org/tools/install)
2. **Linux Environment**: It is recommended to run the project in a native Linux environment or a well-configured VM.
3. **Vulnerable SSH Server**: Use a test server that runs a vulnerable version of OpenSSH. Do **not** use this tool on servers you do not own or have permission to test.

---

### Steps to Run

1. **Clone the Repository**:

    ```bash
    git clone [https://github.com/yourusername/RustgreSSHion.git](https://github.com/havokzero/RustgreSSHion.git)
    cd RustgreSSHion
    ```

2. **Build the Project**:

    ```bash
    cargo build --release
    ```

3. **Run the Exploit**:

    Provide the target IP and SSH port when running the program.

    ```bash
    cargo run <target_ip> <target_port>
    ```

    Example:

    ```bash
    cargo run 192.168.1.100 22
    ```

4. **Monitor SSH Logs**:

    You can use this command to monitor incoming SSH connections on the server:

    ```bash
    tail -f /var/log/secure
    ```

---

## How the Exploit Works

1. **SSH Banner Grab**: The tool connects to the SSH server and attempts to retrieve the SSH banner to determine the version of OpenSSH running.
   
2. **Vulnerability Check**: It uses a regular expression to identify whether the SSH server version is vulnerable.

3. **Heap Manipulation**: The tool uses crafted packets to manipulate the memory layout of the server by simulating heap operations, sending fake file structures.

4. **Shell Interaction**: If successful, it attempts to spawn a remote shell on the vulnerable system. However, failure to do so may result in the server forcibly closing the connection.

---

## Example Output

```bash
Connecting to SSH server at 192.168.1.100:22
Connected to the SSH server.
SSH Banner: SSH-2.0-OpenSSH_8.5

This version of OpenSSH is vulnerable.
Target is vulnerable. Proceeding with exploit...
Attempting exploit with glibc base: 0x7f13d808d000
Sending crafted exploit packet #1...
Sending packet #1...
Possible race condition hit!
Exploit succeeded.
Interacting with shell...
Error reading from shell: An existing connection was forcibly closed by the remote host. (os error 10054)  <-- this happens mostly due to bad glib bases
Shell closed connection.
Exploit process completed.
