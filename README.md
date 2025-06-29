# ΠP

Polyrhoé (PRH or `pr`), from the Greek πολύς (many) and ῥοή (flow), is a protocol operating over TCP/IP for multiplexing simultaneous shell connections to multiple remote hosts.

## Roadmap
Due to complications in a [previous collaborative project](https://github.com/lokasku/misc/tree/main/lys) and the time constraints of my final exams, I had to start a completely new project within a tight timeframe of about ten days. The following roadmap outlines its current structure and objectives.

- [x] Client operational
- [x] Server operational
- [x] Fully encrypted communications with [DH](https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange) and [AES](https://fr.wikipedia.org/wiki/Advanced_Encryption_Standard)-[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [x] Multiplexing of multiple connections
- [x] User-friendly client interface
- [x] Multithreading for the different connections
- [x] Support for multiple client connections
- [x] Modern CLI
- [x] Documentation
- [ ] Authentication support
    - [ ] Password-based authentication
    - [ ] Whitelist of trusted IP addresses
- [ ] Tags support
    - [ ] Add tags to connections
    - [ ] Command dispatch by tag
- [ ] [Macro](https://en.wikipedia.org/wiki/Macro_(computer_science)) support
    - [ ] Per-machine variable substitution in commands (e.g. `{{ip}}`)
    - [ ] Define macros with variables
    - [ ] Execute macros on multiple machines
- [ ] [Diffing](https://en.wikipedia.org/wiki/Diff) support
- [ ] Daemon mode for the server
    - [ ] as a systemd service
    - [ ] Errors and logs management
- [ ] Command history

## Dependencies
You need to have Rust and Cargo installed on your system. If you're using Nix, type
```
nix develop
```
Else, you can install Rust and Cargo by following the instructions on the [official Rust website](https://www.rust-lang.org/tools/install).

Once you have dependencies installed, clone the project
```shell
git clone https://github.com/lokasku/pr.git wherever/you/want
cd wherever/you/want/pr
```

## Usage
### Client
To start the client, run the following command at the root of the repository :
```shell
cargo run --release --package pr-client
```

Then, an interactive interface will be displayed, allowing you to add a connection to a remote host (<kbd>A</kbd> or <kbd>a</kbd>), list all established connections (<kbd>L</kbd> or <kbd>l</kbd>), remove a connection (<kbd>R</kbd> or <kbd>r</kbd>), switch to a connection (<kbd>S</kbd> or <kbd>s</kbd>), or exit the client (<kbd>Q</kbd> or <kbd>q</kbd>). At any time, you can press **Esc** to return to the main menu.

When you switch to a connection, enter the <kbd>%</kbd> to come back the main menu. The connection will remain active in the background, allowing you to switch back to it at any time.

### Server
To start the server, run :
```shell
cargo run --release --package pr-server -- -p 1789
```

By default, the server will listen on port 1736 but you can specify a different port using the `-p` option.

However, in order to connect to a remote machine, the open port must be configured on the router so that it can be accessed remotely. You can still use the server locally for testing purposes.

## Documentation
For detailed technical documentation, including protocol specifications please refer to the `docs/` directory.

## License
PR is licensed under the [MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/) (Mozilla Public License 2.0). See the LICENSE file for mode details.
