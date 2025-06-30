# ΠP

Polyrhoé (PRH or `pr`), from the Greek πολύς (many) and ῥοή (flow), is a protocol operating thanks to [iroh](https://www.iroh.computer/) for multiplexing simultaneous shell connections to multiple remote hosts.

## Roadmap
Due to complications in a [previous collaborative project](https://github.com/lokasku/misc/tree/main/lys) for YH4F 2025 and the time constraints of my final exams, I had to start a completely new project within a tight timeframe of about ten days. The following roadmap outlines its current structure and objectives.

- [x] Client operational
- [x] Server operational
- [x] Fully encrypted communications with [DH](https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange) and [AES](https://fr.wikipedia.org/wiki/Advanced_Encryption_Standard)-[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [x] Multiplexing of multiple connections
- [x] User-friendly client interface
- [x] Multithreading for the different connections
- [x] Support for multiple client connections
- [x] Iroh implementation
- [x] Documentation
- [x] Tags support
    - [x] Add tags to connections
    - [x] Command dispatch by tag
- [ ] Authentication support
    - [ ] Password-based authentication
    - [ ] Whitelist of trusted IP addresses
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
You need to have `rustc` and `cargo` installed on your system. If you're using Nix, you can directly enter
```
nix develop
```
Else, you can install them by following the instructions on the [official Rust website](https://www.rust-lang.org/tools/install).

Once you have dependencies installed, clone the project :
```shell
git clone https://github.com/lokasku/pr.git wherever/you/want
cd wherever/you/want/pr
git checkout iroh
```

## Usage
### Client
To start the client, run the following command at the root of the repository :
```shell
cargo run --release --package pr-client
```

Then, an interactive interface will be displayed, allowing you to :
- <kbd>A</kbd> or <kbd>a</kbd> : Add a connection to a remote host
- <kbd>L</kbd> or <kbd>l</kbd> : List all established connections
- <kbd>R</kbd> or <kbd>r</kbd> : Remove a connection
- <kbd>S</kbd> or <kbd>s</kbd> : Switch to a connection
- <kbd>M</kbd> or <kbd>m</kbd> : Modify a connection
    * <kbd>N</kbd> or <kbd>n</kbd> : Change the name of a connection
    * <kbd>A</kbd> or <kbd>a</kbd> : Add tags to a connection
    * <kbd>R</kbd> or <kbd>R</kbd> : Remove tags from a connection
    * <kbd>B</kbd> or <kbd>b</kbd> : Go back to the menu
- <kbd>D</kbd> or <kbd>d</kbd> : Dispatch a command given tags
    * Enter the tags to dispatch the command to, separated by commas (e.g. `tag1,tag2`)
    * Enter the command to execute on the selected connections
- <kbd>Q</kbd> or <kbd>q</kbd> : Exit the client

When you switch to a connection, enter the <kbd>%</kbd> to come back the main menu. The connection will remain active in the background, allowing you to switch back to it at any time.

### Server
To start the server, run :
```shell
cargo run --release --package pr-server
```
After starting the server, in order to let someone connect to your machine, you have to give him the key given at initialization.

## Documentation
For detailed technical documentation, including protocol specifications please refer to the `docs/` directory.

## Thanks
I extend my sincere thanks to [CoCoSol](https://github.com/CoCoSol007) for his valuable support during the final phase of practical testing, and for helping me implementing PR with Iroh.

## License
PR is licensed under the [MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/) (Mozilla Public License 2.0). See the LICENSE file for mode details.
