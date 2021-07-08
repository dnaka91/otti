# 🦦 Otti

The OTP manager for the terminal, with interactive and fancy TUI.

## Yet another OTP account manager?

I wanted an OTP manager app for the terminal that behaves similar as mobile managers but couldn't
find any that work in that way. Most CLI-based existing managers use single commands to manage the
OTP accounts, which are non-interactive.

Therefore, this is a different approach by using the awesome [tui-rs] crate to build a TUI variant
that is as similar to the mobile apps as possible but still simplistic.

Additionally, I felt the way some OTP managers save the account information is to simple and weak in
regards to security. **Otti** uses the [orion] crate for the credential storage which is very
similar to **libsodium**, but fully implemented in Rust.

[tui-rs]: https://github.com/fdehau/tui-rs
[orion]: https://github.com/orion-rs/orion

## Installation

### Pre-built binaries

Grab the binary for your OS from the [releases](https://github.com/dnaka91/otti/releases), extract
it and put it in a folder that's on your `$PATH` like `/usr/local/bin`.

### From source

Make sure to have the latest Rust compiler and Cargo installed and run:

```sh
cargo install --git https://github.com/dnaka91/otti.git --tag v0.1.0
```

You can omit the `--tag` flag to install the latest development version, but make backups of your
store file just in case.

## Usage

Currently **Otti** is read-only, that means you can not add any new accounts to its database.
Instead you have to import from an external OTP manager until editing features are implemented.

To do so, first export your OTP accounts from one of the supported external apps (currently
**Aegis** and **andOTP**), then run `otti import <provider> <file>` and optionally give a password with the `--password` argument if the import file is protected.

After the import completed successfully simply run `otti`, enter your password and use the TUI. For
further help inside the TUI hit the `h` hotkey.

## License

This project is licensed under [AGPL-3.0 License](LICENSE) (or
<https://www.gnu.org/licenses/agpl-3.0.html>).
