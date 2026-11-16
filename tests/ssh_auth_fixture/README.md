# SSH authentication protocol regressions

Run `cargo test --manifest-path tests/ssh_auth_fixture/Cargo.toml` with Python 3
and Paramiko (`python3 -m pip install paramiko`). Set `PYTHON` to select Python.
When running a cross-compiled test executable, set `MEATSHELL_AUTH_FIXTURE_SCRIPT`
to the runtime machine's absolute path to `server.py`.

This small crate compiles the production authentication, connection deadline and
responder modules with the same russh version as the app. Config and UI events are fixture types;
the key loader uses the same russh decoder for generated PEM keys. It avoids
building the desktop just to test SSH protocol exchanges. The real app still
needs a separate `cargo check --locked --features headless` / desktop build.

Each Paramiko server accepts exactly one loopback connection, generates fresh
host/client keys and requires the first factor before MFA. No real credentials,
profiles or remote servers are accessed. These tests cannot verify USM policies.
