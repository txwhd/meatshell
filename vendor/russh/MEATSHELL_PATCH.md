# MeatShell MFA transport patch

Base: crates.io `russh` 0.61.2. Upstream metadata and Apache-2.0 license are retained.

Forward keyboard-interactive challenges to the caller, then return immediately
to the transport loop. Encode `AuthInfoResponse` in `handle_msg` only while a
keyboard-interactive request is active. This lets remote disconnects, local
cancellation and keepalives run while the user enters an MFA answer.

Unlike the old 0.49.2 patch in the reference checkout, 0.61.2 already refreshes
the active authentication request and returns an error for a closed reply
channel. Those fixes are not reapplied. No dependency versions or public APIs
are changed.

Regression command: `cargo test --locked --manifest-path tests/ssh_auth_fixture/Cargo.toml`.
Remove this patch when upstream handles challenges without blocking the transport,
then rerun the protocol and application regressions.
