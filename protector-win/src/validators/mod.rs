//! Validator registry for protector-win.
//!
//! Platform-independent validators are referenced via `#[path]` from the
//! main `protector` crate sources to avoid duplication.
//! Windows-specific versions (data_guard, fs_guard) live locally.

#[path = "../../../protector/src/validators/git_commit.rs"]
pub mod git_commit;

#[path = "../../../protector/src/validators/secret.rs"]
pub mod secret;

#[path = "../../../protector/src/validators/sql_guard.rs"]
pub mod sql_guard;

#[path = "../../../protector/src/validators/docker_guard.rs"]
pub mod docker_guard;

#[path = "../../../protector/src/validators/redis_guard.rs"]
pub mod redis_guard;

#[path = "../../../protector/src/validators/kubectl_guard.rs"]
pub mod kubectl_guard;

// Windows-adapted versions (use MaskedOutput instead of /proc injection).
pub mod data_guard;
pub mod fs_guard;
