pub mod discovery;
pub mod injector;
pub mod seccomp;

pub use discovery::{scan, ClaudeInstance};
pub use injector::{InjectionResult, ProxyConfig, ProxyInjector};
