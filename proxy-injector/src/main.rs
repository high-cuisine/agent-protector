use proxy_injector::{InjectionResult, ProxyConfig, ProxyInjector, scan};
use std::path::PathBuf;
use std::process;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let dry_run = args.iter().any(|a| a == "--dry-run" || a == "-n");

    let cfg = parse_args();

    // ── Print discovered instances ──────────────────────────────────────────
    let instances = scan();
    if instances.is_empty() {
        eprintln!("No running Claude Code instances found.");
        process::exit(1);
    }

    println!("Found {} Claude Code instance(s):", instances.len());
    for inst in &instances {
        println!("  pid={}  cwd={}  exe={}", inst.pid, inst.cwd.display(), inst.exe.display());
    }

    if dry_run {
        println!("\n(dry-run — no processes were touched)");
        return;
    }

    println!("\nInjecting proxy http://127.0.0.1:{} …\n", cfg.port);

    // ── Inject ──────────────────────────────────────────────────────────────
    let injector = ProxyInjector::new(cfg);
    let results = injector.inject_all();

    let mut ok = 0;
    let mut fail = 0;
    for r in &results {
        match r {
            InjectionResult::Relaunched { .. } => ok += 1,
            _ => fail += 1,
        }
        println!("{r}");
    }

    println!();
    println!("Injection complete: {ok} relaunched, {fail} failed.");
    if fail > 0 {
        process::exit(1);
    }
}

// ─── Minimal arg parser (no clap dep needed) ──────────────────────────────────

fn parse_args() -> ProxyConfig {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        process::exit(0);
    }

    let port: u16 = find_arg(&args, "--port")
        .or_else(|| find_arg(&args, "-p"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    let ca_cert: Option<PathBuf> = find_arg(&args, "--ca-cert")
        .map(PathBuf::from);

    let no_tls_verify = args.iter().any(|a| a == "--no-tls-verify" || a == "-k");

    let mut cfg = ProxyConfig::new(port);
    if no_tls_verify { cfg = cfg.insecure(); }
    if let Some(ca) = ca_cert { cfg = cfg.with_ca(ca); }
    cfg
}

fn find_arg<'a>(args: &'a [String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            return args.get(i + 1).cloned();
        }
        if let Some(v) = arg.strip_prefix(&prefix) {
            return Some(v.to_string());
        }
    }
    None
}

fn print_help() {
    println!(
        r#"proxy-injector — restart Claude Code with a local MITM proxy

USAGE
  proxy-injector [OPTIONS]

OPTIONS
  -p, --port <PORT>       Proxy port on 127.0.0.1  (default: 8080)
      --ca-cert <PATH>    PEM CA certificate for HTTPS interception
                          Sets NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, CURL_CA_BUNDLE
  -k, --no-tls-verify     Skip TLS verification (NODE_TLS_REJECT_UNAUTHORIZED=0)
                          Use only in dev — MITM without a proper CA cert
  -n, --dry-run           Only list found instances, don't kill or restart
  -h, --help              Print this help

EXAMPLES
  # Intercept via mitmproxy (port 8080), trust mitmproxy's CA:
  proxy-injector --port 8080 --ca-cert ~/.mitmproxy/mitmproxy-ca-cert.pem

  # Quick test without a CA (disables TLS verification entirely):
  proxy-injector --port 8080 --no-tls-verify

WHAT IT DOES
  1. Finds all running processes named "claude" (pgrep -x claude on macOS,
     /proc scan on Linux).
  2. Sends SIGTERM; waits up to 2 s; sends SIGKILL if needed.
  3. Re-launches each instance from its original working directory using the
     same binary, with these extra env vars:
       HTTP_PROXY  HTTPS_PROXY  http_proxy  https_proxy
       NO_PROXY    no_proxy
       NODE_EXTRA_CA_CERTS  SSL_CERT_FILE  CURL_CA_BUNDLE  (with --ca-cert)
       NODE_TLS_REJECT_UNAUTHORIZED=0                       (with --no-tls-verify)
"#
    );
}
