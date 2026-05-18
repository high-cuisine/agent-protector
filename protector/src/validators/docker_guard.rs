use crate::errors::ThreatError;
use crate::validator::{ValidationContext, ValidationResult, Validator};
use log::info;

const DB_PORTS: &[(u16, &str)] = &[
    (5432,  "PostgreSQL"),
    (5433,  "PgBouncer"),
    (3306,  "MySQL/MariaDB"),
    (3307,  "MySQL/MariaDB"),
    (1433,  "MSSQL"),
    (1521,  "Oracle DB"),
    (6379,  "Redis"),
    (27017, "MongoDB"),
    (27018, "MongoDB"),
    (27019, "MongoDB"),
    (9200,  "Elasticsearch"),
    (9300,  "Elasticsearch"),
    (5984,  "CouchDB"),
    (5672,  "RabbitMQ"),
    (15672, "RabbitMQ management"),
    (9092,  "Kafka"),
    (2181,  "ZooKeeper"),
];

pub struct DockerGuardValidator;

impl DockerGuardValidator {
    pub fn new() -> Self { Self }
}

impl Validator for DockerGuardValidator {
    fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        let args = &ctx.args;
        let sub = match positional(args, 1) {
            Some(s) => s,
            None => return ValidationResult::Allow,
        };

        match sub.as_str() {
            "run" | "create" => validate_run(args, ctx.pid),
            "exec"           => validate_exec(args, ctx.pid),
            "rm"             => validate_rm(args, "container"),
            "rmi"            => validate_rm(args, "image"),
            "container" => match positional(args, 2).as_deref() {
                Some("rm") | Some("remove") => validate_rm(args, "container"),
                _ => ValidationResult::Allow,
            },
            "image" => match positional(args, 2).as_deref() {
                Some("rm") | Some("remove") | Some("prune") => validate_rm(args, "image"),
                _ => ValidationResult::Allow,
            },
            "system" => match positional(args, 2).as_deref() {
                Some("prune") => validate_system_prune(args),
                _ => ValidationResult::Allow,
            },
            "volume" => match positional(args, 2).as_deref() {
                Some("rm") | Some("remove") => {
                    let name = positional(args, 3).unwrap_or_else(|| "<unknown>".into());
                    ValidationResult::Block(ThreatError::DockerVolumeDestroy { name })
                }
                _ => ValidationResult::Allow,
            },
            "swarm"  => validate_swarm(args),
            "push"   => {
                let image = positional(args, 2).unwrap_or_else(|| "<unknown>".into());
                ValidationResult::Warn(ThreatError::DockerPush { image })
            }
            "login"  => ValidationResult::Warn(ThreatError::DockerLogin),
            "commit" => ValidationResult::Warn(ThreatError::DockerCommit),
            "cp"     => ValidationResult::Warn(ThreatError::DockerCp),
            _ => ValidationResult::Allow,
        }
    }
}

// ─── sub-command validators ───────────────────────────────────────────────────

fn validate_run(args: &[String], pid: u32) -> ValidationResult {
    let mut issues: Vec<String> = Vec::new();
    let mut warns:  Vec<String> = Vec::new();

    if has_flag(args, "--privileged") {
        issues.push("--privileged: full host access — bypasses all container isolation".into());
    }

    for cap in flag_values(args, "--cap-add") {
        let up = cap.to_uppercase();
        if matches!(
            up.as_str(),
            "ALL" | "SYS_ADMIN" | "NET_ADMIN" | "SYS_PTRACE" |
            "SYS_MODULE" | "SYS_RAWIO" | "SYS_BOOT" | "SYS_TIME"
        ) {
            issues.push(format!("--cap-add={cap}: grants dangerous Linux capability"));
        }
    }

    if flag_values(args, "--pid").iter().any(|v| v == "host") || has_flag(args, "--pid=host") {
        issues.push("--pid=host: container sees all host processes via shared PID namespace".into());
    }

    if flag_values(args, "--ipc").iter().any(|v| v == "host") || has_flag(args, "--ipc=host") {
        issues.push("--ipc=host: container shares host IPC namespace".into());
    }

    for opt in flag_values(args, "--security-opt") {
        if opt.contains("seccomp=unconfined") {
            issues.push(format!("--security-opt={opt}: disables seccomp syscall filter"));
        } else if opt.contains("apparmor=unconfined") {
            issues.push(format!("--security-opt={opt}: disables AppArmor MAC profile"));
        }
    }

    for dev in flag_values(args, "--device") {
        let host = dev.split(':').next().unwrap_or(dev.as_str());
        if host.starts_with("/dev/sd") || host.starts_with("/dev/nvme")
            || host.starts_with("/dev/vd")
            || host == "/dev/mem" || host == "/dev/kmem"
        {
            issues.push(format!("--device={dev}: mounts a raw storage/memory device into the container"));
        }
    }

    if args.iter().any(|a| a.contains("docker.sock")) {
        issues.push(
            "Docker socket (docker.sock) mounted — container gains full control over the Docker daemon".into()
        );
    }

    issues.extend(check_volumes(args));
    issues.extend(check_publish_ports(args));

    if flag_values(args, "--network").iter().any(|v| v == "host")
        || flag_values(args, "--net").iter().any(|v| v == "host")
        || has_flag(args, "--network=host")
        || has_flag(args, "--net=host")
    {
        warns.push(
            "--network=host: container shares the host network stack — all ports bind directly on host interfaces".into()
        );
    }

    if !issues.is_empty() {
        ValidationResult::Block(ThreatError::DockerUnsafeRun { issues })
    } else if !warns.is_empty() {
        // Wrap network warnings as a soft DockerUnsafeRun (warn-level)
        ValidationResult::Warn(ThreatError::DockerUnsafeRun { issues: warns })
    } else {
        info!("[docker] pid={pid} run/create — clean");
        ValidationResult::Allow
    }
}

fn validate_exec(args: &[String], pid: u32) -> ValidationResult {
    let privileged = has_flag(args, "--privileged");
    if privileged {
        return ValidationResult::Block(ThreatError::DockerExec { privileged: true });
    }
    info!("[docker] pid={pid} exec — warn");
    ValidationResult::Warn(ThreatError::DockerExec { privileged: false })
}

fn validate_rm(args: &[String], subject: &str) -> ValidationResult {
    if has_flag(args, "-f") || has_flag(args, "--force") {
        return ValidationResult::Warn(ThreatError::DockerForceRemove {
            subject: subject.to_string(),
        });
    }
    ValidationResult::Allow
}

fn validate_system_prune(args: &[String]) -> ValidationResult {
    let all     = has_flag(args, "-a") || has_flag(args, "--all");
    let volumes = has_flag(args, "--volumes");
    if all || volumes {
        let scope = match (all, volumes) {
            (true, true)   => "all unused images, stopped containers, networks, AND volumes",
            (true, false)  => "all unused images and stopped containers",
            _              => "stopped containers, networks, and named volumes",
        };
        return ValidationResult::Block(ThreatError::DockerUnsafeRun {
            issues: vec![format!("docker system prune: would permanently delete {scope}")],
        });
    }
    ValidationResult::Warn(ThreatError::DockerUnsafeRun {
        issues: vec![
            "docker system prune: removes stopped containers, dangling images, and unused networks".into(),
        ],
    })
}

fn validate_swarm(args: &[String]) -> ValidationResult {
    match positional(args, 2).as_deref() {
        Some("init") => ValidationResult::Block(ThreatError::DockerUnsafeRun {
            issues: vec!["docker swarm init: initializes a new Swarm cluster on this node".into()],
        }),
        Some("join") => ValidationResult::Block(ThreatError::DockerUnsafeRun {
            issues: vec!["docker swarm join: adds this node to an existing Swarm cluster".into()],
        }),
        Some("leave") => {
            if has_flag(args, "--force") || has_flag(args, "-f") {
                ValidationResult::Block(ThreatError::DockerUnsafeRun {
                    issues: vec![
                        "docker swarm leave --force: forcibly removes a manager node — can destroy the entire cluster".into(),
                    ],
                })
            } else {
                ValidationResult::Warn(ThreatError::DockerUnsafeRun {
                    issues: vec![
                        "docker swarm leave: removes this node from the Swarm cluster".into(),
                    ],
                })
            }
        }
        _ => ValidationResult::Allow,
    }
}

// ─── port and volume checkers ─────────────────────────────────────────────────

fn check_publish_ports(args: &[String]) -> Vec<String> {
    collect_specs(args, &["-p", "--publish"])
        .into_iter()
        .filter_map(|s| check_port_spec(&s))
        .collect()
}

fn check_port_spec(spec: &str) -> Option<String> {
    let spec = spec.split('/').next().unwrap_or(spec);
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    let (host_ip, host_port_str) = match parts.len() {
        2 => ("0.0.0.0", parts[0]),
        3 => (parts[0], parts[1]),
        _ => return None,
    };
    if !host_ip.is_empty() && host_ip != "0.0.0.0" {
        return None;
    }
    let port: u16 = host_port_str.split('-').next()?.parse().ok()?;
    DB_PORTS.iter().find(|&&(p, _)| p == port).map(|&(p, svc)| {
        format!(
            "DB port {p} ({svc}) published on 0.0.0.0 — exposed on all network interfaces. \
             Use -p 127.0.0.1:{p}:{p} to restrict to localhost"
        )
    })
}

fn check_volumes(args: &[String]) -> Vec<String> {
    const DANGEROUS: &[(&str, &str)] = &[
        ("/:/",                  "root filesystem"),
        ("/etc/",                "/etc — system config"),
        ("/proc/",               "/proc"),
        ("/sys/",                "/sys"),
        ("/dev/",                "/dev"),
        ("/boot/",               "/boot"),
        ("/var/run/docker.sock", "Docker socket"),
        ("/run/docker.sock",     "Docker socket"),
    ];
    collect_specs(args, &["-v", "--volume"])
        .into_iter()
        .filter_map(|spec| {
            let host = spec.split(':').next().unwrap_or(spec.as_str()).to_string();
            if !host.starts_with('/') {
                return None;
            }
            DANGEROUS.iter().find(|(prefix, _)| {
                host == prefix.trim_end_matches('/') || host.starts_with(prefix)
            }).map(|(_, label)| {
                format!("dangerous host path '{host}' ({label}) mounted into container")
            })
        })
        .collect()
}

// ─── argument helpers ─────────────────────────────────────────────────────────

fn positional(args: &[String], n: usize) -> Option<String> {
    args.iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .nth(n - 1)
        .cloned()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    let eq = format!("{flag}=");
    args.iter().any(|a| a == flag || a.starts_with(&eq))
}

fn flag_values(args: &[String], flag: &str) -> Vec<String> {
    let eq = format!("{flag}=");
    let mut result = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == flag {
            if let Some(v) = iter.peek() {
                result.push((*v).clone());
                iter.next();
            }
        } else if let Some(v) = arg.strip_prefix(&eq) {
            result.push(v.to_string());
        }
    }
    result
}

fn collect_specs(args: &[String], flags: &[&str]) -> Vec<String> {
    let mut specs = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        for &flag in flags {
            if arg == flag {
                if let Some(v) = iter.peek() {
                    specs.push((*v).clone());
                    iter.next();
                }
                break;
            }
            let eq = format!("{flag}=");
            if let Some(v) = arg.strip_prefix(&eq) {
                specs.push(v.to_string());
                break;
            }
            if flag.len() == 2 && flag.starts_with('-') {
                if let Some(v) = arg.strip_prefix(flag) {
                    if !v.is_empty() {
                        specs.push(v.to_string());
                        break;
                    }
                }
            }
        }
    }
    specs
}
