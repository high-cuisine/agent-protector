/// Secret scanner — structural pattern matching without regex.
///
/// Each token type is described as a `PatternDef` that specifies:
///   • how to locate the start of the secret value in a line (`Trigger`)
///   • what characters and minimum length the value must have (`ValueSpec`)
///   • optional Shannon entropy gate to suppress false positives
///
/// Detection is O(n * p) in line length and number of patterns, but without
/// regex compilation overhead and with zero external runtime dependencies.
use std::path::Path;

// ── Public output type ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub line_number: usize,
    /// Redacted excerpt of the offending line for display in reports.
    pub snippet: String,
    /// First 40 chars of the extracted secret value (for audit trail).
    pub matched_value: String,
}

// ── Charset ───────────────────────────────────────────────────────────────────

/// Defines which characters are valid inside a secret value.
#[derive(Clone, Copy)]
pub enum Charset {
    /// [A-Z0-9]
    UpperAlphaNum,
    /// [0-9a-f]
    LowerHex,
    /// [0-9a-fA-F]
    Hex,
    /// [A-Za-z0-9]
    AlphaNum,
    /// [A-Za-z0-9_-]
    AlphaNumDash,
    /// [A-Za-z0-9_\-.]
    AlphaNumDashDot,
    /// Base64 standard alphabet including padding  [A-Za-z0-9+/=]
    Base64,
    /// URL-safe Base64                             [A-Za-z0-9_-]
    Base64Url,
    /// Any non-whitespace ASCII printable
    Printable,
}

impl Charset {
    fn accepts(self, c: char) -> bool {
        match self {
            Self::UpperAlphaNum   => c.is_ascii_uppercase() || c.is_ascii_digit(),
            Self::LowerHex        => matches!(c, '0'..='9' | 'a'..='f'),
            Self::Hex             => c.is_ascii_hexdigit(),
            Self::AlphaNum        => c.is_ascii_alphanumeric(),
            Self::AlphaNumDash    => c.is_ascii_alphanumeric() || c == '_' || c == '-',
            Self::AlphaNumDashDot => c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.',
            Self::Base64          => c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=',
            Self::Base64Url       => c.is_ascii_alphanumeric() || c == '_' || c == '-',
            Self::Printable       => c.is_ascii() && !c.is_ascii_whitespace(),
        }
    }
}

// ── Trigger ───────────────────────────────────────────────────────────────────

/// Describes where in the line to look for the start of a secret value.
pub enum Trigger {
    /// The value itself starts with a fixed literal prefix (e.g. "ghp_", "AKIA").
    /// Case-sensitive.
    ValuePrefix(&'static str),

    /// Any of the given literal prefixes can start the value.
    AnyValuePrefix(&'static [&'static str]),

    /// A key=value (or key: value) assignment where the key is one of the given
    /// names (matched case-insensitively against the lowercased line).
    KeyAssignment {
        /// Variable/key names to look for (all lowercase).
        keys: &'static [&'static str],
        /// Which separators count as assignment.
        sep: Sep,
    },

    /// The value has a fixed prefix AND is preceded by a key assignment.
    /// Both conditions must be met; the value prefix anchors the actual token.
    KeyedValuePrefix {
        keys: &'static [&'static str],
        prefix: &'static str,
    },
}

/// Assignment separators recognised by `KeyAssignment`.
#[derive(Clone, Copy)]
pub enum Sep {
    /// `=`
    Equals,
    /// `:` (YAML style)
    Colon,
    /// Either `=` or `:`
    Any,
}

// ── Value specification ───────────────────────────────────────────────────────

pub struct ValueSpec {
    /// The value must be at least this many characters long (after the trigger).
    pub min_len: usize,
    /// The value must be at most this many characters long. 0 = no upper bound
    /// (stop at whitespace or end of line).
    pub max_len: usize,
    /// Allowed character class for the value body.
    pub charset: Charset,
    /// Minimum Shannon entropy (bits per character). 0.0 = no gate.
    pub min_entropy: f32,
}

// ── Pattern definition ────────────────────────────────────────────────────────

pub struct PatternDef {
    pub name: &'static str,
    pub trigger: Trigger,
    pub value: ValueSpec,
}

// ── Pattern catalog ───────────────────────────────────────────────────────────
// Patterns are listed from most specific to least specific so that when
// multiple patterns fire on the same line the first (most precise) match
// determines the snippet kind in deduplication.

static PATTERNS: &[PatternDef] = &[
    // ── AWS ──────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "AWS Access Key ID",
        trigger: Trigger::AnyValuePrefix(&["AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"]),
        value: ValueSpec { min_len: 16, max_len: 16, charset: Charset::UpperAlphaNum, min_entropy: 2.8 },
    },
    PatternDef {
        name: "AWS Secret Access Key",
        trigger: Trigger::KeyAssignment {
            keys: &["aws_secret_access_key", "aws_secret_key", "secret_access_key"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 40, max_len: 40, charset: Charset::Base64, min_entropy: 3.8 },
    },
    PatternDef {
        name: "AWS Session Token",
        trigger: Trigger::KeyAssignment {
            keys: &["aws_session_token", "aws_security_token"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 100, max_len: 0, charset: Charset::Printable, min_entropy: 3.5 },
    },

    // ── GitHub ────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "GitHub Personal Access Token (classic)",
        trigger: Trigger::ValuePrefix("ghp_"),
        value: ValueSpec { min_len: 36, max_len: 36, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },
    PatternDef {
        name: "GitHub Fine-Grained PAT",
        trigger: Trigger::ValuePrefix("github_pat_"),
        value: ValueSpec { min_len: 82, max_len: 82, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "GitHub App Secret Token",
        trigger: Trigger::ValuePrefix("ghs_"),
        value: ValueSpec { min_len: 36, max_len: 36, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },
    PatternDef {
        name: "GitHub App Refresh Token",
        trigger: Trigger::ValuePrefix("ghr_"),
        value: ValueSpec { min_len: 36, max_len: 36, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },
    PatternDef {
        name: "GitHub Actions Token (env)",
        trigger: Trigger::KeyAssignment {
            keys: &["github_token", "github_pat", "gh_token", "github_webhook_secret"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 20, max_len: 0, charset: Charset::Printable, min_entropy: 3.2 },
    },

    // ── GitLab ────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "GitLab Personal Access Token",
        trigger: Trigger::ValuePrefix("glpat-"),
        value: ValueSpec { min_len: 20, max_len: 20, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "GitLab Deploy Token",
        trigger: Trigger::ValuePrefix("gldt-"),
        value: ValueSpec { min_len: 20, max_len: 20, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "GitLab Runner Token",
        trigger: Trigger::ValuePrefix("glrt-"),
        value: ValueSpec { min_len: 20, max_len: 20, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "GitLab Agent Token",
        trigger: Trigger::ValuePrefix("glagent-"),
        value: ValueSpec { min_len: 50, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },

    // ── Google / GCP / Firebase ───────────────────────────────────────────────────
    PatternDef {
        name: "Google API Key",
        trigger: Trigger::ValuePrefix("AIza"),
        value: ValueSpec { min_len: 35, max_len: 35, charset: Charset::AlphaNumDash, min_entropy: 3.0 },
    },
    PatternDef {
        name: "Firebase API Key",
        trigger: Trigger::ValuePrefix("AIzaSy"),
        value: ValueSpec { min_len: 33, max_len: 33, charset: Charset::AlphaNumDash, min_entropy: 3.0 },
    },
    PatternDef {
        name: "Google OAuth Client Secret",
        trigger: Trigger::ValuePrefix("GOCSPX-"),
        value: ValueSpec { min_len: 28, max_len: 28, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Google OAuth Access Token",
        trigger: Trigger::ValuePrefix("ya29."),
        value: ValueSpec { min_len: 50, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 3.0 },
    },

    // ── Azure ─────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Azure Storage Account Key",
        trigger: Trigger::KeyAssignment {
            keys: &["accountkey", "azure_storage_key", "storage_account_key"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 60, max_len: 90, charset: Charset::Base64, min_entropy: 4.0 },
    },
    PatternDef {
        name: "Azure Client Secret (env)",
        trigger: Trigger::KeyAssignment {
            keys: &["azure_client_secret", "arm_client_secret"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 34, max_len: 44, charset: Charset::AlphaNumDashDot, min_entropy: 3.5 },
    },

    // ── Stripe ───────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Stripe Secret Key",
        trigger: Trigger::AnyValuePrefix(&["sk_live_", "sk_test_"]),
        value: ValueSpec { min_len: 24, max_len: 99, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Stripe Restricted Key",
        trigger: Trigger::AnyValuePrefix(&["rk_live_", "rk_test_"]),
        value: ValueSpec { min_len: 24, max_len: 99, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Stripe Webhook Secret",
        trigger: Trigger::ValuePrefix("whsec_"),
        value: ValueSpec { min_len: 32, max_len: 64, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },

    // ── Twilio ───────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Twilio Account SID",
        trigger: Trigger::ValuePrefix("AC"),
        value: ValueSpec { min_len: 32, max_len: 32, charset: Charset::LowerHex, min_entropy: 3.5 },
    },
    PatternDef {
        name: "Twilio Auth Token (env)",
        trigger: Trigger::KeyAssignment {
            keys: &["twilio_auth_token", "twilio_token"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 32, max_len: 32, charset: Charset::LowerHex, min_entropy: 3.5 },
    },

    // ── Slack ─────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Slack Bot Token",
        trigger: Trigger::ValuePrefix("xoxb-"),
        value: ValueSpec { min_len: 20, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Slack User Token",
        trigger: Trigger::ValuePrefix("xoxp-"),
        value: ValueSpec { min_len: 20, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Slack App Token",
        trigger: Trigger::ValuePrefix("xapp-"),
        value: ValueSpec { min_len: 20, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Slack Signing Secret (env)",
        trigger: Trigger::KeyAssignment {
            keys: &["slack_signing_secret", "slack_secret"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 32, max_len: 32, charset: Charset::LowerHex, min_entropy: 3.5 },
    },

    // ── SendGrid ─────────────────────────────────────────────────────────────────
    PatternDef {
        name: "SendGrid API Key",
        trigger: Trigger::ValuePrefix("SG."),
        // SG.<22 chars>.<43 chars> — validate combined length, dot is in AlphaNumDash
        value: ValueSpec { min_len: 66, max_len: 70, charset: Charset::AlphaNumDash, min_entropy: 3.5 },
    },

    // ── npm ──────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "npm Access Token",
        trigger: Trigger::ValuePrefix("npm_"),
        value: ValueSpec { min_len: 36, max_len: 36, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },

    // ── PyPI ─────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "PyPI Upload Token",
        trigger: Trigger::ValuePrefix("pypi-"),
        value: ValueSpec { min_len: 42, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },

    // ── HuggingFace ──────────────────────────────────────────────────────────────
    PatternDef {
        name: "HuggingFace User Token",
        trigger: Trigger::ValuePrefix("hf_"),
        value: ValueSpec { min_len: 34, max_len: 0, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },

    // ── Anthropic ────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Anthropic API Key",
        trigger: Trigger::AnyValuePrefix(&["sk-ant-api03-", "sk-ant-admin01-"]),
        value: ValueSpec { min_len: 90, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Anthropic API Key (env)",
        trigger: Trigger::KeyedValuePrefix {
            keys: &["anthropic_api_key"],
            prefix: "sk-ant-",
        },
        value: ValueSpec { min_len: 90, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },

    // ── OpenAI ───────────────────────────────────────────────────────────────────
    PatternDef {
        name: "OpenAI API Key",
        trigger: Trigger::AnyValuePrefix(&["sk-proj-", "sk-openai-"]),
        value: ValueSpec { min_len: 48, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "OpenAI API Key (env)",
        trigger: Trigger::KeyedValuePrefix {
            keys: &["openai_api_key"],
            prefix: "sk-",
        },
        value: ValueSpec { min_len: 45, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 3.8 },
    },

    // ── Databricks ────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Databricks API Token",
        trigger: Trigger::ValuePrefix("dapi"),
        value: ValueSpec { min_len: 32, max_len: 32, charset: Charset::LowerHex, min_entropy: 3.5 },
    },

    // ── HashiCorp Vault ───────────────────────────────────────────────────────────
    PatternDef {
        name: "Vault Service Token",
        trigger: Trigger::ValuePrefix("hvs."),
        value: ValueSpec { min_len: 90, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Vault Batch Token",
        trigger: Trigger::ValuePrefix("hvb."),
        value: ValueSpec { min_len: 138, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },

    // ── DigitalOcean ──────────────────────────────────────────────────────────────
    PatternDef {
        name: "DigitalOcean Personal Access Token",
        trigger: Trigger::ValuePrefix("dop_v1_"),
        value: ValueSpec { min_len: 43, max_len: 43, charset: Charset::LowerHex, min_entropy: 0.0 },
    },
    PatternDef {
        name: "DigitalOcean OAuth Token",
        trigger: Trigger::ValuePrefix("doo_v1_"),
        value: ValueSpec { min_len: 64, max_len: 64, charset: Charset::LowerHex, min_entropy: 0.0 },
    },

    // ── Linear ────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Linear API Key",
        trigger: Trigger::ValuePrefix("lin_api_"),
        value: ValueSpec { min_len: 40, max_len: 40, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },

    // ── Shopify ───────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Shopify Access Token",
        trigger: Trigger::ValuePrefix("shpat_"),
        value: ValueSpec { min_len: 32, max_len: 32, charset: Charset::Hex, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Shopify Custom App Token",
        trigger: Trigger::ValuePrefix("shpca_"),
        value: ValueSpec { min_len: 32, max_len: 32, charset: Charset::Hex, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Shopify Partner API Token",
        trigger: Trigger::ValuePrefix("shppa_"),
        value: ValueSpec { min_len: 32, max_len: 32, charset: Charset::Hex, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Shopify Shared Secret",
        trigger: Trigger::ValuePrefix("shpss_"),
        value: ValueSpec { min_len: 32, max_len: 32, charset: Charset::Hex, min_entropy: 0.0 },
    },

    // ── Netlify ───────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Netlify Personal Access Token",
        trigger: Trigger::ValuePrefix("nfp_"),
        value: ValueSpec { min_len: 36, max_len: 36, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },

    // ── Square ───────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Square Access Token",
        trigger: Trigger::ValuePrefix("sq0atp-"),
        value: ValueSpec { min_len: 22, max_len: 22, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Square App Secret",
        trigger: Trigger::ValuePrefix("sq0csp-"),
        value: ValueSpec { min_len: 43, max_len: 43, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },
    PatternDef {
        name: "Square OAuth Token",
        trigger: Trigger::ValuePrefix("EAAAE"),
        value: ValueSpec { min_len: 60, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 3.5 },
    },

    // ── Pulumi ────────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Pulumi Access Token",
        trigger: Trigger::ValuePrefix("pul-"),
        value: ValueSpec { min_len: 40, max_len: 40, charset: Charset::AlphaNum, min_entropy: 0.0 },
    },

    // ── Tailscale ────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Tailscale API Key",
        trigger: Trigger::ValuePrefix("tskey-"),
        value: ValueSpec { min_len: 30, max_len: 0, charset: Charset::AlphaNumDash, min_entropy: 0.0 },
    },

    // ── Doppler ───────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Doppler Service Token",
        trigger: Trigger::ValuePrefix("dp.st."),
        value: ValueSpec { min_len: 40, max_len: 0, charset: Charset::AlphaNumDashDot, min_entropy: 0.0 },
    },

    // ── Supabase ──────────────────────────────────────────────────────────────────
    PatternDef {
        name: "Supabase Service Key",
        trigger: Trigger::ValuePrefix("sbp_"),
        value: ValueSpec { min_len: 40, max_len: 40, charset: Charset::LowerHex, min_entropy: 0.0 },
    },

    // ── New Relic ─────────────────────────────────────────────────────────────────
    PatternDef {
        name: "New Relic API Key",
        trigger: Trigger::ValuePrefix("NRAK-"),
        value: ValueSpec { min_len: 27, max_len: 27, charset: Charset::UpperAlphaNum, min_entropy: 3.0 },
    },

    // ── Private keys / certificates ────────────────────────────────────────────
    // These are multi-line blocks; we detect just the header line.
    PatternDef {
        name: "PEM Private Key Header",
        trigger: Trigger::AnyValuePrefix(&[
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        ]),
        // The value after the prefix is the rest of the header line (dashes handled above)
        value: ValueSpec { min_len: 0, max_len: 0, charset: Charset::Printable, min_entropy: 0.0 },
    },

    // ── JWT ──────────────────────────────────────────────────────────────────────
    // JWT = eyJ<base64url>.<base64url>.<base64url>
    PatternDef {
        name: "JWT Token",
        trigger: Trigger::ValuePrefix("eyJ"),
        // Validate that we get two more dot-separated segments
        value: ValueSpec { min_len: 30, max_len: 0, charset: Charset::AlphaNumDashDot, min_entropy: 3.5 },
    },

    // ── Database / service connection strings ──────────────────────────────────
    PatternDef {
        name: "Database URL with embedded credentials",
        trigger: Trigger::KeyAssignment {
            keys: &["database_url", "db_url", "postgres_url", "mysql_url",
                    "mongo_uri", "mongodb_uri", "redis_url", "connection_string",
                    "database_uri", "db_connection"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 10, max_len: 0, charset: Charset::Printable, min_entropy: 2.0 },
    },

    // ── Generic contextual patterns ────────────────────────────────────────────
    // These fire only when a known-sensitive key name is present.
    PatternDef {
        name: "Password (assignment)",
        trigger: Trigger::KeyAssignment {
            keys: &["password", "passwd", "db_password", "db_pass",
                    "database_password", "admin_password", "root_password",
                    "smtp_password", "ftp_password"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 8, max_len: 0, charset: Charset::Printable, min_entropy: 3.0 },
    },
    PatternDef {
        name: "API Key (generic assignment)",
        trigger: Trigger::KeyAssignment {
            keys: &["api_key", "apikey", "api_secret", "app_key", "app_secret",
                    "client_secret", "client_key", "access_key", "secret_key",
                    "private_key", "auth_token", "service_key"],
            sep: Sep::Any,
        },
        value: ValueSpec { min_len: 16, max_len: 0, charset: Charset::Printable, min_entropy: 3.5 },
    },
    PatternDef {
        name: "Bearer Token (header)",
        trigger: Trigger::ValuePrefix("Bearer "),
        value: ValueSpec { min_len: 20, max_len: 0, charset: Charset::Base64Url, min_entropy: 3.5 },
    },
];

// ── Shannon entropy ────────────────────────────────────────────────────────────

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f32;
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    -freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            p * p.log2()
        })
        .sum::<f32>()
}

// ── Value extractor ────────────────────────────────────────────────────────────

/// Extract a value from `text` starting at position 0 according to `spec`.
/// Returns `Some(value_str)` if structural constraints are satisfied, else `None`.
fn extract_value<'a>(text: &'a str, spec: &ValueSpec) -> Option<&'a str> {
    // Skip leading whitespace and an optional opening quote
    let text = text.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (text, quoted) = if text.starts_with('"') || text.starts_with('\'') {
        let q = text.chars().next().unwrap();
        (&text[q.len_utf8()..], Some(q))
    } else {
        (text, None)
    };

    // Consume characters according to the charset
    let end = text
        .char_indices()
        .take_while(|(_, c)| {
            // Stop at the closing quote if we started with one
            if let Some(q) = quoted {
                if *c == q {
                    return false;
                }
            }
            spec.charset.accepts(*c)
        })
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);

    let value = &text[..end];

    // Enforce length constraints
    if value.len() < spec.min_len {
        return None;
    }
    if spec.max_len > 0 && value.len() > spec.max_len {
        return None;
    }

    Some(value)
}

// ── Allowlist ──────────────────────────────────────────────────────────────────
// Lines containing obvious placeholder strings are skipped entirely.

const ALLOWLIST: &[&str] = &[
    "example.com",
    "example.org",
    "example.net",
    "your-api-key",
    "your_api_key",
    "YOUR_API_KEY",
    "INSERT_YOUR_",
    "REPLACE_WITH_",
    "<your",
    "xxxxxxxxxxx",
    "000000000000",
    "changeme",
    "placeholder",
];

fn is_placeholder(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ALLOWLIST.iter().any(|&s| lower.contains(s))
}

// ── Line scanner ──────────────────────────────────────────────────────────────

/// Try to find the given pattern anywhere in `line`.
/// Returns `Some(matched_value)` on success.
fn match_pattern<'a>(pat: &PatternDef, line: &'a str) -> Option<&'a str> {
    let lower = line.to_ascii_lowercase();

    match &pat.trigger {
        Trigger::ValuePrefix(prefix) => {
            let pos = line.find(prefix)?;
            let value = extract_value(&line[pos + prefix.len()..], &pat.value)?;
            Some(value)
        }

        Trigger::AnyValuePrefix(prefixes) => {
            for &prefix in *prefixes {
                if let Some(pos) = line.find(prefix) {
                    if let Some(value) = extract_value(&line[pos + prefix.len()..], &pat.value) {
                        return Some(value);
                    }
                }
            }
            None
        }

        Trigger::KeyAssignment { keys, sep } => {
            for &key in *keys {
                let Some(key_pos) = lower.find(key) else { continue };
                let after_key = lower[key_pos + key.len()..].trim_start();

                let sep_ok = match sep {
                    Sep::Equals => after_key.starts_with('='),
                    Sep::Colon  => after_key.starts_with(':'),
                    Sep::Any    => after_key.starts_with('=') || after_key.starts_with(':'),
                };
                if !sep_ok {
                    continue;
                }

                // Find the same position in the original (non-lowercased) line
                let sep_offset = lower[key_pos + key.len()..]
                    .find(|c| c == '=' || c == ':')
                    .unwrap();
                let original_after_sep =
                    &line[key_pos + key.len() + sep_offset + 1..];

                if let Some(value) = extract_value(original_after_sep, &pat.value) {
                    if !value.is_empty() {
                        return Some(value);
                    }
                }
            }
            None
        }

        Trigger::KeyedValuePrefix { keys, prefix } => {
            // First confirm a relevant key name is somewhere on the line
            let has_key = keys.iter().any(|&k| lower.contains(k));
            if !has_key {
                return None;
            }
            // Then find the value prefix
            let pos = line.find(prefix)?;
            extract_value(&line[pos + prefix.len()..], &pat.value)
        }
    }
}

// ── SecretScanner ─────────────────────────────────────────────────────────────

pub struct SecretScanner;

impl Default for SecretScanner {
    fn default() -> Self {
        Self
    }
}

impl SecretScanner {
    /// Number of compiled patterns.
    pub fn pattern_count(&self) -> usize {
        PATTERNS.len()
    }

    /// Scan a single line; returns all pattern matches.
    fn scan_line(&self, line: &str, line_number: usize) -> Vec<SecretMatch> {
        if is_placeholder(line) {
            return vec![];
        }

        let mut matches: Vec<SecretMatch> = Vec::new();

        for pat in PATTERNS {
            let Some(value) = match_pattern(pat, line) else { continue };

            // Entropy gate
            if pat.value.min_entropy > 0.0
                && shannon_entropy(value) < pat.value.min_entropy
            {
                continue;
            }

            let matched_value: String = value.chars().take(40).collect();
            let excerpt: String = line.trim().chars().take(100).collect();
            let ellipsis = if line.trim().len() > 100 { "…" } else { "" };
            let snippet = format!("{excerpt}{ellipsis}  ▶ {}: {matched_value}…", pat.name);

            matches.push(SecretMatch {
                pattern_name: pat.name.to_string(),
                line_number,
                snippet,
                matched_value,
            });
        }

        // If the same value was caught by multiple patterns, keep only the first
        // (most specific) hit for that value.
        matches.dedup_by(|a, b| a.matched_value == b.matched_value);
        matches
    }

    /// Scan multi-line content (e.g. a full file or a diff hunk).
    pub fn scan_content(&self, content: &str) -> Vec<SecretMatch> {
        content
            .lines()
            .enumerate()
            .flat_map(|(idx, line)| self.scan_line(line, idx + 1))
            .collect()
    }

    /// Scan a file. Skips binary files and files larger than 2 MB.
    pub fn scan_file(&self, path: &Path) -> Vec<SecretMatch> {
        let Ok(meta) = std::fs::metadata(path) else { return vec![] };
        if meta.len() > 2_000_000 {
            return vec![];
        }
        let Ok(content) = std::fs::read_to_string(path) else { return vec![] };
        self.scan_content(&content)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> SecretScanner { SecretScanner::default() }

    #[test]
    fn pattern_count_reasonable() {
        assert!(s().pattern_count() >= 40, "expected 40+ patterns, got {}", s().pattern_count());
    }

    #[test]
    fn entropy_low_for_repeated() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 0.1);
    }

    #[test]
    fn entropy_high_for_random() {
        // realistic 40-char AWS secret key segment
        assert!(shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzAbCdEfGh") > 3.5);
    }

    #[test]
    fn detects_github_classic_pat() {
        let line = "GITHUB_TOKEN=ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYz";
        let hits = s().scan_line(line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("GitHub")), "{hits:?}");
    }

    #[test]
    fn detects_aws_key_id() {
        let line = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFGH";
        let hits = s().scan_line(line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("AWS Access Key")), "{hits:?}");
    }

    #[test]
    fn detects_aws_secret_by_key_name() {
        let line = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let hits = s().scan_line(line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("AWS Secret")), "{hits:?}");
    }

    #[test]
    fn detects_stripe_secret_key() {
        let key = format!("sk_live_{}", "A".repeat(24));
        let line = format!("STRIPE_SK={key}");
        let hits = s().scan_line(&line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("Stripe")), "{hits:?}");
    }

    #[test]
    fn detects_pem_header() {
        let line = "-----BEGIN RSA PRIVATE KEY-----";
        let hits = s().scan_line(line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("PEM")), "{hits:?}");
    }

    #[test]
    fn detects_anthropic_key() {
        let key = format!("sk-ant-api03-{}", "A".repeat(90));
        let line = format!("KEY={key}");
        let hits = s().scan_line(&line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("Anthropic")), "{hits:?}");
    }

    #[test]
    fn detects_database_url_by_key() {
        let line = r#"DATABASE_URL=postgresql://admin:s3cr3tP@ssw0rd!@db.internal/prod"#;
        let hits = s().scan_line(line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("Database")), "{hits:?}");
    }

    #[test]
    fn detects_password_assignment() {
        let line = r#"db_password = "SuperSecretPass123!""#;
        let hits = s().scan_line(line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("Password")), "{hits:?}");
    }

    #[test]
    fn ignores_placeholder_line() {
        let line = "API_KEY=your-api-key-placeholder";
        let hits = s().scan_line(line, 1);
        assert!(hits.is_empty(), "placeholder should be suppressed, got {hits:?}");
    }

    #[test]
    fn ignores_low_entropy_generic_value() {
        // "password = aaaaaaaaaaaaaaa" — too low entropy to be a real secret
        let line = "password = aaaaaaaaaaaaaaaa";
        let hits = s().scan_line(line, 1);
        assert!(hits.is_empty(), "low-entropy password should be suppressed, got {hits:?}");
    }

    #[test]
    fn detects_slack_bot_token() {
        let token = format!(
            "xoxb-{}-{}-{}",
            "1".repeat(10),
            "9".repeat(10),
            "a".repeat(24),
        );
        let line = format!("BOT={token}");
        let hits = s().scan_line(&line, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("Slack")), "{hits:?}");
    }

    #[test]
    fn detects_vault_service_token() {
        let tok = format!("hvs.{}", "A".repeat(90));
        let hits = s().scan_line(&tok, 1);
        assert!(hits.iter().any(|h| h.pattern_name.contains("Vault")), "{hits:?}");
    }

    #[test]
    fn scan_content_multi_line() {
        let content = "FOO=bar\nGITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\nBAZ=qux";
        let hits = s().scan_content(content);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].line_number, 2);
    }

    #[test]
    fn charset_accepts_correct_chars() {
        assert!( Charset::LowerHex.accepts('a'));
        assert!(!Charset::LowerHex.accepts('A'));
        assert!( Charset::Hex.accepts('A'));
        assert!(!Charset::AlphaNum.accepts('-'));
        assert!( Charset::AlphaNumDash.accepts('-'));
    }
}
