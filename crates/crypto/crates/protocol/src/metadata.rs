//! Encrypted metadata contract. These types do not establish evidence or trust.
use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

pub type ExtraFields = BTreeMap<String, serde_json::Value>;

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct MemoryMeta {
    pub memory_contract: u8,
    pub summary: Option<String>,
    pub source_refs: Vec<SourceRef>,
    pub valid_until: Option<String>,
    pub review_at: Option<String>,
    pub artifact: Option<Artifact>,
    pub verification: Option<Verification>,
}

impl Serialize for MemoryMeta {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        // Keep the exact legacy field set; contract 1 includes explicit nulls.
        if self != &Self::default() {
            map.serialize_entry("memory_contract", &self.memory_contract)?;
            map.serialize_entry("summary", &self.summary)?;
            map.serialize_entry("source_refs", &self.source_refs)?;
            map.serialize_entry("valid_until", &self.valid_until)?;
            map.serialize_entry("review_at", &self.review_at)?;
            map.serialize_entry("artifact", &self.artifact)?;
            map.serialize_entry("verification", &self.verification)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceRef {
    pub id: String,
    pub revision: String,
    pub required: bool,
    #[serde(flatten)]
    pub unknown_fields: ExtraFields,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    pub path: Option<String>,
    pub repo: Option<String>,
    pub commit: Option<String>,
    pub purpose: Option<String>,
    #[serde(flatten)]
    pub unknown_fields: ExtraFields,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    pub project: Option<String>,
    pub device: Option<String>,
    pub version: Option<String>,
    pub from: Option<String>,
    pub until: Option<String>,
    #[serde(flatten)]
    pub unknown_fields: ExtraFields,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    Memory {
        id: String,
        revision: String,
        #[serde(flatten)]
        unknown_fields: ExtraFields,
    },
    User {
        locator: String,
        revision: String,
        #[serde(flatten)]
        unknown_fields: ExtraFields,
    },
    Primary {
        locator: String,
        revision: String,
        #[serde(flatten)]
        unknown_fields: ExtraFields,
    },
    Run {
        locator: String,
        revision: String,
        #[serde(flatten)]
        unknown_fields: ExtraFields,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmerKind {
    Human,
    TrustedHost,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfirmedBy {
    pub kind: ConfirmerKind,
    pub id: String,
    pub event_id: String,
    #[serde(flatten)]
    pub unknown_fields: ExtraFields,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verification {
    pub record_revision: String,
    pub claim: String,
    pub scope: Scope,
    pub evidence: Vec<Evidence>,
    pub method: String,
    pub confirmed_by: ConfirmedBy,
    pub confirmed_at: String,
    #[serde(flatten)]
    pub unknown_fields: ExtraFields,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestScope {
    pub project: Option<String>,
    pub device: Option<String>,
    pub version: Option<String>,
    pub at: String,
    #[serde(flatten)]
    pub unknown_fields: ExtraFields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataError {
    pub code: &'static str,
    pub message: &'static str,
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for MetadataError {}

fn invalid(message: &'static str) -> MetadataError {
    MetadataError {
        code: "invalid_metadata",
        message,
    }
}

pub fn validate_extra_fields(fields: &ExtraFields) -> Result<(), MetadataError> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(MetadataError {
            code: "unsupported_metadata",
            message: "unknown metadata fields",
        })
    }
}

pub fn validate_revision(value: &str) -> Result<(), MetadataError> {
    match value.strip_prefix("sha256:") {
        Some(hex)
            if hex.len() == 64
                && hex
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) =>
        {
            Ok(())
        }
        _ => Err(invalid(
            "revision must be sha256 followed by 64 lowercase hexadecimal digits",
        )),
    }
}

pub fn validate_full_id(value: &str) -> Result<(), MetadataError> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    if valid {
        Ok(())
    } else {
        Err(invalid("source ID must be a complete UUID"))
    }
}

pub fn validate_timestamp(value: &str) -> Result<(), MetadataError> {
    let b = value.as_bytes();
    if b.len() != 24
        || !b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'.',
            23 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
    {
        return Err(invalid("time must be YYYY-MM-DDTHH:MM:SS.SSSZ"));
    }
    let number = |start: usize, end: usize| {
        b[start..end]
            .iter()
            .fold(0u32, |n, c| n * 10 + u32::from(*c - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    if day == 0 || day > days || number(11, 13) > 23 || number(14, 16) > 59 || number(17, 19) > 59 {
        return Err(invalid("invalid UTC calendar date or time"));
    }
    Ok(())
}

impl Scope {
    pub fn validate(&self) -> Result<(), MetadataError> {
        validate_extra_fields(&self.unknown_fields)?;
        for value in [&self.from, &self.until].into_iter().flatten() {
            if value != "*" {
                validate_timestamp(value)?;
            }
        }
        if let (Some(from), Some(until)) = (&self.from, &self.until) {
            if from != "*" && until != "*" && from >= until {
                return Err(invalid("scope requires from < until"));
            }
        }
        Ok(())
    }
}

impl RequestScope {
    pub fn validate(&self) -> Result<(), MetadataError> {
        validate_extra_fields(&self.unknown_fields)?;
        if [&self.project, &self.device, &self.version]
            .into_iter()
            .flatten()
            .any(|v| v == "*")
        {
            return Err(invalid("request scope cannot contain a wildcard"));
        }
        validate_timestamp(&self.at)
    }
}

impl Evidence {
    pub fn validate(&self) -> Result<(), MetadataError> {
        let (locator, revision, fields) = match self {
            Self::Memory {
                id,
                revision,
                unknown_fields,
            } => {
                validate_full_id(id)?;
                (id, revision, unknown_fields)
            }
            Self::User {
                locator,
                revision,
                unknown_fields,
            }
            | Self::Primary {
                locator,
                revision,
                unknown_fields,
            }
            | Self::Run {
                locator,
                revision,
                unknown_fields,
            } => (locator, revision, unknown_fields),
        };
        validate_extra_fields(fields)?;
        if locator.trim().is_empty() {
            return Err(invalid("evidence locator cannot be empty"));
        }
        validate_revision(revision)
    }
}

impl Verification {
    /// Structural validation only; confirmed_by is not proof of authority.
    pub fn validate(&self) -> Result<(), MetadataError> {
        validate_extra_fields(&self.unknown_fields)?;
        validate_extra_fields(&self.confirmed_by.unknown_fields)?;
        validate_revision(&self.record_revision)?;
        validate_timestamp(&self.confirmed_at)?;
        self.scope.validate()?;
        if self.claim.trim().is_empty()
            || self.method.trim().is_empty()
            || self.evidence.is_empty()
            || self.confirmed_by.id.trim().is_empty()
            || self.confirmed_by.event_id.trim().is_empty()
        {
            return Err(invalid(
                "verification requires claim, method, evidence and confirmation identity",
            ));
        }
        let mut unique = BTreeSet::new();
        for evidence in &self.evidence {
            evidence.validate()?;
            let encoded =
                serde_json::to_string(evidence).map_err(|_| invalid("invalid evidence"))?;
            if !unique.insert(encoded) {
                return Err(invalid("duplicate evidence"));
            }
        }
        Ok(())
    }
}

impl MemoryMeta {
    pub fn validate(&self) -> Result<(), MetadataError> {
        match self.memory_contract {
            0 if self == &Self::default() => return Ok(()),
            0 => return Err(invalid("contract 0 cannot contain metadata")),
            1 => {}
            _ => {
                return Err(MetadataError {
                    code: "unsupported_metadata",
                    message: "unknown memory contract",
                })
            }
        }
        if self
            .summary
            .as_ref()
            .is_some_and(|s| s.chars().count() > 120)
        {
            return Err(invalid("summary exceeds 120 Unicode scalars"));
        }
        let mut ids = BTreeSet::new();
        for source in &self.source_refs {
            validate_extra_fields(&source.unknown_fields)?;
            validate_full_id(&source.id)?;
            validate_revision(&source.revision)?;
            if !ids.insert(&source.id) {
                return Err(invalid("duplicate source ID"));
            }
        }
        for value in [&self.valid_until, &self.review_at].into_iter().flatten() {
            validate_timestamp(value)?;
        }
        if let Some(artifact) = &self.artifact {
            validate_extra_fields(&artifact.unknown_fields)?;
        }
        if let Some(verification) = &self.verification {
            verification.validate()?;
        }
        Ok(())
    }

    /// Ordinary write inputs cannot supply verification or extension semantics.
    pub fn from_input(value: serde_json::Value) -> Result<Self, MetadataError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("metadata input must be an object"))?;
        if object.contains_key("verification")
            || object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "memory_contract"
                        | "summary"
                        | "source_refs"
                        | "valid_until"
                        | "review_at"
                        | "artifact"
                )
            })
        {
            return Err(invalid("unknown or forbidden metadata input field"));
        }
        let meta: Self =
            serde_json::from_value(value).map_err(|_| invalid("invalid metadata input shape"))?;
        meta.validate().map_err(|error| MetadataError {
            code: "invalid_metadata",
            message: error.message,
        })?;
        Ok(meta)
    }
}
