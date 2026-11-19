//! Source-declared discovery and descriptive metadata. No executable presentation.
use crate::{DomainError, SourceRef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use utoipa::ToSchema;

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryQuery {
    #[serde(default)]
    pub filters: BTreeMap<String, Vec<String>>,
    pub sort: Option<String>,
    pub feed: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryOption {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appearance: Option<LabelAppearance>,
}
/// A source's label color, never arbitrary CSS or executable presentation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LabelAppearance {
    pub color: String,
}
impl LabelAppearance {
    pub fn valid(&self) -> bool {
        self.color.len() == 7
            && self.color.starts_with('#')
            && self.color.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryFilter {
    pub id: String,
    pub label: String,
    pub multiple: bool,
    pub options: Vec<DiscoveryOption>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySchema {
    /// Query this discovery operation with a query (including empty for popular tags).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tag_search: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<DiscoveryOption>,
    pub filters: Vec<DiscoveryFilter>,
    pub sorts: Vec<DiscoveryOption>,
    pub feeds: Vec<DiscoveryOption>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MetadataField {
    pub label: String,
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appearance: Option<LabelAppearance>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectionDetails {
    pub reference: SourceRef,
    pub description: Option<String>,
    pub alternative_titles: BTreeMap<String, Vec<String>>,
    pub creators: Vec<MetadataField>,
    pub tags: Vec<DiscoveryOption>,
    pub facts: Vec<MetadataField>,
    pub languages: Vec<String>,
    /// Honest explanation of source-provided or similarity-based recommendations.
    pub recommendation_basis: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Artwork {
    pub id: String,
    pub label: String,
    pub url: String,
    #[serde(default)]
    pub locale: Option<String>,
}
fn fail() -> DomainError {
    DomainError::Invalid("Invalid discovery or descriptive metadata".into())
}
fn text(s: &str) -> bool {
    !s.is_empty() && s.len() <= 2048
}
fn options(items: &[DiscoveryOption]) -> bool {
    let mut ids = BTreeSet::new();
    items.len() <= 500
        && items.iter().all(|o| {
            text(&o.id)
                && text(&o.label)
                && ids.insert(&o.id)
                && o.appearance.as_ref().is_none_or(LabelAppearance::valid)
        })
}
impl DiscoveryQuery {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.filters.len() > 32
            || self
                .filters
                .iter()
                .any(|(k, v)| !text(k) || v.len() > 100 || v.iter().any(|s| !text(s)))
            || self.sort.iter().chain(self.feed.iter()).any(|s| !text(s))
        {
            return Err(fail());
        }
        Ok(())
    }
}
impl DiscoverySchema {
    pub fn validate(&self) -> Result<(), DomainError> {
        let mut ids = BTreeSet::new();
        if self.filters.len() > 32
            || !options(&self.tags)
            || !options(&self.sorts)
            || !options(&self.feeds)
            || self.filters.iter().any(|f| {
                !text(&f.id) || !text(&f.label) || !ids.insert(&f.id) || !options(&f.options)
            })
        {
            return Err(fail());
        }
        Ok(())
    }
}
impl CollectionDetails {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self
            .description
            .as_ref()
            .is_some_and(|s| s.len() > 128 * 1024)
            || self.alternative_titles.len() > 200
            || self
                .alternative_titles
                .iter()
                .any(|(k, v)| !text(k) || v.len() > 50 || v.iter().any(|s| !text(s)))
            || self.creators.len() > 32
            || self.facts.len() > 64
            || self.creators.iter().chain(self.facts.iter()).any(|f| {
                !text(&f.label)
                    || f.values.len() > 200
                    || f.values.iter().any(|s| !text(s))
                    || f.appearance.as_ref().is_some_and(|a| !a.valid())
            })
            || !options(&self.tags)
            || self.languages.len() > 200
            || self.languages.iter().any(|s| !text(s))
            || self
                .recommendation_basis
                .as_ref()
                .is_some_and(|s| s.len() > 2048)
        {
            return Err(fail());
        }
        Ok(())
    }
}
impl Artwork {
    pub fn validate(&self) -> Result<(), DomainError> {
        let url = url::Url::parse(&self.url).map_err(|_| fail())?;
        if self.locale.as_ref().is_some_and(|v| {
            v.len() > 35
                || v.is_empty()
                || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }) || !text(&self.id)
            || !text(&self.label)
            || self.url.len() > 8192
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(fail());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_colors_are_data_not_css() {
        for color in ["#04d000", "#FF4040", "#7d40ff"] {
            assert!(
                LabelAppearance {
                    color: color.into()
                }
                .valid()
            );
        }
        for color in [
            "red",
            "#fff",
            "#12345g",
            "url(https://example.org)",
            "#123456;display:none",
        ] {
            assert!(
                !LabelAppearance {
                    color: color.into()
                }
                .valid()
            );
        }
        let mut summary = crate::CollectionSummary::default();
        summary.tags.push("Warning".into());
        summary.tag_appearances.insert(
            "Warning".into(),
            LabelAppearance {
                color: "#ff4040".into(),
            },
        );
        assert!(summary.validate().is_ok());
        summary.tag_appearances.insert(
            "Missing".into(),
            LabelAppearance {
                color: "#ff4040".into(),
            },
        );
        assert!(summary.validate().is_err());
    }
    #[test]
    fn discovery_rejects_duplicate_filter_identity_and_unbounded_input() {
        let option = DiscoveryOption {
            id: "status".into(),
            label: "Status".into(),
            appearance: None,
        };
        let filter = DiscoveryFilter {
            id: "status".into(),
            label: "Status".into(),
            multiple: true,
            options: vec![option],
        };
        let mut schema = DiscoverySchema {
            tag_search: false,
            tags: vec![],
            filters: vec![filter.clone()],
            sorts: vec![],
            feeds: vec![],
        };
        assert!(schema.validate().is_ok());
        schema.filters.push(filter);
        assert!(schema.validate().is_err());
        let mut query = DiscoveryQuery::default();
        query.filters.insert("tags".into(), vec!["x".into(); 101]);
        assert!(query.validate().is_err());
    }
    #[test]
    fn artwork_locale_is_optional_and_bounded() {
        let mut art:Artwork=serde_json::from_value(serde_json::json!({"id":"cover","label":"Volume 1","url":"https://example.org/cover.jpg"})).unwrap();
        assert!(art.validate().is_ok());
        art.locale = Some("pt-br".into());
        assert!(art.validate().is_ok());
        art.locale = Some("../en".into());
        assert!(art.validate().is_err());
    }
    #[test]
    fn artwork_rejects_local_or_credential_urls() {
        for url in ["file:///etc/passwd", "https://secret@example.org/image"] {
            assert!(
                Artwork {
                    id: "1".into(),
                    label: "Cover".into(),
                    url: url.into(),
                    locale: None
                }
                .validate()
                .is_err()
            );
        }
    }
}
