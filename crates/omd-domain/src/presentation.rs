//! User presentation is separate from immutable source metadata and identity.
use crate::*;
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MetadataOverride {
    pub title: Option<String>,
    pub description: Option<String>,
    pub chapter: Option<String>,
    pub volume: Option<String>,
}
impl MetadataOverride {
    pub fn validate(&self, collection: bool) -> Result<(), DomainError> {
        if self.title.as_ref().is_some_and(|v| {
            v.trim().is_empty() || v.len() > 1000 || v.chars().any(char::is_control)
        }) || self.description.as_ref().is_some_and(|v| {
            v.len() > 32000
                || v.chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
        }) || [&self.chapter, &self.volume].iter().any(|v| {
            v.as_ref()
                .is_some_and(|v| v.len() > 100 || v.chars().any(char::is_control))
        }) || collection && (self.chapter.is_some() || self.volume.is_some())
        {
            return Err(DomainError::Invalid("Use a title up to 1,000 bytes, description up to 32,000 bytes, and textual chapter/volume identifiers up to 100 bytes. Chapter and volume apply to releases only.".into()));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct OutputMetadata {
    pub collection: MetadataOverride,
    pub release: MetadataOverride,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NamingTemplates {
    pub collection: String,
    pub release: String,
}
impl Default for NamingTemplates {
    fn default() -> Self {
        Self {
            collection: "{title}".into(),
            release: "{title}".into(),
        }
    }
}
impl NamingTemplates {
    pub fn validate(&self) -> Result<(), DomainError> {
        self.expand(&self.collection, true, |_| "".into())?;
        self.expand(&self.release, false, |_| "".into())?;
        Ok(())
    }
    fn expand(
        &self,
        template: &str,
        collection: bool,
        field: impl Fn(&str) -> String,
    ) -> Result<String, DomainError> {
        fn invalid() -> DomainError {
            DomainError::Invalid("Use one filename segment with supported {fields}; paths, control characters, unmatched braces, and templates over 500 bytes are not allowed.".into())
        }
        if template.trim().is_empty()
            || template.len() > 500
            || template
                .chars()
                .any(|c| c.is_control() || "/\\<>:\"|?*".contains(c))
        {
            return Err(invalid());
        }
        let mut text = template;
        let mut output = String::new();
        while let Some(start) = text.find('{') {
            if text[..start].contains('}') {
                return Err(invalid());
            }
            output.push_str(&text[..start]);
            let rest = &text[start + 1..];
            let end = rest.find('}').ok_or_else(invalid)?;
            let token = &rest[..end];
            if !["title", "source_id", "provider", "kind"].contains(&token)
                && (collection || !["chapter", "volume", "language", "group"].contains(&token))
            {
                return Err(invalid());
            }
            output.push_str(&field(token));
            text = &rest[end + 1..];
        }
        if text.contains('}') {
            return Err(invalid());
        }
        output.push_str(text);
        Ok(output)
    }
    pub fn path(&self, plan: &Plan) -> Result<String, DomainError> {
        let collection = self.expand(&self.collection, true, |name| match name {
            "title" => plan.collection_title().into(),
            "provider" => plan.collection.reference.provider.clone(),
            "source_id" => plan.collection.reference.id.clone(),
            "kind" => serde_json::to_value(plan.collection.kind)
                .unwrap()
                .as_str()
                .unwrap()
                .into(),
            _ => unreachable!(),
        })?;
        let release = self.expand(&self.release, false, |name| match name {
            "title" => plan.release_title().into(),
            "provider" => plan.release.reference.provider.clone(),
            "source_id" => plan.release.reference.id.clone(),
            "kind" => serde_json::to_value(plan.recipe)
                .unwrap()
                .as_str()
                .unwrap()
                .into(),
            "chapter" => plan.chapter().into(),
            "volume" => plan.volume().into(),
            "language" => plan.release.language.clone().unwrap_or_default(),
            "group" => plan.release.group.clone().unwrap_or_default(),
            _ => unreachable!(),
        })?;
        if plan.recipe == crate::Recipe::OriginalImages {
            return Ok(format!(
                "{} [{}]",
                path_segment(&collection, "Image post"),
                &plan.collection.reference.key()[..10]
            ));
        }
        Ok(format!(
            "{} [{}]/{} [{}]",
            path_segment(&collection, "Collection"),
            &plan.collection.reference.key()[..10],
            path_segment(&release, "Release"),
            &plan.release.reference.key()[..10]
        ))
    }
}
impl Plan {
    pub fn collection_title(&self) -> &str {
        self.metadata
            .collection
            .title
            .as_deref()
            .unwrap_or(&self.collection.title)
    }
    pub fn release_title(&self) -> &str {
        self.metadata
            .release
            .title
            .as_deref()
            .unwrap_or(&self.release.title)
    }
    pub fn chapter(&self) -> &str {
        self.metadata
            .release
            .chapter
            .as_deref()
            .or(self.release.chapter.as_deref())
            .unwrap_or("")
    }
    pub fn volume(&self) -> &str {
        self.metadata
            .release
            .volume
            .as_deref()
            .or(self.release.volume.as_deref())
            .unwrap_or("")
    }
    pub fn description(&self) -> Option<&str> {
        self.metadata
            .release
            .description
            .as_deref()
            .or(self.metadata.collection.description.as_deref())
            .or(self.collection.description.as_deref())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn size_preview_does_not_overflow_or_claim_an_unknown_total() {
        let mut plan: crate::Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        plan.outputs[0].expected_size = Some(u64::MAX);
        let mut second = plan.outputs[0].clone();
        second.id = "another".into();
        second.expected_size = Some(1);
        plan.outputs.push(second);
        assert_eq!(plan.estimated_bytes(), None);
        plan.outputs[0].expected_size = None;
        assert_eq!(plan.estimated_bytes(), None);
        for output in &mut plan.outputs {
            output.expected_size = Some(1);
        }
        assert_eq!(plan.estimated_bytes(), Some(plan.outputs.len() as u64));
    }
    #[test]
    fn templates_are_constrained_and_metadata_never_changes_identity() {
        let mut p: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        let key = p.acquisition_key();
        let source = p.release.clone();
        p.metadata.collection.title = Some("My / collection".into());
        p.metadata.release.chapter = Some("Special 12.5a".into());
        p.metadata.release.title = Some("CON".into());
        let naming = NamingTemplates {
            collection: "{title}".into(),
            release: "{chapter} - {title}".into(),
        };
        let path = naming.path(&p).unwrap();
        assert!(path.starts_with("My _ collection ["));
        assert!(path.contains("Special 12.5a - CON ["));
        assert_eq!(p.release, source);
        assert_eq!(p.acquisition_key(), key);
        for bad in [
            "../{title}",
            "{unknown}",
            "{title",
            "{title}}",
            "{title}/{chapter}",
            "\0",
        ] {
            assert!(
                NamingTemplates {
                    collection: bad.into(),
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            NamingTemplates {
                collection: "{chapter}".into(),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            path_segment(&format!("{}._", "a".repeat(119)), "fallback"),
            "a".repeat(119)
        );
    }
    #[test]
    fn locator_refresh_keeps_the_reviewed_metadata_and_name() {
        let mut original: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        original.metadata.release.title = Some("Reviewed title".into());
        let mut later = original.clone();
        later.metadata.release.title = Some("Later edit".into());
        later.final_relative_path = "later/name".into();
        let refreshed = original.refresh(&later).unwrap();
        assert_eq!(refreshed.release_title(), "Reviewed title");
        assert_eq!(refreshed.final_relative_path, original.final_relative_path);
    }
}
