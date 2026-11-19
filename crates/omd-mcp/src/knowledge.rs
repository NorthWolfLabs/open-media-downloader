//! Version-matched, embedded reference material; no ambient filesystem reads.
use super::*;
pub struct Entry {
    pub uri: &'static str,
    pub name: &'static str,
    pub mime: &'static str,
    pub text: &'static str,
}
pub const ENTRIES: &[Entry] = &[
    Entry {
        uri: "omd://guide/workflows",
        name: "OMD agent workflows",
        mime: "text/markdown",
        text: include_str!("../../../docs/mcp/workflows.md"),
    },
    Entry {
        uri: "omd://guide/plugin-authoring",
        name: "Author a source plugin",
        mime: "text/markdown",
        text: include_str!("../../../docs/mcp/plugin-authoring.md"),
    },
    Entry {
        uri: "omd://reference/provider-sdk",
        name: "Matching provider SDK README",
        mime: "text/markdown",
        text: include_str!("../../../sdk/provider/README.md"),
    },
    Entry {
        uri: "omd://reference/provider-contracts",
        name: "Exact provider TypeScript contracts",
        mime: "text/plain",
        text: include_str!("../../../sdk/provider/src/contracts.ts"),
    },
    Entry {
        uri: "omd://reference/provider-wit",
        name: "Exact component WIT contract",
        mime: "text/plain",
        text: include_str!("../../../sdk/provider/wit/provider.wit"),
    },
    Entry {
        uri: "omd://reference/openapi",
        name: "Engine public HTTP contract",
        mime: "application/json",
        text: include_str!("../../../schemas/v2/openapi.json"),
    },
    Entry {
        uri: "omd://reference/mcp-coverage",
        name: "Engine to MCP operation coverage",
        mime: "application/json",
        text: include_str!("coverage.json"),
    },
];
pub fn no_cursor(request: Option<PaginatedRequestParams>) -> Result<(), ErrorData> {
    if request.and_then(|r| r.cursor).is_some() {
        return Err(ErrorData::invalid_params(
            "Catalog has no continuation cursor",
            None,
        ));
    }
    Ok(())
}
pub fn resources() -> ListResourcesResult {
    ListResourcesResult {
        resources: ENTRIES
            .iter()
            .map(|e| {
                Resource::new(e.uri, e.name)
                    .with_mime_type(e.mime)
                    .with_size(e.text.len() as u64)
            })
            .collect(),
        ..Default::default()
    }
}
pub fn read(uri: &str) -> Result<ReadResourceResponse, ErrorData> {
    let entry = ENTRIES
        .iter()
        .find(|e| e.uri == uri)
        .ok_or_else(|| ErrorData::invalid_params("Unknown OMD reference URI", None))?;
    let content = ResourceContents::TextResourceContents {
        uri: entry.uri.into(),
        mime_type: Some(entry.mime.into()),
        text: entry.text.into(),
        meta: None,
    };
    Ok(ReadResourceResult::new(vec![content]).into())
}
pub fn prompts() -> ListPromptsResult {
    ListPromptsResult {
        prompts: [
            (
                "use_omd",
                "Browse, search, download and subscribe consistently",
            ),
            ("install_plugin", "Review and install a source package"),
            (
                "author_plugin",
                "Build and validate a matching source plugin",
            ),
        ]
        .into_iter()
        .map(|(name, description)| Prompt::new(name, Some(description), None))
        .collect(),
        ..Default::default()
    }
}
pub fn prompt(request: GetPromptRequestParams) -> Result<GetPromptResponse, ErrorData> {
    if request.arguments.as_ref().is_some_and(|a| !a.is_empty()) {
        return Err(ErrorData::invalid_params(
            "This workflow prompt takes no arguments",
            None,
        ));
    }
    let index = match request.name.as_str() {
        "use_omd" | "install_plugin" => 0,
        "author_plugin" => 1,
        _ => {
            return Err(ErrorData::invalid_params(
                "Unknown OMD workflow prompt",
                None,
            ));
        }
    };
    Ok(GetPromptResult::new(vec![PromptMessage::new_text(
        Role::User,
        ENTRIES[index].text,
    )])
    .into())
}
