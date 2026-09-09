//! The little XML the Blob service speaks: a listing naming blobs, an error
//! naming a code.
//!
//! Picked by hand rather than parsed. Both documents are flat, the service
//! writes them and only the service reads what [`crate::Session`] writes,
//! and the one question either side asks — the text of every element by
//! one name — is a scan, not a tree.

/// The text of every `<name>` element, entities unescaped.
#[must_use]
pub fn texts(xml: &str, name: &str) -> Vec<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        found.push(unescape(&after[..end]));
        rest = &after[end + close.len()..];
    }
    found
}

/// The text of the first `<name>` element.
#[must_use]
pub fn first(xml: &str, name: &str) -> Option<String> {
    texts(xml, name).into_iter().next()
}

/// An `EnumerationResults` naming `blobs` under `prefix` in `container`.
#[must_use]
pub fn listing(container: &str, prefix: &str, blobs: &[String]) -> String {
    let entries: Vec<String> = blobs
        .iter()
        .map(|blob| format!("<Blob><Name>{}</Name><Properties /></Blob>", escape(blob)))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <EnumerationResults ContainerName=\"{}\"><Prefix>{}</Prefix>\
         <Blobs>{}</Blobs><NextMarker /></EnumerationResults>",
        escape(container),
        escape(prefix),
        entries.concat()
    )
}

/// An `Error` naming `code`.
#[must_use]
pub fn error(code: &str, message: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <Error><Code>{}</Code><Message>{}</Message></Error>",
        escape(code),
        escape(message)
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_names_its_blobs_back_with_entities_intact() {
        let blobs = vec!["in/a&b.edi".to_string(), "in/<c>.edi".to_string()];
        let xml = listing("orders", "in/", &blobs);
        assert!(xml.contains("<Name>in/a&amp;b.edi</Name>"));
        assert_eq!(texts(&xml, "Name"), blobs);
        assert_eq!(first(&xml, "Prefix").as_deref(), Some("in/"));
        assert!(texts(&xml, "Absent").is_empty());
        assert!(texts("<Name>unclosed", "Name").is_empty());
    }

    #[test]
    fn an_error_names_its_code() {
        let xml = error("AuthenticationFailed", "Server failed to authenticate");
        assert_eq!(first(&xml, "Code").as_deref(), Some("AuthenticationFailed"));
        assert_eq!(first(&xml, "Absent"), None);
    }
}
