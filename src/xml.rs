//! The little XML the Blob service speaks: a listing naming blobs, an error
//! naming a code.
//!
//! Written by hand, both documents flat; read back by the capability's
//! flat scan (ADR-0044), which is a scan, not a tree, because the one
//! question either side asks is the text of every element by one name.

use transport::xml::escape;
pub use transport::xml::{first, texts};

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
