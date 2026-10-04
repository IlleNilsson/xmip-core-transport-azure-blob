//! The little XML the Blob service speaks: a listing naming blobs with their
//! `Etag`s, an error naming a code.
//!
//! Written by hand, both documents flat; read back by the
//! estate's flat scan (`codec::xml`), which is a scan, not a tree, because the one
//! question either side asks is the text of an element by its name.

use codec::xml::escape;
use transport::listed::Listing;

/// How an `EnumerationResults` names a blob: each `<Blob>`'s name with the
/// `Etag` in its `<Properties>`, the stamp that changes whenever it is
/// written again; read by the capability's one listing scan.
pub const BLOBS: Listing = Listing {
    entry: "Blob",
    name: "Name",
    stamp: "Etag",
};

/// An `EnumerationResults` naming `blobs` — each a name with its `Etag` —
/// under `prefix` in `container`.
#[must_use]
pub fn listing(container: &str, prefix: &str, blobs: &[(String, String)]) -> String {
    let entries: Vec<String> = blobs
        .iter()
        .map(|(blob, tag)| {
            format!(
                "<Blob><Name>{}</Name><Properties><Etag>{}</Etag></Properties></Blob>",
                escape(blob),
                escape(tag)
            )
        })
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
    use codec::xml::{text, texts};

    #[test]
    fn a_listing_names_its_blobs_and_etags_back_with_entities_intact() {
        let held = vec![
            ("in/a&b.edi".to_string(), "0x1".to_string()),
            ("in/<c>.edi".to_string(), "0x2".to_string()),
        ];
        let xml = listing("orders", "in/", &held);
        assert!(xml.contains("<Name>in/a&amp;b.edi</Name><Properties><Etag>0x1</Etag>"));
        assert_eq!(BLOBS.objects(&xml).expect("read"), held);
        assert_eq!(text(&xml, "Prefix").expect("read").as_deref(), Some("in/"));
        assert!(texts(&xml, "Absent").expect("read").is_empty());
        assert!(
            BLOBS
                .objects("<Blob><Name>unclosed")
                .expect("read")
                .is_empty()
        );
        let untagged = BLOBS
            .objects("<Blob><Name>b</Name><Properties /></Blob>")
            .expect_err("no Etag");
        assert!(untagged.message.contains("Etag"), "{untagged}");
    }

    #[test]
    fn an_error_names_its_code() {
        let xml = error("AuthenticationFailed", "Server failed to authenticate");
        assert_eq!(
            text(&xml, "Code").expect("read").as_deref(),
            Some("AuthenticationFailed")
        );
        assert_eq!(text(&xml, "Absent").expect("read"), None);
    }
}
