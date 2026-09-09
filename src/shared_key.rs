//! Shared Key: what a Blob request carries to prove who sent it.
//!
//! The string to sign Azure documents for version 2009-09-19 and later:
//! the verb, eleven standard headers in a fixed order, every `x-ms-` header
//! canonicalized, and the resource with its query parameters one per line.
//! The signature is HMAC-SHA256 under the account key, base64 both ways.
//! Both sides are here — a Location signs, [`crate::Session`] verifies —
//! because verifying is the same computation with a comparison at the end.
//!
//! **The body is not signed.** Shared Key covers `Content-Length` and, when
//! the sender chooses to send it, `Content-MD5`; the bytes themselves are
//! covered only through that digest. This is Azure's scheme, not a
//! shortcut here — S3's Signature Version 4 hashes the payload and this
//! does not — and it is why a request that reaches the service over
//! plaintext HTTP can have its content altered by anything in the path.
//! The `tls` feature is the answer to that, not a stronger signature.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use transport::error::{Result, protocol_error};

use crate::wire::Request;

/// The service version every request names.
pub const VERSION: &str = "2021-08-06";

/// The standard headers in the order the string to sign lists them.
const STANDARD_HEADERS: [&str; 11] = [
    "content-encoding",
    "content-language",
    "content-length",
    "content-md5",
    "content-type",
    "date",
    "if-modified-since",
    "if-match",
    "if-none-match",
    "if-unmodified-since",
    "range",
];

/// The account and key a signature is made under.
#[derive(Clone, Debug)]
pub struct Signer {
    account: String,
    key: Vec<u8>,
}

impl Signer {
    /// Sign as `account` with its key, as the portal shows it: base64.
    ///
    /// # Errors
    /// Where `key_base64` is not base64.
    pub fn new(account: &str, key_base64: &str) -> Result<Self> {
        let key = STANDARD
            .decode(key_base64.trim())
            .map_err(|e| protocol_error(format!("an account key that is not base64: {e}")))?;
        Ok(Self {
            account: account.to_string(),
            key,
        })
    }

    /// Sign `request` as of `at`, an RFC 1123 moment such as [`now`] gives,
    /// adding `x-ms-date`, `x-ms-version` and `Authorization`.
    #[must_use]
    pub fn sign(&self, request: Request, at: &str) -> Request {
        let request = request
            .header("x-ms-date", at)
            .header("x-ms-version", VERSION);
        let signature = self.signature(&string_to_sign(&self.account, &request));
        request.header(
            "Authorization",
            &format!("SharedKey {}:{signature}", self.account),
        )
    }

    /// Whether `request` carries the signature this signer would have made.
    ///
    /// # Errors
    /// Where the request has no `Authorization`, or one that differs.
    pub fn verify(&self, request: &Request) -> Result<()> {
        let authorization = request
            .header_value("authorization")
            .ok_or_else(|| protocol_error("a request with no Authorization"))?;
        let expected = format!(
            "SharedKey {}:{}",
            self.account,
            self.signature(&string_to_sign(&self.account, request))
        );
        if same(&expected, authorization) {
            Ok(())
        } else {
            Err(protocol_error("a signature that does not match"))
        }
    }

    fn signature(&self, to_sign: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes a key of any length");
        mac.update(to_sign.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    }
}

/// The string to sign: the verb, the standard headers, the canonicalized
/// `x-ms-` headers and the canonicalized resource, newline-separated.
///
/// `Content-Length` is the body's length and empty where the body is empty,
/// as versions from 2015-02-21 have it.
#[must_use]
pub fn string_to_sign(account: &str, request: &Request) -> String {
    let mut lines = vec![request.method.clone()];
    for name in STANDARD_HEADERS {
        lines.push(if name == "content-length" {
            if request.body.is_empty() {
                String::new()
            } else {
                request.body.len().to_string()
            }
        } else {
            request.header_value(name).unwrap_or("").to_string()
        });
    }
    let mut canonical: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .filter(|(name, _)| name.starts_with("x-ms-"))
        .collect();
    canonical.sort();
    for (name, value) in canonical {
        lines.push(format!("{name}:{value}"));
    }
    let mut query: Vec<(String, &str)> = request
        .query
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
        .collect();
    query.sort();
    let mut resource = format!("/{account}{}", request.path);
    for (name, value) in query {
        write!(resource, "\n{name}:{value}").expect("writing to a String cannot fail");
    }
    lines.push(resource);
    lines.join("\n")
}

/// The moment now, as `x-ms-date` writes it: `Tue, 08 Sep 2026 12:00:00 GMT`.
#[must_use]
pub fn now() -> String {
    rfc1123(SystemTime::now())
}

/// `at` as RFC 1123 writes it, which is how `x-ms-date` writes it.
#[must_use]
pub fn rfc1123(at: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = at
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let (year, month, day) = civil(days);
    let rest = secs.rem_euclid(86_400);
    let weekday = usize::try_from((days + 4).rem_euclid(7)).unwrap_or(0);
    let month_name = usize::try_from(month - 1).map_or("Jan", |m| MONTHS[m % 12]);
    format!(
        "{}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Year, month and day of a day count since 1970-01-01 — Howard Hinnant's
/// civil-from-days.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Equal, without the comparison's timing saying how far the two agreed.
fn same(expected: &str, given: &str) -> bool {
    expected.len() == given.len()
        && expected
            .bytes()
            .zip(given.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const KEY: &str = "c2VjcmV0";
    const AT: &str = "Tue, 08 Sep 2026 12:00:00 GMT";

    #[test]
    fn the_string_to_sign_is_laid_out_as_azure_documents_it() {
        let request = Request::new("GET", "/orders")
            .query("restype", "container")
            .query("comp", "list")
            .query("prefix", "in/")
            .header("Host", "blob.local")
            .header("x-ms-version", VERSION)
            .header("x-ms-date", AT);
        assert_eq!(
            string_to_sign("acct", &request),
            format!(
                "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:{AT}\nx-ms-version:{VERSION}\n\
                 /acct/orders\ncomp:list\nprefix:in/\nrestype:container"
            )
        );
        let put = Request::new("PUT", "/orders/in%2F1.edi")
            .header("Content-Type", "application/octet-stream")
            .header("x-ms-blob-type", "BlockBlob")
            .body(b"UNA");
        let to_sign = string_to_sign("acct", &put);
        let lines: Vec<&str> = to_sign.split('\n').collect();
        assert_eq!(lines[3], "3", "content-length is the body's length");
        assert_eq!(lines[5], "application/octet-stream");
        assert_eq!(lines[12], "x-ms-blob-type:BlockBlob");
        assert_eq!(lines[13], "/acct/orders/in%2F1.edi");
    }

    #[test]
    fn a_signature_verifies_and_a_tampered_request_or_another_key_does_not() {
        let signer = Signer::new("acct", KEY).expect("base64");
        let sent = signer.sign(
            Request::new("PUT", "/orders/in/1.edi")
                .header("Host", "blob.local")
                .body(b"UNA"),
            &now(),
        );
        assert!(sent.header_value("x-ms-version").is_some());
        assert!(
            sent.header_value("authorization")
                .expect("signed")
                .starts_with("SharedKey acct:")
        );
        signer.verify(&sent).expect("verifies");
        let mut tampered = sent.clone();
        tampered.body = b"UNB".to_vec();
        signer.verify(&tampered).expect(
            "Shared Key signs Content-Length, not the bytes: a same-length \
             body still verifies, which is the scheme, not a defect here",
        );
        let mut tampered = sent.clone();
        tampered.body = b"UNA and more".to_vec();
        assert!(signer.verify(&tampered).is_err(), "the length is signed");
        let mut tampered = sent.clone();
        tampered.path = "/orders/in/2.edi".to_string();
        assert!(signer.verify(&tampered).is_err());
        let other = Signer::new("acct", "d3Jvbmc=").expect("base64");
        assert!(other.verify(&sent).is_err());
        assert!(signer.verify(&Request::new("GET", "/")).is_err());
        assert!(Signer::new("acct", "not base64!").is_err());
    }

    #[test]
    fn the_date_is_written_as_rfc_1123_writes_it() {
        assert_eq!(rfc1123(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let at = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(at, UNIX_EPOCH + Duration::from_secs(784_111_777));
        assert_eq!(rfc1123(at), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert!(now().ends_with(" GMT"));
    }
}
