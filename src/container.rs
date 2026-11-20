//! The container a Receive Location takes blobs from, as the capability's
//! one object-store receive and claim reach it (`transport::listed`):
//! listed under the Location's prefix, each blob got and deleted as it was
//! listed (`If-Match`), and its claim, `<name>.xmip-claim`, put only where
//! none lies (Put Blob with `If-None-Match: *`, ADR-0024, amendment
//! 2026-11-20). Not a blob lease: a lease locks the blob against its
//! producer's own writes and deletes while it is held.

use std::sync::Arc;

use transport::claim::{Artifact, Claimed, ResourceClaim};
use transport::error::Result;
use transport::listed::{AsListed, Object, Store};

use crate::{AzureBlobTransport, Client, origin};

/// One container under one prefix, spoken to through one client.
pub struct Container {
    client: Client,
    /// The container's own name.
    named: String,
    prefix: String,
}

impl Store for Container {
    fn list(&self) -> Result<Vec<Object>> {
        self.client.list(&self.named, &self.prefix)
    }

    fn get(&self, blob: &str, etag: &str) -> Result<AsListed<Vec<u8>>> {
        self.client.get_as_listed(&self.named, blob, etag)
    }

    fn delete(&self, blob: &str, etag: &str) -> Result<AsListed<()>> {
        self.client.delete_as_listed(&self.named, blob, etag)
    }

    fn create(&self, blob: &str, bytes: &[u8]) -> Result<Option<String>> {
        self.client.put_new(&self.named, blob, bytes)
    }

    fn origin(&self, blob: &str) -> String {
        origin(&self.named, blob)
    }
}

impl AzureBlobTransport {
    /// The container this transport receives from, through a client of
    /// its own.
    ///
    /// # Errors
    /// Where the endpoint is not an HTTP URL, or the key is not base64.
    pub fn container(&self) -> Result<Arc<dyn Store>> {
        Ok(Arc::new(Container {
            client: self.client()?,
            named: self.container.clone(),
            prefix: self.prefix.clone(),
        }))
    }
}

/// One blob claimed by its address, `azure-blob://container/blob`, as a
/// receive claims it.
impl ResourceClaim for AzureBlobTransport {
    fn is_available(&self, artifact: &Artifact) -> Result<bool> {
        self.claims.is_available(&*self.container()?, artifact)
    }

    fn claim(&self, artifact: &Artifact) -> Result<Claimed> {
        self.claims.claim(&*self.container()?, artifact)
    }

    fn release(&self, claimed: Claimed) -> Result<()> {
        self.claims.release(&*self.container()?, &claimed)
    }
}
