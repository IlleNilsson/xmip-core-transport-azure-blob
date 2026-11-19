# xmip-core-transport-azure-blob

Azure Blob transport: Shared Key over the Blob REST API — list a prefix, get each blob and delete it once the runtime accepts it, put a Stream as a block blob — a container prefix is a Location. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

Shared Key comes from [xmip-core-transport-azure](https://github.com/IlleNilsson/xmip-core-transport-azure), where every Azure technology shares what Azure speaks over HTTP (ADR-0044, amendment 2026-09-24); HTTP itself comes from [xmip-core-transport-http](https://github.com/IlleNilsson/xmip-core-transport-http).

Requests go on connections kept between them (`http::endpoint::Connections`, offering HTTP/1.1): the transport holds them and hands them to every client it makes, so a call costs one exchange and not a connect, a TLS handshake and a `Connection: close`, as it did until 2026-09-27.

## How a received blob is acknowledged

A receive deletes nothing and gets nothing: it lists the prefix, and each blob's `GET` is made when the runtime first reads its body (`transport::listed::listed`, the capability's one object-store receive, over `transport::body::fetched`), whole (`net::http` reads a response body whole), so a receive that lists a hundred blobs holds none of them in memory. Every blob stays in the container until the runtime gives its verdict after the whole receive cycle (runtime-model section 5). Accepted deletes the blob. Refused leaves it where it lies — a refusal is not a consumption, and a Stream refused at a transport gate was never written to the Ledger, so the blob is the only copy — and this Location does not receive it again while its `Etag` is unchanged (`transport::Refused`, which the listing is sifted through: the client lists each blob with the `Etag` in its `Properties`, read by the capability's one listing scan, `transport::listed::Listing`); one written again under its name has another `Etag` and is a new arrival. The memory is the node process's: a node started again receives a refused blob once more, refuses it once more, and remembers it from then on. Failed leaves it, and the next receive lists and gets it again. Until 2026-10-02 a receive got every blob it listed before handing any on. No lease is taken, so none is released. A crash before the verdict leaves the blob too: at-least-once, never a loss. The delete is the one the receive made until 2026-10-02, so a verdict adds no request.

The get and the delete hold to the blob as it was listed (ADR-0024, amendment 2026-11-19): each carries `If-Match` with the `Etag` the listing gave, quoted. A blob written again between the listing and the first read answers the get 412 `ConditionNotMet`, or 404 `BlobNotFound` where it was deleted, and is not read under the old `Etag`: the read fails, the cycle fails, nothing is deleted, and the next listing takes it as a new arrival. A blob written again between the read and the acceptance answers the delete the same way and stays for the next listing, and the acceptance is told done. Any other 412 or 404, a lease's or a container's, is the failure it is. The condition rides on the calls the receive made already, so it adds no request. Until 2026-11-19 both were unconditional, and a replacement written between the read and the acceptance was deleted unread.

An archive writes with `Client::put_new`: Put Blob with `If-None-Match: *`, which never writes over a blob already there. The conditional-header tables answer it 412 where one is there, the service 409 `BlobAlreadyExists`; both say "there", and the blob is left as it was. A send still puts over what lies at its target. Microsoft's sources: [conditional headers](https://learn.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations), [Get Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob), [Delete Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/delete-blob), [Put Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob), [error codes](https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-error-codes). Shared Key signs `If-Match` and `If-None-Match` among its standard headers. The session, the far end a test binds, holds every request to the condition it carries as the service does.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
