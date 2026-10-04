# xmip-core-transport-azure-blob

Azure Blob transport: Shared Key over the Blob REST API — list a prefix, get each blob and delete it once the runtime accepts it, put a Stream as a block blob — a container prefix is a Location. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

Shared Key comes from [xmip-core-transport-azure](https://github.com/IlleNilsson/xmip-core-transport-azure), where every Azure technology shares what Azure speaks over HTTP (ADR-0044, amendment 2026-09-24); HTTP itself comes from [xmip-core-transport-http](https://github.com/IlleNilsson/xmip-core-transport-http).

Requests go on connections kept between them (`http::endpoint::Connections`, offering HTTP/1.1): the transport holds them and hands them to every client it makes, so a call costs one exchange and not a connect, a TLS handshake and a `Connection: close`, as it did until 2026-09-27.

## How a received blob is acknowledged

A receive deletes nothing and gets nothing: it lists the prefix, and each blob's `GET` is made when the runtime first reads its body (`transport::listed::listed`, the capability's one object-store receive, over `transport::body::fetched`), whole (`net::http` reads a response body whole), so a receive that lists a hundred blobs holds none of them in memory. Every blob stays in the container until the runtime gives its verdict after the whole receive cycle (runtime-model section 5). Accepted deletes the blob. Refused leaves it where it lies — a refusal is not a consumption, and a Stream refused at a transport gate was never written to the Ledger, so the blob is the only copy — and this Location does not receive it again while its `Etag` is unchanged (`transport::Refused`, which the listing is sifted through: the client lists each blob with the `Etag` in its `Properties`, read by the capability's one listing scan, `transport::listed::Listing`); one written again under its name has another `Etag` and is a new arrival. The memory is the node process's: a node started again receives a refused blob once more, refuses it once more, and remembers it from then on. Failed leaves it, and the next receive lists and gets it again. Until 2026-10-02 a receive got every blob it listed before handing any on. No lease is taken, so none is released. A crash before the verdict leaves the blob too: at-least-once, never a loss. The delete is the one the receive made until 2026-10-02, so a verdict adds no request.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
