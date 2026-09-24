# xmip-core-transport-azure-blob

Azure Blob transport: Shared Key over the Blob REST API — list a prefix, get and delete each blob, put a Stream as a block blob — a container prefix is a Location. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

Shared Key comes from [xmip-core-transport-azure](https://github.com/IlleNilsson/xmip-core-transport-azure), where every Azure technology shares what Azure speaks over HTTP (ADR-0044, amendment 2026-09-24); HTTP itself comes from [xmip-core-transport-http](https://github.com/IlleNilsson/xmip-core-transport-http).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
