# OMD provider SDK source kit

This kit contains provider SDK 0.11.1 source, the pinned snapshot-transformer input
and its Rust source/build lock. It contains no engine service, desktop UI or production
source plugin. The JavaScript/runtime dependencies retain their own licenses.

Read sdk/provider/README.md and sdk/provider/build-tool/README.md. Plugin authors
install/use the matching SDK package and don't need Rust. Maintainers can rebuild
the transformer from this narrow workspace after installing the wasm32-wasip1 Rust
target, then verify its digest against the pinned toolchain before changing an SDK.
Passing a source build does not authorize replacing a reviewed binary identity.
