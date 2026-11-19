fn main() {
    // sqlx::migrate! embeds files at compile time. Stable Rust does not track new
    // directory entries from that proc macro, so explicitly invalidate the crate
    // when a migration is added as well as when an existing migration changes.
    println!("cargo:rerun-if-changed=migrations");
}
