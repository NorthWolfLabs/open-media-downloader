fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&schemars::schema_for!(omd_domain::Contracts))
            .expect("schema serializes")
    );
}
