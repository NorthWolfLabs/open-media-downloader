fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&omd_service::contract::document())
            .expect("OpenAPI serializes")
    );
}
