use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};
#[path = "../../../tests/support/worker.rs"]
mod worker;

fn frame(out: &mut impl Write, value: Value) {
    let bytes = serde_json::to_vec(&value).unwrap();
    out.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&bytes).unwrap();
    out.flush().unwrap();
}
fn read(input: &mut impl Read) -> Value {
    let mut size = [0; 4];
    input.read_exact(&mut size).unwrap();
    let size = u32::from_le_bytes(size) as usize;
    assert!(size <= 16 * 1024 * 1024);
    let mut data = vec![0; size];
    input.read_exact(&mut data).unwrap();
    serde_json::from_slice(&data).unwrap()
}
fn invoke(query: &str, inspect: bool) -> (Value, usize) {
    invoke_cached(query, inspect, None)
}
fn invoke_cached(query: &str, inspect: bool, cache: Option<&std::path::Path>) -> (Value, usize) {
    let component = std::env::var_os("OMD_TEST_COMPONENT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/v2-provider/.omd-build/plugin.wasm")
        });
    assert!(
        component.exists(),
        "Build the conformance component with the SDK before running worker acceptance tests"
    );
    let mut child = Command::new(worker::executable())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    frame(
        &mut input,
        json!({"component":component,"cache_config":cache,"inspect":inspect,"payload":json!({"operation":"search","query":query,"page_size":100}).to_string()}),
    );
    let mut calls = 0;
    let result = loop {
        let message = read(&mut output);
        if let Some(request) = message.get("broker") {
            calls += 1;
            assert_eq!(request["operation"], "http");
            let payload: Value =
                serde_json::from_str(request["payload"].as_str().unwrap()).unwrap();
            assert_eq!(payload["url"], "https://example.com/catalog");
            frame(
                &mut input,
                json!({"result":json!({"status":200,"body":"<article data-id='chapter-special'><h2>A &amp; B</h2><a href='/series/1'>Details</a></article>"}).to_string()}),
            );
        } else {
            break message;
        }
    };
    assert!(child.wait().unwrap().success());
    (result, calls)
}
#[test]
fn component_has_no_ambient_wasi_imports() {
    let (result, calls) = invoke("", true);
    assert_eq!(
        result["result"]["imports"],
        json!(["omd:provider/broker@2.0.0"])
    );
    assert_eq!(calls, 0);
}
#[test]
fn typescript_brokers_http_and_parses_html() {
    let (result, calls) = invoke("normal", false);
    assert_eq!(calls, 1);
    assert_eq!(result["result"]["ok"], true, "{result}");
    assert_eq!(result["result"]["result"]["items"][0]["title"], "A & B");
}
#[test]
fn author_errors_survive_component_boundary() {
    let (result, _) = invoke("trap", false);
    assert_eq!(result["result"]["ok"], false, "{result}");
    assert_eq!(result["result"]["error"]["code"], "source_error");
}
#[test]
fn unbounded_author_loop_is_interrupted() {
    let directory = tempfile::tempdir().unwrap();
    let cache = worker::cache_config(directory.path());
    let (inspection, calls) = invoke_cached("", true, Some(&cache));
    assert!(inspection.get("result").is_some());
    assert_eq!(calls, 0);
    let start = std::time::Instant::now();
    let (result, _) = invoke_cached("loop", false, Some(&cache));
    assert!(result.get("error").is_some(), "{result}");
    assert!(start.elapsed().as_secs() < 45);
}

#[test]
fn a_reused_worker_starts_each_invocation_with_fresh_guest_state() {
    let component = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/v2-provider/.omd-build/plugin.wasm");
    let cache = tempfile::tempdir().unwrap();
    let config = worker::cache_config(cache.path());
    let mut child = Command::new(worker::executable())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    for _ in 0..3 {
        frame(
            &mut input,
            json!({"component":component,"cache_config":config,"reuse":true,"payload":json!({"operation":"search","query":"state","page_size":100}).to_string()}),
        );
        let result = read(&mut output);
        assert_eq!(
            result["result"]["result"]["items"][0]["title"], "1",
            "{result}"
        );
        assert!(child.try_wait().unwrap().is_none());
    }
    drop(input);
    assert!(child.wait().unwrap().success());
}
