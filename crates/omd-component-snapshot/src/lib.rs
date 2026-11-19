//! Build-time transformation only. Freeze nondeterministic WASI imports before
//! Wizer snapshots the JavaScript runtime. This is not a plugin execution host.
pub fn deterministic_initialization(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut module = walrus::Module::from_buffer(bytes)?;
    let memory = module.get_memory_id()?;
    let imports: Vec<_> = module
        .imports
        .iter()
        .filter_map(|import| {
            if import.module != "wasi_snapshot_preview1" {
                return None;
            }
            let walrus::ImportKind::Function(function) = import.kind else {
                return None;
            };
            matches!(
                import.name.as_str(),
                "clock_time_get" | "clock_res_get" | "random_get"
            )
            .then(|| (function, import.name.clone()))
        })
        .collect();
    anyhow::ensure!(
        imports.len() == 3,
        "The pinned component engine's initialization imports changed; review the toolchain before building"
    );
    for (function, name) in imports {
        let ty = module.types.get(module.funcs.get(function).ty());
        use walrus::ValType::{I32, I64};
        let expected: &[walrus::ValType] = if name == "clock_time_get" {
            &[I32, I64, I32]
        } else {
            &[I32, I32]
        };
        anyhow::ensure!(
            ty.params() == expected && ty.results() == [I32],
            "Unexpected initialization ABI"
        );
        module.replace_imported_func(function, |(body, args)| {
            if name == "random_get" {
                body.local_get(args[0])
                    .i32_const(0)
                    .local_get(args[1])
                    .memory_fill(memory);
            } else {
                let out = if name == "clock_time_get" { 2 } else { 1 };
                body.local_get(args[out])
                    .i64_const(if name == "clock_res_get" { 1 } else { 0 })
                    .store(
                        memory,
                        walrus::ir::StoreKind::I64 { atomic: false },
                        walrus::ir::MemArg {
                            align: 8,
                            offset: 0,
                        },
                    );
            }
            body.i32_const(0);
        })?;
    }
    Ok(module.emit_wasm())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removes_only_snapshot_entropy_and_rejects_changed_toolchain_abi() {
        let input = wat::parse_str(r#"(module
            (import "wasi_snapshot_preview1" "random_get" (func (param i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "clock_time_get" (func (param i32 i64 i32) (result i32)))
            (import "wasi_snapshot_preview1" "clock_res_get" (func (param i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_read" (func (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1))"#).unwrap();
        let output = deterministic_initialization(&input).unwrap();
        assert_eq!(output, deterministic_initialization(&input).unwrap());
        let module = walrus::Module::from_buffer(&output).unwrap();
        let names: Vec<_> = module.imports.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["fd_read"]);
        assert!(deterministic_initialization(&output).is_err());
    }
}
