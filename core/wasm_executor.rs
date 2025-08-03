use wasmtime::*;
use anyhow::Result;

pub struct WasmExecutor {
    engine: Engine,
    linker: Linker<()>,
}

impl WasmExecutor {
    pub fn new() -> Self {
        let engine = Engine::default();
        let mut linker = Linker::new(&engine);
        Self { engine, linker }
    }

    pub fn execute(&self, wasm_bytes: &[u8], input: &str) -> Result<String> {
        let module = Module::new(&self.engine, wasm_bytes)?;
        let mut store = Store::new(&self.engine, ());
        let instance = self.linker.instantiate(&mut store, &module)?;

        let func = instance.get_func(&mut store, "run")
            .ok_or(anyhow::anyhow!("Missing 'run' function"))?;

        let run = func.typed::<i32, i32, _>(&store)?;
        let result = run.call(&mut store, input.len() as i32)?;
        Ok(format!("WASM returned code: {}", result))
    }
}
---

file: core/tools.rs
---
mod wasm_executor;
use wasm_executor::WasmExecutor;
use std::sync::Arc;

pub struct WasmTool {
    wasm_bytes: Arc<Vec<u8>>,
    executor: WasmExecutor,
}

#[async_trait]
impl Tool for WasmTool {
    async fn name(&self) -> String {
        "wasm_tool".into()
    }

    async fn call(&self, input: &str) -> String {
        match self.executor.execute(&self.wasm_bytes, input) {
            Ok(result) => result,
            Err(e) => format!("WASM error: {}", e),
        }
    }
}
---

file: lib.rs
---
pub mod wasm_executor;
---
