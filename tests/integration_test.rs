// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.

use pretty_assertions::assert_eq;

use wasm_dep_analyzer::Export;
use wasm_dep_analyzer::ExportType;
use wasm_dep_analyzer::GlobalType;
use wasm_dep_analyzer::Import;
use wasm_dep_analyzer::ImportType;
use wasm_dep_analyzer::Limits;
use wasm_dep_analyzer::TableType;
use wasm_dep_analyzer::TagType;
use wasm_dep_analyzer::WasmDeps;

#[test]
fn wasm_export_only() {
  // The following Rust code compiled:
  //
  // #[no_mangle]
  // pub fn add(left: usize, right: Usize) -> usize {
  //     left + right
  // }
  let input = std::fs::read("tests/testdata/export_only.wasm").unwrap();
  let module = WasmDeps::parse(&input).unwrap();
  assert_eq!(
    module,
    WasmDeps {
      imports: vec![],
      exports: vec![
        Export {
          name: "memory",
          index: 0,
          export_type: ExportType::Memory,
        },
        Export {
          name: "add",
          index: 0,
          export_type: ExportType::Function,
        },
        Export {
          name: "__data_end",
          index: 1,
          export_type: ExportType::Global,
        },
        Export {
          name: "__heap_base",
          index: 2,
          export_type: ExportType::Global,
        }
      ],
    }
  );
}

#[test]
fn wasm_import_and_export() {
  // The following Rust code compiled:
  //
  // extern "C" {
  //     fn get_random_value() -> usize;
  // }

  // #[no_mangle]
  // pub fn add(left: usize) -> usize {
  //     left + unsafe { get_random_value() }
  // }
  let input = std::fs::read("tests/testdata/import_export.wasm").unwrap();
  let module = WasmDeps::parse(&input).unwrap();
  assert_eq!(
    module,
    WasmDeps {
      imports: vec![Import {
        name: "get_random_value",
        module: "env",
        import_type: ImportType::Function(0),
      }],
      exports: vec![
        Export {
          name: "memory",
          index: 0,
          export_type: ExportType::Memory,
        },
        Export {
          name: "add",
          index: 1,
          export_type: ExportType::Function,
        },
        Export {
          name: "__data_end",
          index: 1,
          export_type: ExportType::Global,
        },
        Export {
          name: "__heap_base",
          index: 2,
          export_type: ExportType::Global,
        }
      ],
    }
  );
}

#[test]
fn wasm_import_module() {
  let input = std::fs::read("tests/testdata/import_module.wasm").unwrap();
  let module = WasmDeps::parse(&input).unwrap();
  assert_eq!(
    module,
    WasmDeps {
      imports: vec![Import {
        name: "add",
        module: "./import_inner.mjs",
        import_type: ImportType::Function(0),
      }],
      exports: vec![Export {
        name: "exported_add",
        index: 1,
        export_type: ExportType::Function,
      }],
    }
  );
}

#[test]
fn wasm_mutable_global() {
  // from wat2wasm "mutable globals" example
  // (module
  // (import "env" "g" (global (mut i32)))
  // (func (export "f")
  //  i32.const 100
  //  global.set 0))
  let input = std::fs::read("tests/testdata/mutable_global.wasm").unwrap();
  let module = WasmDeps::parse(&input).unwrap();
  assert_eq!(
    module,
    WasmDeps {
      imports: vec![Import {
        name: "g",
        module: "env",
        import_type: ImportType::Global(GlobalType {
          value_type: 127,
          mutability: true,
        }),
      }],
      exports: vec![Export {
        name: "f",
        index: 0,
        export_type: ExportType::Function,
      }],
    }
  );
}

#[test]
fn wasm_import_table() {
  // (module
  //   ;; Import a table named "tbl" from a module named "js".
  //   ;; The table is of type "funcref" with initial size 2 and no maximum size.
  //   (import "js" "tbl" (table 2 funcref))
  // )
  let input = std::fs::read("tests/testdata/import_table.wasm").unwrap();
  let module = WasmDeps::parse(&input).unwrap();
  assert_eq!(
    module,
    WasmDeps {
      imports: vec![Import {
        name: "table",
        module: "env",
        import_type: ImportType::Table(TableType {
          element_type: 112,
          limits: Limits {
            initial: 2,
            maximum: None,
          },
        }),
      }],
      exports: vec![],
    }
  );
}

#[test]
fn wasm_import_tag() {
  // (module
  //   ;; Import an exception tag
  //   (import "env" "exception_tag" (tag (type 0)))

  //   ;; Define an exception type (a list of value types that the exception can carry)
  //   (type (func (param i32)))

  //   ;; Define a tag that uses the above exception type
  //   (tag (type 0))

  //   ;; Export the defined tag
  //   (export "exported_tag" (tag 0))
  // )
  let input = std::fs::read("tests/testdata/import_tag.wasm").unwrap();
  let module = WasmDeps::parse(&input).unwrap();
  assert_eq!(
    module,
    WasmDeps {
      imports: vec![Import {
        name: "exception_tag",
        module: "env",
        import_type: ImportType::Tag(TagType {
          kind: 0,
          type_index: 0,
        }),
      }],
      exports: vec![Export {
        name: "exported_tag",
        index: 0,
        export_type: ExportType::Tag,
      }],
    }
  );
}

#[test]
fn wasm_export_memory() {
  // (module
  //   ;; Define a memory with an initial size of 1 page (64KiB)
  //   ;; and a maximum size of 10 pages (640KiB).
  //   (memory (export "mem") 1 10)
  // )
  let input = std::fs::read("tests/testdata/export_memory.wasm").unwrap();
  let module = WasmDeps::parse(&input).unwrap();
  assert_eq!(
    module,
    WasmDeps {
      imports: vec![],
      exports: vec![Export {
        name: "mem",
        index: 0,
        export_type: ExportType::Memory,
      }],
    }
  );
}