// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.

use std::collections::HashMap;
use std::str::Utf8Error;

use thiserror::Error;

#[derive(Debug, PartialEq, Eq)]
pub struct WasmBytes<'a> {
  pub imports: Vec<Import<'a>>,
  pub exports: Vec<Export<'a>>,
}

impl<'a> WasmBytes<'a> {
  /// Parses a Wasm module's bytes discovering the imports, exports, and types.
  ///
  /// The parser will try to parse even when it doesn't understand something
  /// and will only parse out the information necessary for dependency analysis.
  pub fn parse(input: &'a [u8]) -> Result<Self, ParseError> {
    let (input, _) = parse_magic_bytes(input)?;
    let (mut input, _) = ensure_known_version(input)?;
    let mut imports = None;
    let mut exports = None;
    let mut types_section = None;
    let mut functions_section = None;
    let mut globals_section = None;
    let mut search_for_types = true;
    let mut search_for_fns = true;
    let mut search_for_globals = true;
    while !input.is_empty()
      && (imports.is_none()
        || exports.is_none()
        || search_for_types
        || search_for_fns
        || search_for_globals)
    {
      let (rest, section) = parse_section(input)?;
      input = rest;
      match section.kind {
        0x02 if imports.is_none() => {
          imports = Some(parse_import_section(section.bytes)?);
        }
        0x07 if exports.is_none() => {
          let result = parse_export_section(section.bytes)?;
          if !result
            .iter()
            .any(|e| matches!(e.export_type, ExportType::Function(_)))
          {
            search_for_types = false;
            search_for_fns = false;
            // clear these out if there are no function exports
            types_section = None;
            functions_section = None;
          }
          if !result
            .iter()
            .any(|e| matches!(e.export_type, ExportType::Global(_)))
          {
            search_for_globals = false;
            globals_section = None;
          }
          exports = Some(result);
        }
        0x01 if search_for_types => {
          types_section = Some(section.bytes);
          search_for_types = false;
        }
        0x03 if search_for_fns => {
          functions_section = Some(section.bytes);
          search_for_fns = false;
        }
        0x06 if search_for_globals => {
          globals_section = Some(section.bytes);
          search_for_globals = false;
        }
        _ => {}
      }
    }
    if let Some(exports) = &mut exports {
      if types_section.is_some()
        || functions_section.is_some()
        || globals_section.is_some()
      {
        let mut parsed_types = None;
        let mut parsed_functions = None;
        let mut parsed_globals = None;
        let mut function_indexes = None;
        for export in exports {
          if let ExportType::Function(sig) = &mut export.export_type {
            let parsed_types = parsed_types.get_or_insert_with(|| {
              parse_type_section(types_section.unwrap_or_default())
            });
            let parsed_functions = parsed_functions.get_or_insert_with(|| {
              parse_function_section(functions_section.unwrap_or_default())
            });
            let func_export_idx_to_type_idx = function_indexes
              .get_or_insert_with(|| {
                let parsed_functions = match parsed_functions.as_ref() {
                  Ok(f) => f,
                  Err(err) => return Err(err.clone()),
                };
                // the function index space is created by iterating the
                // function imports and then the function section
                let mut space = HashMap::with_capacity(
                  imports.as_ref().map(|i| i.len()).unwrap_or(0)
                    + parsed_functions.len(),
                );
                let mut i = 0;
                if let Some(imports) = &imports {
                  for import in imports {
                    if let ImportType::Function(final_index) =
                      &import.import_type
                    {
                      space.insert(i, *final_index);
                      i += 1;
                    }
                  }
                }
                for index in parsed_functions.iter() {
                  space.insert(i, *index);
                  i += 1;
                }
                Ok(space)
              });
            match &func_export_idx_to_type_idx {
              Ok(func_export_idx_to_type_idx) => match &parsed_types {
                Ok(types) => {
                  if let Some(types_index) =
                    func_export_idx_to_type_idx.get(&export.index)
                  {
                    let types_index = *types_index as usize;
                    if types_index < types.len() {
                      *sig = Ok(types[types_index].clone());
                    }
                  }
                }
                Err(err) => {
                  *sig = Err(err.clone());
                }
              },
              Err(err) => {
                *sig = Err(err.clone());
              }
            }
          } else if let ExportType::Global(global) = &mut export.export_type {
            let parsed_globals = parsed_globals.get_or_insert_with(|| {
              parse_global_section(globals_section.unwrap_or_default())
            });
            let export_index = export.index as usize;
            match &parsed_globals {
              Ok(globals) => {
                if let Some(global_type) = globals.get(export_index) {
                  *global = Ok(global_type.clone());
                }
              }
              Err(err) => {
                *global = Err(err.clone());
              }
            }
          }
        }
      }
    }
    Ok(Self {
      imports: imports.unwrap_or_default(),
      exports: exports.unwrap_or_default(),
    })
  }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImportType {
  Function(u32),
  Table(TableType),
  Memory(MemoryType),
  Global(GlobalType),
  Tag(TagType),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Limits {
  pub initial: u32,
  pub maximum: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TableType {
  pub element_type: u8,
  pub limits: Limits,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MemoryType {
  pub limits: Limits,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ValueType {
  I32,
  I64,
  F32,
  F64,
  /// A value currently not understood by this parser.
  Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalType {
  pub value_type: ValueType,
  pub mutability: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TagType {
  pub kind: u8,
  pub type_index: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Import<'a> {
  pub name: &'a str,
  pub module: &'a str,
  pub import_type: ImportType,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Export<'a> {
  pub name: &'a str,
  pub index: u32,
  pub export_type: ExportType,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExportType {
  Function(Result<FunctionSignature, ParseError>),
  Table,
  Memory,
  Global(Result<GlobalType, ParseError>),
  Tag,
  Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSignature {
  pub params: Vec<ValueType>,
  pub returns: Vec<ValueType>,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
  #[error("not a Wasm module")]
  NotWasm,
  #[error("unsupported Wasm version: {0}")]
  UnsupportedVersion(u32),
  #[error("unexpected end of file")]
  UnexpectedEof,
  #[error("integer overflow")]
  IntegerOverflow,
  #[error("invalid utf-8. {0:#}")]
  InvalidUtf8(Utf8Error),
  #[error("unknown import type '{0:X}'")]
  UnknownImportType(u8),
  #[error("unknown element type '{0:X}'")]
  UnknownElementType(u8),
  #[error("invalid mutability flag '{0:X}'")]
  InvalidMutabilityFlag(u8),
  #[error("unknown attribute '{0:X}'")]
  UnknownTagKind(u8),
  #[error("invalid type indicator '{0:X}'")]
  InvalidTypeIndicator(u8),
  #[error("export type not found")]
  ExportTypeNotFound,
}

type ParseResult<'a, T> = Result<(&'a [u8], T), ParseError>;

fn parse_magic_bytes(input: &[u8]) -> ParseResult<()> {
  // \0asm
  if input.starts_with(&[0, 97, 115, 109]) {
    Ok((&input[4..], ()))
  } else {
    Err(ParseError::NotWasm)
  }
}

fn ensure_known_version(input: &[u8]) -> ParseResult<()> {
  if input.len() < 4 {
    return Err(ParseError::UnexpectedEof);
  }

  let version = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
  if version != 1 {
    return Err(ParseError::UnsupportedVersion(version));
  }

  Ok((&input[4..], ()))
}

fn parse_import_section(input: &[u8]) -> Result<Vec<Import>, ParseError> {
  let (mut input, count) = parse_var_uint(input)?;
  let mut imports = Vec::with_capacity(count as usize);

  for _ in 0..count {
    let (rest, import) = parse_import(input)?;
    input = rest;
    imports.push(import);
  }

  debug_assert!(input.is_empty());

  Ok(imports)
}

fn parse_import(input: &[u8]) -> ParseResult<Import> {
  let (input, module) = parse_length_prefixed_string(input)?;
  let (input, name) = parse_length_prefixed_string(input)?;
  let (input, import_type) = parse_import_type(input)?;

  Ok((
    input,
    Import {
      module,
      name,
      import_type,
    },
  ))
}

fn parse_import_type(input: &[u8]) -> ParseResult<ImportType> {
  let (input, kind_byte) = read_byte(input)?;
  match kind_byte {
    0x00 => {
      let (input, type_index) = parse_var_uint(input)?;
      Ok((input, ImportType::Function(type_index)))
    }
    0x01 => {
      let (input, table_type) = parse_table_type(input)?;
      Ok((input, ImportType::Table(table_type)))
    }
    0x02 => {
      let (input, memory_type) = parse_memory_type(input)?;
      Ok((input, ImportType::Memory(memory_type)))
    }
    0x03 => {
      let (input, global_type) = parse_global_type(input)?;
      Ok((input, ImportType::Global(global_type)))
    }
    0x04 => {
      let (input, tag_type) = parse_tag_type(input)?;
      Ok((input, ImportType::Tag(tag_type)))
    }
    _ => Err(ParseError::UnknownImportType(kind_byte)),
  }
}

fn parse_table_type(input: &[u8]) -> ParseResult<TableType> {
  // element type
  let (input, element_type) = read_byte(input)?;
  if element_type != /* funref */ 0x70 {
    return Err(ParseError::UnknownElementType(element_type));
  }

  // limits
  let (input, limits) = parse_limits(input)?;

  Ok((
    input,
    TableType {
      element_type,
      limits,
    },
  ))
}

fn parse_memory_type(input: &[u8]) -> ParseResult<MemoryType> {
  let (input, limits) = parse_limits(input)?;
  Ok((input, MemoryType { limits }))
}

fn parse_global_type(input: &[u8]) -> ParseResult<GlobalType> {
  let (input, value_type) = parse_value_type(input)?;
  let (input, mutability_byte) = read_byte(input)?;
  let mutability = match mutability_byte {
    0x00 => false,
    0x01 => true,
    _ => return Err(ParseError::InvalidMutabilityFlag(mutability_byte)),
  };

  Ok((
    input,
    GlobalType {
      value_type,
      mutability,
    },
  ))
}

fn skip_init_expr(input: &[u8]) -> ParseResult<()> {
  let mut input = input;

  loop {
    if input.is_empty() {
      return Err(ParseError::UnexpectedEof);
    }

    let (next_input, opcode) = read_byte(input)?;
    input = next_input;

    // end op code
    if opcode == 0x0b {
      break;
    }
  }

  Ok((input, ()))
}

fn parse_value_type(input: &[u8]) -> ParseResult<ValueType> {
  let (input, byte) = read_byte(input)?;
  Ok((
    input,
    match byte {
      0x7F => ValueType::I32,
      0x7E => ValueType::I64,
      0x7D => ValueType::F32,
      0x7C => ValueType::F64,
      _ => ValueType::Unknown,
    },
  ))
}

fn parse_limits(input: &[u8]) -> ParseResult<Limits> {
  fn maybe_parse_maximum(input: &[u8], flags: u8) -> ParseResult<Option<u32>> {
    if flags == 0x01 {
      let (input, max) = parse_var_uint(input)?;
      Ok((input, Some(max)))
    } else {
      Ok((input, None))
    }
  }

  let (input, flags) = read_byte(input)?;
  let (input, initial) = parse_var_uint(input)?;
  let (input, maximum) = maybe_parse_maximum(input, flags)?;

  Ok((input, Limits { initial, maximum }))
}

fn parse_tag_type(input: &[u8]) -> ParseResult<TagType> {
  let (input, kind) = read_byte(input)?;
  if kind != 0x00 {
    return Err(ParseError::UnknownTagKind(kind));
  }

  let (input, type_index) = parse_var_uint(input)?;
  Ok((input, TagType { kind, type_index }))
}

fn parse_export_section(input: &[u8]) -> Result<Vec<Export>, ParseError> {
  let (mut input, count) = parse_var_uint(input)?;
  let mut exports = Vec::with_capacity(count as usize);

  for _ in 0..count {
    let (rest, export) = parse_export_type(input)?;
    input = rest;
    exports.push(export);
  }

  debug_assert!(input.is_empty());

  Ok(exports)
}

fn parse_export_type(input: &[u8]) -> ParseResult<Export> {
  let (input, name) = parse_length_prefixed_string(input)?;
  let (input, kind_byte) = read_byte(input)?;
  let (input, index) = parse_var_uint(input)?;

  let export_type = match kind_byte {
    0x00 => ExportType::Function(Err(ParseError::ExportTypeNotFound)),
    0x01 => ExportType::Table,
    0x02 => ExportType::Memory,
    0x03 => ExportType::Global(Err(ParseError::ExportTypeNotFound)),
    0x04 => ExportType::Tag,
    _ => ExportType::Unknown,
  };

  Ok((
    input,
    Export {
      name,
      index,
      export_type,
    },
  ))
}

fn parse_type_section(
  input: &[u8],
) -> Result<Vec<FunctionSignature>, ParseError> {
  if input.is_empty() {
    return Ok(Vec::new());
  }

  let (mut input, count) = parse_var_uint(input)?;
  let mut function_signatures = Vec::with_capacity(count as usize);

  for _ in 0..count {
    let (rest, signature) = parse_function_signature(input)?;
    function_signatures.push(signature);
    input = rest;
  }

  debug_assert!(input.is_empty());

  Ok(function_signatures)
}

fn parse_function_signature(input: &[u8]) -> ParseResult<FunctionSignature> {
  let (input, type_byte) = read_byte(input)?;
  if type_byte != 0x60 {
    return Err(ParseError::InvalidTypeIndicator(type_byte));
  }

  let (mut input, param_count) = parse_var_uint(input)?;
  let mut params = Vec::with_capacity(param_count as usize);

  for _ in 0..param_count {
    let (rest, param_type) = parse_value_type(input)?;
    input = rest;
    params.push(param_type);
  }

  let (mut input, return_count) = parse_var_uint(input)?;
  let mut returns = Vec::with_capacity(return_count as usize);

  for _ in 0..return_count {
    let (rest, return_type) = parse_value_type(input)?;
    input = rest;
    returns.push(return_type);
  }
  Ok((input, FunctionSignature { params, returns }))
}

fn parse_function_section(input: &[u8]) -> Result<Vec<u32>, ParseError> {
  if input.is_empty() {
    return Ok(Vec::new());
  }

  let (mut input, count) = parse_var_uint(input)?;
  let mut function_indices = Vec::with_capacity(count as usize);

  for _ in 0..count {
    let (rest, index) = parse_var_uint(input)?;
    function_indices.push(index);
    input = rest;
  }

  debug_assert!(input.is_empty());

  Ok(function_indices)
}

fn parse_global_section(input: &[u8]) -> Result<Vec<GlobalType>, ParseError> {
  if input.is_empty() {
    return Ok(Vec::new());
  }

  let (mut input, count) = parse_var_uint(input)?;
  let mut globals = Vec::with_capacity(count as usize);

  for _ in 0..count {
    let (rest, global_type) = parse_global_type(input)?;
    let (rest, _) = skip_init_expr(rest)?;
    globals.push(global_type);
    input = rest;
  }

  debug_assert!(input.is_empty());

  Ok(globals)
}

struct WasmSection<'a> {
  kind: u8,
  bytes: &'a [u8],
}

fn parse_section(input: &[u8]) -> ParseResult<WasmSection> {
  let (input, kind) = read_byte(input)?;
  let (input, payload_len) = parse_var_uint(input)?;
  let payload_len = payload_len as usize;
  if input.len() < payload_len {
    return Err(ParseError::UnexpectedEof);
  }
  let section_bytes = &input[..payload_len];
  Ok((
    &input[payload_len..],
    WasmSection {
      kind,
      bytes: section_bytes,
    },
  ))
}

fn parse_length_prefixed_string(
  input: &[u8],
) -> Result<(&[u8], &str), ParseError> {
  let (input, length) = parse_var_uint(input)?;
  if input.len() < length as usize {
    return Err(ParseError::UnexpectedEof);
  }
  let string_bytes = &input[..length as usize];
  match std::str::from_utf8(string_bytes) {
    Ok(s) => Ok((&input[length as usize..], s)),
    Err(err) => Err(ParseError::InvalidUtf8(err)),
  }
}

/// Parse a variable length ULEB128 unsigned integer.
fn parse_var_uint(input: &[u8]) -> ParseResult<u32> {
  let mut result = 0;
  let mut shift = 0;
  let mut input = input;
  loop {
    let (rest, byte) = read_byte(input)?;
    input = rest;
    if shift >= 32 || (shift == 28 && byte > 0b1111) {
      return Err(ParseError::IntegerOverflow);
    }
    result |= ((byte & 0x7f) as u32) << shift;
    if byte & 0x80 == 0 {
      break;
    }
    shift += 7;
  }
  Ok((input, result))
}

fn read_byte(input: &[u8]) -> ParseResult<u8> {
  if input.is_empty() {
    return Err(ParseError::UnexpectedEof);
  }
  Ok((&input[1..], input[0]))
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn test_parse_length_prefixed_string() {
    // normal string
    {
      let input = [0x05, b'H', b'e', b'l', b'l', b'o'];
      let (rest, string) = parse_length_prefixed_string(&input).unwrap();
      assert_eq!(string, "Hello");
      assert!(rest.is_empty());
    }

    // empty string
    {
      let input = [0x00];
      let (rest, string) = parse_length_prefixed_string(&input).unwrap();
      assert_eq!(string, "");
      assert!(rest.is_empty());
    }

    // non-ASCII characters (UTF-8)
    {
      let input = [0x03, 0xC3, 0xA9, b'm']; // "é" in UTF-8 + 'm'
      let (rest, string) = parse_length_prefixed_string(&input).unwrap();
      assert_eq!(string, "ém");
      assert!(rest.is_empty());
    }

    // incorrect UTF-8 sequence
    {
      let input = [0x01, 0xFF]; // 0xFF is not valid in UTF-8
      assert!(parse_length_prefixed_string(&input).is_err());
    }

    // insufficient length (claims 5 bytes, only 4 provided)
    {
      let input = [0x05, b't', b'e', b's', b't']; // length prefix says 5, but only 4 bytes follow
      assert!(parse_length_prefixed_string(&input).is_err());
    }

    // excessive length (claims 2 bytes, 3 provided)
    {
      let input = [0x02, b'x', b'y', b'z'];
      let (rest, string) = parse_length_prefixed_string(&input).unwrap();
      assert_eq!(string, "xy");
      assert_eq!(rest, &[b'z']);
    }
  }

  #[test]
  fn test_parse_var_uint() {
    // single byte
    {
      let input = [0x01];
      let (rest, value) = parse_var_uint(&input).unwrap();
      assert_eq!(value, 1);
      assert_eq!(rest.len(), 0);
    }

    // number that spans multiple bytes
    {
      let input = [0x80, 0x01];
      let (rest, value) = parse_var_uint(&input).unwrap();
      assert_eq!(value, 128);
      assert_eq!(rest.len(), 0);
    }

    // the maximum 32-bit value
    {
      let input = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
      let (rest, value) = parse_var_uint(&input).unwrap();
      assert_eq!(value, 0xFFFF_FFFF);
      assert_eq!(rest.len(), 0);
    }

    // input longer than 5 bytes (overflow protection)
    {
      let input = [0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
      assert!(parse_var_uint(&input).is_err());
    }

    // non-terminated sequence
    {
      let input = [0x80, 0x80, 0x80];
      assert!(parse_var_uint(&input).is_err());
    }

    // input where the final byte would cause an overflow
    {
      let input = [0xFF, 0xFF, 0xFF, 0xFF, 0x4F];
      assert!(parse_var_uint(&input).is_err());
    }
  }
}
