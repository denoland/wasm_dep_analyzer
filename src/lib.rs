// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.

use std::str::Utf8Error;

use thiserror::Error;

#[derive(Debug, PartialEq, Eq)]
pub struct WasmDeps<'a> {
  pub imports: Vec<Import<'a>>,
  pub exports: Vec<Export<'a>>,
}

impl<'a> WasmDeps<'a> {
  /// Parses a Wasm module's bytes discovering the imports and exports.
  ///
  /// The parser will try to parse even when it doesn't understand something
  /// and will only parse out the information necessary for dependency analysis.
  pub fn parse(input: &'a [u8]) -> Result<Self, ParseError> {
    let (mut input, _) = parse_magic_bytes(input)?;
    let mut imports = None;
    let mut exports = None;
    while !input.is_empty() && (imports.is_none() || exports.is_none()) {
      let (rest, section) = parse_section(input)?;
      input = rest;
      if imports.is_none() && section.kind == 0x02 {
        imports = Some(parse_import_section(section.bytes)?);
      } else if exports.is_none() && section.kind == 0x07 {
        exports = Some(parse_export_section(section.bytes)?);
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

#[derive(Debug, PartialEq, Eq)]
pub struct GlobalType {
  pub value_type: u8,
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
  Function,
  Table,
  Memory,
  Global,
  Tag,
  Unknown,
}

#[derive(Error, Debug)]
pub enum ParseError {
  #[error("not a Wasm module")]
  NotWasm,
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
  let (input, value_type) = read_byte(input)?;
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
    0x00 => ExportType::Function,
    0x01 => ExportType::Table,
    0x02 => ExportType::Memory,
    0x03 => ExportType::Global,
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