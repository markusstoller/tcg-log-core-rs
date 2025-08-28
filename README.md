# tcg-rs

A small, zero-std-alloc parsing iterator for Trusted Computing Group (TCG) Windows Boot Configuration Logs (WBCL). It provides a safe, idiomatic Rust wrapper for iterating through PCR event entries from a WBCL buffer, supporting legacy PC Client (TCG1.2) and TCG2 formats with multiple digest algorithms.

## Features
- Zero-copy iteration over WBCL buffers provided as `&[u8]`.
- Supports TCG EFI SpecID events and TCG2 multi-digest headers.
- Extracts per-entry metadata:
  - PCR index
  - Event type
  - Digest(s) slice
  - Event data size and slice
- Simple API surface with `WbclIterator` and helper free functions.
- No external dependencies.

## Status
This is an early crate (0.1.0) intended for experimentation, learning, or narrow tooling purposes. The public API may change.

## Installation
Add to your `Cargo.toml`:

```toml
[dependencies]
tcg-rs = "0.1"
```

Rust edition: 2024.

## Quick Start
The API works over an in-memory WBCL buffer, commonly read from a file (on Windows, for example, from the WBCL exported by system tools).

```rust
use tcg_rs::{
    wbcl_api_init_iterator,
    wbcl_api_move_to_next_element,
    wbcl_api_get_current_element,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Replace with an actual WBCL path or buffer source
    let buffer = std::fs::read("path\\to\\your.wbcl")?;

    let mut it = wbcl_api_init_iterator(&buffer)
        .map_err(|code| format!("failed to init WBCL iterator, error=0x{code:08x}"))?;

    while it.has_next() {
        wbcl_api_move_to_next_element(&mut it)
            .map_err(|code| format!("failed to move to next element, error=0x{code:08x}"))?;

        let (pcr_index, event_type, digest_opt, data_size, data_opt) =
            wbcl_api_get_current_element(&it)
                .map_err(|code| format!("failed to get current element, error=0x{code:08x}"))?;

        println!(
            "PCR: {pcr_index}, EventType: 0x{event_type:x}, DigestLen: {}, DataLen: {}",
            digest_opt.map(|d| d.len()).unwrap_or(0),
            data_size
        );

        // Optionally process digest and data slices
        if let Some(d) = digest_opt { /* ... */ }
        if let Some(ed) = data_opt { /* ... */ }
    }

    Ok(())
}
```

## Concepts and API

### Core Types
- `WbclIterator<'a>`: Stateful iterator over a WBCL byte buffer. It validates headers, keeps current offset, and exposes helpers to read the current element.

### Constructor
- `WbclIterator::new(log_buffer: &'a [u8]) -> Result<Self, u32>`
  - Validates the buffer, parses initial headers (e.g., SpecID event and TCG2 algorithm table), and positions before the first real event.

### Iteration
- `has_next(&self) -> bool` — Whether another event can be read.
- `move_to_next_element(&mut self) -> Result<(), u32>` — Advance to the next event.
- `get_current_element(&self) -> Result<(u32, u32, Option<&'a [u8]>, u32, Option<&'a [u8]>), u32>`
  - Returns a tuple:
    - `(pcr_index, event_type, digest_slice_opt, event_data_size, event_data_slice_opt)`
  - When multiple digests are present (TCG2), this returns the combined/selected digest region for the current element. Consult the source for details.

### Convenience FFI-style Helpers
- `wbcl_api_init_iterator(log_buffer: &[u8]) -> Result<WbclIterator, u32>`
- `wbcl_api_get_current_element(iterator: &WbclIterator) -> Result<(u32, u32, Option<&[u8]>, u32, Option<&[u8]>), u32>`
- `wbcl_api_move_to_next_element(iterator: &mut WbclIterator) -> Result<(), u32>`

These mimic a C-FFI style interface and may be easier to integrate in some contexts.

## Error Handling
Functions return `Result<_, u32>` where the `u32` is an error code. Common conditions include:
- Invalid or too-small buffer
- Unsupported or malformed WBCL headers
- Out-of-bounds sizes when parsing elements

During development, you can consult the tests in `src/lib.rs` for behavior expectations. Error codes are hex-friendly; when printing, use `0x{code:08x}` to make debugging easier.

## Examples
- Reading from a file and printing PCR and event type: see Quick Start.
- The test `test_load_file` in `src/lib.rs` demonstrates iterating a log loaded from `D://temp//markus.log`. Adjust the path to your environment.

## Testing
Run the test suite:

```bash
cargo test
```

Note: Some tests assume presence of a local WBCL file; you may skip or adjust those if you do not have one.

## Safety Notes
- All parsing operates on borrowed byte slices; no unsafe memory ownership tricks are required by the user of the API.
- Internally, bounds are checked before slicing to prevent panics.
- The crate aims to avoid allocations during iteration.

## Limitations and Roadmap
- The iterator currently exposes only a single digest slice per element even in multi-digest TCG2 scenarios; richer per-algorithm access may be added later.
- The public API and error codes may evolve prior to 1.0.

## Contributing
Issues and PRs are welcome. Please:
- Include a clear description and, where possible, a reproducible case.
- Add tests covering new functionality or bug fixes.

## License
Unless otherwise noted in `Cargo.toml`, this project is released under a permissive license customary for Rust crates. If a specific license file is added (e.g., MIT/Apache-2.0), that file governs.

## Acknowledgements
- TCG specifications for PC Client and EFI are the basis of the formats handled here.
- Inspiration from platform attestation tooling and WBCL readers in other languages.
