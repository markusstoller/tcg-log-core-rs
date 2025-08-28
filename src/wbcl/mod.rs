//! TCG log parsing functionality for WBCL (Windows Boot Configuration Log)
//!
//! This module provides an API surface for parsing and iterating through TCG event logs.
//! It supports both TCG 1.2 (SHA-1 only) and TCG 2.0 (crypto-agile) formats.

use std::mem;
use std::slice;

// Constants
const TREE_EVENT_LOG_FORMAT_TCG_1_2: u32 = 0x00000001;
const TREE_EVENT_LOG_FORMAT_TCG_2: u32 = 0x00000002;
const SIPAEV_NO_ACTION: u32 = 0x00000003;

const MIN_TCG_VERSION_MAJOR: u8 = 1;
const MIN_TCG_VERSION_MINOR: u8 = 2;

const SHA1_DIGEST_SIZE: u16 = 20;
const SHA256_DIGEST_SIZE: u16 = 32;
const SHA384_DIGEST_SIZE: u16 = 48;
const SHA512_DIGEST_SIZE: u16 = 64;

const MAX_NUMBER_OF_DIGESTS: u32 = 5;

// Algorithm IDs
pub type WbclDigestAlgId = u16;

pub const WBCL_DIGEST_ALG_ID_SHA_1: WbclDigestAlgId = 0x0004;
pub const WBCL_DIGEST_ALG_ID_SHA_2_256: WbclDigestAlgId = 0x000B;
pub const WBCL_DIGEST_ALG_ID_SHA_2_384: WbclDigestAlgId = 0x000C;
pub const WBCL_DIGEST_ALG_ID_SHA_2_512: WbclDigestAlgId = 0x000D;
pub const WBCL_DIGEST_ALG_ID_SM3_256: WbclDigestAlgId = 0x0012;
pub const WBCL_DIGEST_ALG_ID_SHA3_256: WbclDigestAlgId = 0x0027;
pub const WBCL_DIGEST_ALG_ID_SHA3_384: WbclDigestAlgId = 0x0028;
pub const WBCL_DIGEST_ALG_ID_SHA3_512: WbclDigestAlgId = 0x0029;

// Algorithm bitmaps
const WBCL_DIGEST_ALG_BITMAP_SHA_1: u32 = 0x00000001;
const WBCL_DIGEST_ALG_BITMAP_SHA_2_256: u32 = 0x00000002;
const WBCL_DIGEST_ALG_BITMAP_SHA_2_384: u32 = 0x00000004;
const WBCL_DIGEST_ALG_BITMAP_SHA_2_512: u32 = 0x00000008;
const WBCL_DIGEST_ALG_BITMAP_SM3_256: u32 = 0x00000010;
const WBCL_DIGEST_ALG_BITMAP_SHA3_256: u32 = 0x00000020;
const WBCL_DIGEST_ALG_BITMAP_SHA3_384: u32 = 0x00000040;
const WBCL_DIGEST_ALG_BITMAP_SHA3_512: u32 = 0x00000080;

// Error codes
const S_OK: u32 = 0;
const S_FALSE: u32 = 1;
const E_INVALIDARG: u32 = 0x80070057;
const ERROR_INVALID_DATA: u32 = 0x0000000D;
const ERROR_NOT_SUPPORTED: u32 = 0x00000032;

// TCG EFI Spec ID Event signature
const TCG_EFI_SPEC_ID_EVENT_STRUCT_SIGNATURE_03: [u8; 16] = [
    0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x00,
];

// Algorithm ID to bitmap lookup table
static G_WBCL_ALGORITHM_ID_TO_BITMAP_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    table[WBCL_DIGEST_ALG_ID_SHA_1 as usize] = WBCL_DIGEST_ALG_BITMAP_SHA_1;
    table[WBCL_DIGEST_ALG_ID_SHA_2_256 as usize] = WBCL_DIGEST_ALG_BITMAP_SHA_2_256;
    table[WBCL_DIGEST_ALG_ID_SHA_2_384 as usize] = WBCL_DIGEST_ALG_BITMAP_SHA_2_384;
    table[WBCL_DIGEST_ALG_ID_SHA_2_512 as usize] = WBCL_DIGEST_ALG_BITMAP_SHA_2_512;
    table[WBCL_DIGEST_ALG_ID_SM3_256 as usize] = WBCL_DIGEST_ALG_BITMAP_SM3_256;
    table[WBCL_DIGEST_ALG_ID_SHA3_256 as usize] = WBCL_DIGEST_ALG_BITMAP_SHA3_256;
    table[WBCL_DIGEST_ALG_ID_SHA3_384 as usize] = WBCL_DIGEST_ALG_BITMAP_SHA3_384;
    table[WBCL_DIGEST_ALG_ID_SHA3_512 as usize] = WBCL_DIGEST_ALG_BITMAP_SHA3_512;
    table
};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TcgEfiSpecIdEventAlgorithmSize {
    pub algorithm_id: WbclDigestAlgId,
    pub digest_size: u16,
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct TcgEfiSpecIdEventStruct {
    pub signature: [u8; 16],
    pub platform_class: u32,
    pub spec_version_minor: u8,
    pub spec_version_major: u8,
    pub spec_errata: u8,
    pub uintn_size: u8,
    pub number_of_algorithms: u32,
    // Variable length fields follow
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct TcgPcClientPcrEventStruct {
    pub pcr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 20], // SHA1_DIGEST_SIZE
    pub event_data_size: u32,
    // Variable length event data follows
}

/// WBCL Iterator for traversing log entries
pub struct WbclIterator<'a> {
    pub first_element_ptr: &'a [u8],
    pub log_size: u32,
    pub current_element_ptr: Option<&'a [u8]>,
    pub current_element_size: u32,
    pub digest_size: u16,
    pub log_format: u16,
    pub number_of_digests: u32,
    pub digest_sizes: Option<&'a [TcgEfiSpecIdEventAlgorithmSize]>,
    pub hash_algorithm: WbclDigestAlgId,
}

impl<'a> WbclIterator<'a> {
    /// Creates a new instance of the `WbclIterator`.
    ///
    /// This function initializes a `WbclIterator` with the provided WBCL log buffer and
    /// determines the format of the event log (TCG 1.2 or TCG 2.0) by examining the first event.
    ///
    /// # Parameters
    /// - `log_buffer`: A byte slice that represents the WBCL log buffer. The buffer must
    ///   contain at least enough data to read `TcgPcClientPcrEventStruct` (minus one byte).
    ///
    /// # Returns
    /// - `Ok(Self)`: If the initialization and log format detection succeed.
    /// - `Err(u32)`: Returns an error code in the following scenarios:
    ///   - `E_INVALIDARG` if the provided buffer is too small to contain the header of
    pub fn new(log_buffer: &'a [u8]) -> Result<Self, u32> {
        if log_buffer.len() < size_of::<TcgPcClientPcrEventStruct>() - 1 {
            return Err(E_INVALIDARG);
        }

        let mut iterator = WbclIterator {
            first_element_ptr: log_buffer,
            log_size: log_buffer.len() as u32,
            current_element_ptr: Some(log_buffer),
            current_element_size: 0,
            digest_size: SHA1_DIGEST_SIZE,
            log_format: TREE_EVENT_LOG_FORMAT_TCG_1_2 as u16,
            number_of_digests: 0,
            digest_sizes: None,
            hash_algorithm: WBCL_DIGEST_ALG_ID_SHA_1,
        };

        // Get the size of the first element
        let element_size = iterator.get_current_element_size()?;
        if log_buffer.len() < element_size as usize {
            return Err(ERROR_INVALID_DATA);
        }
        iterator.current_element_size = element_size;

        // Check if this is a crypto-agile log by examining the first event
        let (pcr_index, event_type, _, first_element_data_size, _) =
            iterator.get_current_element()?;

        // Check for TCG 2.0 log format
        if pcr_index == 0
            && event_type == SIPAEV_NO_ACTION
            && first_element_data_size >= size_of::<TcgEfiSpecIdEventStruct>() as u32
        {
            if let Some(event_data) = iterator.get_current_element_data() {
                if event_data.len() >= size_of::<TcgEfiSpecIdEventStruct>() {
                    // Check signature
                    if &event_data[0..16] == &TCG_EFI_SPEC_ID_EVENT_STRUCT_SIGNATURE_03 {
                        iterator.process_tcg2_header(event_data)?;
                        return Ok(iterator);
                    }
                }
            }
        }

        Err(ERROR_INVALID_DATA)
    }

    /// Processes the TCG 2.0 header from the provided event data to initialize log properties.
    ///
    /// This method checks the integrity and compatibility of the provided binary data
    /// that represents a TCG (Trusted Computing Group) EFI (Extensible Firmware Interface)
    /// Spec ID event structure. If valid, it extracts the relevant information and
    /// configures the internal state of the log iterator.
    ///
    /// # Parameters
    /// - `event_data`: A reference to a byte slice representing the event data containing
    ///   the TCG EFI Spec ID event header and potentially additional entries.
    ///
    /// # Returns
    /// - `Ok(())`: If the TCG header is processed successfully.
    /// - `Err(ERROR_NOT_SUPPORTED)`: If the provided event data does not conform to the
    ///   required TCG version, contains unsupported algorithms, or lacks a proper
    ///   matching hashing algorithm.
    /// - `Err(ERROR_INVALID_DATA)`: If the event data does not have enough data to perform
    ///   required processing.
    ///
    /// # Behavior
    /// - Validates the size of the input data for containing at least the header structure.
    /// - Performs a version compatibility check against the `MIN_TCG_VERSION_MAJOR` and
    ///   `MIN_TCG_VERSION_MINOR`.
    /// - Verifies the number of algorithms defined in the header does not exceed
    ///   `MAX_NUMBER_OF_DIGESTS`.
    /// - Parses and calculates an offset to the digest sizes array and validates its presence
    ///   in the event data buffer.
    /// - Constructs a bitmap of supported algorithms based on the parsed digest sizes.
    /// - Sets the iterator's attributes such as log format, number of digests, and selected
    ///   hash algorithm based on supported preferences (e.g., SHA-256 is preferred over SHA-1).
    /// - Moves the iterator to the first log entry after processing the descriptor.
    ///
    /// # Supported Hash Algorithms
    /// The implementation supports prioritization of hash algorithms in the following order:
    /// - SHA-256 (`WBCL_DIGEST_ALG_BITMAP_SHA_2_256`)
    /// - SHA-1 (`WBCL_DIGEST_ALG_BITMAP_SHA_1`)
    /// - SHA-384 (`WBCL_DIGEST_ALG_BITMAP_SHA_2_384`)
    /// - SHA-512 (`WBCL_DIGEST_ALG_BITMAP_SHA_2_512`)
    /// - SHA3-256 (`WBCL_DIGEST_ALG_BITMAP_SHA3_256`)
    /// - SHA3-384 (`WBCL_DIGEST_ALG_BITMAP_SHA3_384`)
    /// - SHA3-512 (`WBCL_DIGEST_ALG_BITMAP_SHA3_512`)
    /// - SM3-256 (`WBCL_DIGEST_ALG_BITMAP_SM3_256`)
    ///
    /// If none of the algorithms are supported, the function returns an error with
    /// `ERROR_NOT_SUPPORTED`.
    ///
    /// # Safety
    /// - This function uses unsafe code to perform raw pointer casting and slicing to
    ///   interpret the binary data. The caller must ensure that `event_data` points to
    ///   valid and appropriately aligned memory that meets the structure's layout
    ///   expectations to avoid undefined behavior.
    ///
    /// # Errors
    /// - `ERROR_NOT_SUPPORTED`: Returned if the data fails version checks, contains
    ///   unsupported digest algorithms, or doesn't include a valid matching hash algorithm.
    /// - `ERROR_INVALID_DATA`: Returned when the size of `event_data` is insufficient to
    ///   process all required fields (header and digest sizes).
    fn process_tcg2_header(&mut self, event_data: &'a [u8]) -> Result<(), u32> {
        if event_data.len() < size_of::<TcgEfiSpecIdEventStruct>() {
            return Err(ERROR_NOT_SUPPORTED);
        }

        let header = unsafe { &*(event_data.as_ptr() as *const TcgEfiSpecIdEventStruct) };

        // Sanity check version
        if header.spec_version_major < MIN_TCG_VERSION_MAJOR
            || (header.spec_version_major == MIN_TCG_VERSION_MAJOR
            && header.spec_version_minor < MIN_TCG_VERSION_MINOR)
        {
            return Err(ERROR_NOT_SUPPORTED);
        }

        // Check number of algorithms
        if header.number_of_algorithms > MAX_NUMBER_OF_DIGESTS {
            return Err(ERROR_NOT_SUPPORTED);
        }

        // Calculate offset to digest sizes array
        let digest_sizes_offset = size_of::<TcgEfiSpecIdEventStruct>();
        let digest_sizes_size =
            header.number_of_algorithms as usize * size_of::<TcgEfiSpecIdEventAlgorithmSize>();

        if event_data.len() < digest_sizes_offset + digest_sizes_size {
            return Err(ERROR_INVALID_DATA);
        }

        // Get digest sizes slice
        let digest_sizes_ptr = unsafe {
            event_data.as_ptr().add(digest_sizes_offset) as *const TcgEfiSpecIdEventAlgorithmSize
        };
        let digest_sizes = unsafe {
            slice::from_raw_parts(digest_sizes_ptr, header.number_of_algorithms as usize)
        };

        // Calculate supported algorithms bitmap
        let mut supported_algorithms = 0u32;
        for digest_size in digest_sizes {
            let alg_id = digest_size.algorithm_id as usize;
            if alg_id < G_WBCL_ALGORITHM_ID_TO_BITMAP_TABLE.len() {
                supported_algorithms |= G_WBCL_ALGORITHM_ID_TO_BITMAP_TABLE[alg_id];
            }
        }

        // Set iterator properties for TCG 2.0 format
        self.log_format = TREE_EVENT_LOG_FORMAT_TCG_2 as u16;
        self.number_of_digests = header.number_of_algorithms;
        self.digest_sizes = Some(digest_sizes);

        // Choose hash algorithm based on preference
        if supported_algorithms & WBCL_DIGEST_ALG_BITMAP_SHA_2_256 != 0 {
            self.hash_algorithm = WBCL_DIGEST_ALG_ID_SHA_2_256;
            self.digest_size = SHA256_DIGEST_SIZE;
        } else if supported_algorithms & WBCL_DIGEST_ALG_BITMAP_SHA_1 != 0 {
            self.hash_algorithm = WBCL_DIGEST_ALG_ID_SHA_1;
            self.digest_size = SHA1_DIGEST_SIZE;
        } else if supported_algorithms & WBCL_DIGEST_ALG_BITMAP_SHA_2_384 != 0 {
            self.hash_algorithm = WBCL_DIGEST_ALG_ID_SHA_2_384;
            self.digest_size = SHA384_DIGEST_SIZE;
        } else if supported_algorithms & WBCL_DIGEST_ALG_BITMAP_SHA_2_512 != 0 {
            self.hash_algorithm = WBCL_DIGEST_ALG_ID_SHA_2_512;
            self.digest_size = SHA512_DIGEST_SIZE;
        } else if supported_algorithms & WBCL_DIGEST_ALG_BITMAP_SHA3_256 != 0 {
            self.hash_algorithm = WBCL_DIGEST_ALG_ID_SHA3_256;
            self.digest_size = SHA256_DIGEST_SIZE;
        } else if supported_algorithms & WBCL_DIGEST_ALG_BITMAP_SHA3_384 != 0 {
            self.hash_algorithm = WBCL_DIGEST_ALG_ID_SHA3_384;
            self.digest_size = SHA384_DIGEST_SIZE;
        } else if supported_algorithms & WBCL_DIGEST_ALG_BITMAP_SHA3_512 != 0 {
            self.hash_algorithm = WBCL_DIGEST_ALG_ID_SHA3_512;
            self.digest_size = SHA512_DIGEST_SIZE;
        } else if supported_algorithms & WBCL_DIGEST_ALG_BITMAP_SM3_256 != 0 {
            self.hash_algorithm = WBCL_DIGEST_ALG_ID_SM3_256;
            self.digest_size = SHA256_DIGEST_SIZE;
        } else {
            return Err(ERROR_NOT_SUPPORTED);
        }

        // Move to the first log entry after the descriptor
        self.move_to_next_element()?;

        Ok(())
    }

    /// Returns the digest size for the specified algorithm.
    ///
    /// This function takes an algorithm identifier (`algorithm_id`) of type
    /// `WbclDigestAlgId` and searches for its corresponding digest size within
    /// the `digest_sizes` field of the struct. If a matching `algorithm_id`
    /// is found, the function returns its `digest_size`. Otherwise, it
    /// returns the default `SHA1_DIGEST_SIZE`.
    ///
    /// # Parameters
    ///
    /// * `algorithm_id` - The identifier of the digest algorithm for which
    ///   the digest size is being requested.
    ///
    /// # Returns
    ///
    /// * `u16` - The size of the digest for the specified algorithm, or the
    ///   default digest size (`SHA1_DIGEST_SIZE`) if the algorithm is not found.
    ///
    /// # Behavior
    ///
    /// * If `digest_sizes` is `None`, the function will directly return
    ///
    fn get_digest_size(&self, algorithm_id: WbclDigestAlgId) -> u16 {
        if let Some(digest_sizes) = self.digest_sizes {
            for digest_size in digest_sizes {
                if digest_size.algorithm_id == algorithm_id {
                    return digest_size.digest_size;
                }
            }
        }
        SHA1_DIGEST_SIZE
    }

    /// Retrieves the size of the current element's digest in the event log.
    ///
    /// This function calculates the size of the digest based on the tree event log format
    /// (`log_format`) and the structure of the current element's data. It supports two formats:
    /// - `TREE_EVENT_LOG_FORMAT_TCG_1_2`: Returns the digest size corresponding to SHA1.
    /// - `TREE_EVENT_LOG_FORMAT_TCG_2`: Parses the current element to calculate the digest size.
    ///
    /// # Returns
    /// - `Ok(u32)`: The size of the digest in bytes.
    /// - `Err(u32)`: An error code if the operation fails. The possible error codes are:
    ///   - `E_INVALIDARG`: Indicates invalid arguments,
    ///     such as improperly formatted data or a violation of expected size constraints.
    ///
    /// # Errors and Validations for `TREE_EVENT_LOG_FORMAT_TCG_2`
    /// - If `current_element_ptr` is `None`, the function will return the error `E_INVALIDARG`.
    /// - If the data within `current_element_ptr` is smaller than expected to contain a valid number of digests,
    ///   the function will return the error `E_INVALIDARG`.
    /// - If the number of digests in the data exceeds `MAX_NUMBER_OF_DIGESTS`, the function will return `E_INVALIDARG`.
    /// - The function validates the integrity of each digest entry by ensuring there is enough
    ///   data for both the digest algorithm identifier and the digest itself. If the entry is malformed,
    ///   the function will return `E_INVALIDARG`.
    ///
    /// # Parameters
    /// - `self`:
    ///   - A reference to the current instance containing the `log_format`, `current_element_ptr`,
    ///     and helper functions for processing.
    ///
    /// # Internal Logic
    /// 1. For `TREE_EVENT_LOG_FORMAT_TCG_1_2`, the function immediately returns the SHA1 digest size.
    /// 2. For `TREE_EVENT_LOG_FORMAT_TCG_2`:
    ///    - Extracts the number of digests by parsing the `current_element_ptr`.
    ///    - Iterates over the digest entries, ensuring proper structure and calculating the cumulative size.
    ///    - Returns the total size of digests, including the number of digests and associated sizes.
    /// 3. If the format is unrecognized or any checks fail, the function returns `E_INVALIDARG`.
    ///
    /// # Dependencies
    /// - `SHA1_DIGEST_SIZE`: Constant defining the size of a SHA1 digest.
    /// - `size_of::<T>()`: Function used to compute the size of various types.
    /// - `WbclDigestAlgId`: Represents the digest algorithm identifier.
    /// - `MAX_NUMBER_OF_DIGESTS`: Limit on the maximum number of digests allowed.
    ///
    /// # Example
    /// ```rust
    /// let result = instance.get_current_element_digest_size();
    /// match result {
    ///     Ok(size) => println!("Digest size: {}", size),
    ///     Err(error_code) => eprintln!("Error occurred: {}", error_code),
    /// }
    /// ```
    ///
    /// # Note
    /// - This function assumes that the `current_element_ptr` is a byte array with properly
    ///   structured data for the `TREE_EVENT_LOG_FORMAT_TCG_2` format.
    fn get_current_element_digest_size(&self) -> Result<u32, u32> {
        if self.log_format == TREE_EVENT_LOG_FORMAT_TCG_1_2 as u16 {
            return Ok(SHA1_DIGEST_SIZE as u32);
        }

        if self.log_format == TREE_EVENT_LOG_FORMAT_TCG_2 as u16 {
            let current_element = self.current_element_ptr.ok_or(E_INVALIDARG)?;

            if current_element.len() < 2 * size_of::<u32>() + size_of::<u32>() {
                return Err(E_INVALIDARG);
            }

            // Skip PCRIndex and EventType to get to number of digests
            let ptr = &current_element[2 * size_of::<u32>()..];
            let number_of_digests = u32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);

            if number_of_digests > MAX_NUMBER_OF_DIGESTS {
                return Err(E_INVALIDARG);
            }

            let mut size = size_of::<u32>() as u32; // sizeof(numberOfDigests)
            let mut offset = size_of::<u32>(); // Start after numberOfDigests

            for _ in 0..number_of_digests {
                if offset + size_of::<WbclDigestAlgId>() >= ptr.len() {
                    return Err(E_INVALIDARG);
                }

                let alg_id = WbclDigestAlgId::from_le_bytes([ptr[offset], ptr[offset + 1]]);

                let digest_size = self.get_digest_size(alg_id) as u32;
                let tpmt_ha_size = digest_size + size_of::<WbclDigestAlgId>() as u32;

                offset += tpmt_ha_size as usize;
                if offset > ptr.len() {
                    return Err(E_INVALIDARG);
                }

                size += tpmt_ha_size;
            }

            return Ok(size);
        }

        Err(E_INVALIDARG)
    }

    /// Retrieves the size of the data associated with the current element.
    ///
    /// This function calculates and returns the size of the data for the current element
    /// by performing several checks and computations on the internal `current_element_ptr` buffer.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - Returns the size of the data in bytes if computation is successful.
    /// * `Err(u32)` - Returns an error code if the computation fails. Specifically, it may return:
    ///     - `E_INVALIDARG` if `current_element_ptr` is `None`,
    ///       or if the computed offset exceeds the bounds of the `current_element` buffer.
    ///
    /// # Errors
    ///
    /// The function can fail in the following scenarios:
    /// - If `current_element_ptr` is not set (i.e., is `None`), the function will return `E_INVALIDARG`.
    /// - If the computed offset (based on digest size and element layout) exceeds the
    ///   bounds of the `current_element` buffer, the function will return `E_INVALIDARG`.
    ///
    /// # Internal Details
    ///
    /// 1. The function first computes `digest_size` by calling `get_current_element_digest_size()`.
    /// 2. It verifies whether `current_element_ptr` is set; otherwise, it returns an error.
    /// 3. Computes the byte offset within the element buffer based on the digest size and
    ///    additional layout requirements.
    /// 4. Ensures the offset plus the size of a `u32` remains within the bounds of the buffer.
    /// 5. If all checks pass, extracts the 4 bytes at the computed offset, interprets them
    ///    as a little-endian `u32`, and returns it.
    ///
    /// # Example
    ///
    /// ```rust
    /// let data_size = instance.get_current_element_data_size();
    /// match data_size {
    ///     Ok(size) => println!("Current element data size: {} bytes", size),
    ///     Err(err) => println!("Error retrieving data size: {:#X}", err),
    /// }
    /// ```
    ///
    /// # Assumptions
    /// The method assumes that `current_element` adheres to a specific memory layout:
    /// - The first part of the buffer contains metadata (e.g., digest information).
    /// - The size of the data is stored as a 4-byte little-endian value at a specific offset
    ///   determined by the digest size.
    ///
    /// # Dependencies
    /// - `get_current_element_digest_size()`: Used to determine the digest size necessary
    ///   for offset computation.
    /// - Constant `E_INVALIDARG`: Represents an error code returned when inputs or state are invalid.
    ///
    /// # Safety
    /// This function operates on internal pointers and buffer lengths, so it assumes proper
    /// initialization of the `current_element_ptr` before invocation to avoid panics or undefined behavior.
    fn get_current_element_data_size(&self) -> Result<u32, u32> {
        let digest_size = self.get_current_element_digest_size()?;

        let current_element = self.current_element_ptr.ok_or(E_INVALIDARG)?;
        let offset = 2 * size_of::<u32>() + digest_size as usize;

        if offset + size_of::<u32>() > current_element.len() {
            return Err(E_INVALIDARG);
        }

        let data_size = u32::from_le_bytes([
            current_element[offset],
            current_element[offset + 1],
            current_element[offset + 2],
            current_element[offset + 3],
        ]);

        Ok(data_size)
    }

    /// Calculates the size of the current element structure.
    ///
    /// This function computes the total size in bytes of the current element,
    /// which includes the header, digests, and event data. The calculations are
    /// based on the following components:
    ///
    /// - Header: Comprised of two `u32` values (PCRIndex and EventType).
    /// - Digest field: The size is dynamically obtained through `get_current_element_digest_size()`.
    /// - Event data size: The size is dynamically obtained through `get_current_element_data_size()`.
    /// - Additional `u32` to store the size of the event data (`EventDataSize`).
    ///
    /// # Returns
    /// - `Ok(u32)`: The total calculated size of the current element in bytes.
    /// - `Err(u32)`: An error code returned by either `get_current_element_digest_size()`
    ///   or `get_current_element_data_size()`.
    ///
    /// # Errors
    /// This function may return an error if either of the underlying methods,
    /// `get_current_element_digest_size()` or `get_current_element_data_size()`, fails to retrieve
    /// the necessary size values.
    ///
    /// # Examples
    /// ```
    /// let size = my_instance.get_current_element_size();
    /// match size {
    ///     Ok(bytes) => println!("Size of current element: {} bytes", bytes),
    ///     Err(err) => eprintln!("Failed to calculate size: error code {}", err),
    /// }
    /// ```
    ///
    /// # Requirements
    /// - This method assumes that the underlying methods `get_current_element_digest_size()`
    ///   and `get_current_element_data_size()` are correctly implemented and return valid results.
    fn get_current_element_size(&self) -> Result<u32, u32> {
        let digest_size = self.get_current_element_digest_size()?;
        let data_size = self.get_current_element_data_size()?;

        Ok(
            2 * size_of::<u32>() as u32 +  // header (PCRIndex + EventType)
                digest_size +                        // Digests field
                size_of::<u32>() as u32 +      // EventDataSize
                data_size,
        ) // EventData
    }

    /// Retrieves the data associated with the current element.
    ///
    /// This method calculates and extracts the event data from the current element
    /// based on its size and offsets.
    ///
    /// # Returns
    /// An `Option` containing a reference to a byte slice (`&'a [u8]`) representing
    /// the event data of the current element, or `None` if:
    /// - The data size could not be determined.
    /// - The calculated data size is zero.
    /// - The digest size could not be determined.
    /// - The pointer to the current element is `None`.
    /// - The calculated offset and data size exceed the bounds of the current element.
    ///
    /// # Details
    /// The method performs the following steps:
    /// 1. Gets the size of the current element's event data by calling
    ///    `get_current_element_data_size()`.
    /// 2. Returns `None` if the size is invalid or zero.
    /// 3. Gets the digest size for the current element by calling
    ///    `get_current_element_digest_size()`.
    /// 4. Computes the offset to the event data within the current element:
    ///    - Adds the size of a 2-field header (2 * `size_of::<u32>()`), the size
    ///      of the digest data, and the size of an `EventDataSize` field
    ///      (`size_of::<u32>()`).
    /// 5. Checks the bounds to ensure the calculated offset and data slice length
    ///    are valid within the current element's data.
    /// 6. Returns a slice from the calculated offset to the end of the event data.
    ///
    /// # Note
    /// - The method assumes `self.current_element_ptr` contains a valid reference
    ///   to the current element's buffer.
    /// - If any of the preconditions for extracting the event data are not met,
    ///   the method gracefully returns `None`.
    ///
    /// # Example
    /// ```
    /// let element_data = my_object.get_current_element_data();
    /// if let Some(data) = element_data {
    ///     // Do something with the data
    ///     println!("Current element data: {:?}", data);
    /// } else {
    ///     println!("No valid event data available.");
    /// }
    /// ```
    ///
    /// # Errors
    /// This method does not explicitly return errors but will return `None`
    /// in cases of invalid or inconsistent data state (e.g., missing size or pointer).
    pub fn get_current_element_data(&self) -> Option<&'a [u8]> {
        let data_size = self.get_current_element_data_size().ok()? as usize;
        if data_size == 0 {
            return None;
        }

        let digest_size = self.get_current_element_digest_size().ok()? as usize;
        let current_element = self.current_element_ptr?;

        let offset = 2 * size_of::<u32>() + // header
            digest_size +               // Digests
            size_of::<u32>(); // EventDataSize field

        if offset + data_size > current_element.len() {
            return None;
        }

        Some(&current_element[offset..offset + data_size])
    }

    /// Retrieves the current element's digest based on the log format and hash algorithm.
    ///
    /// # Description
    /// This function extracts the digest of the current element from a log entry.
    /// The behavior depends on the log format (`TREE_EVENT_LOG_FORMAT_TCG_1_2` or `TREE_EVENT_LOG_FORMAT_TCG_2`)
    /// and ensures that the digest aligns with the specified `hash_algorithm`.
    ///
    /// - For `TREE_EVENT_LOG_FORMAT_TCG_1_2`, it assumes the digest is based on the SHA-1 algorithm
    ///   and directly returns it after skipping the initial fields.
    /// - For `TREE_EVENT_LOG_FORMAT_TCG_2`, it processes multiple digests and finds the one
    ///   matching the `hash_algorithm`.
    ///
    /// # Returns
    /// - `Some(&[u8])`: A reference to the slice containing the digest if successfully extracted.
    /// - `None`: If there's any error or mismatch in extracting the digest (e.g., invalid offsets, unsupported algorithms).
    ///
    /// # Internal Operation
    /// 1. Determines the correct offset by skipping fields such as `PCRIndex` and `EventType`.
    /// 2. Handles both `TREE_EVENT_LOG_FORMAT_TCG_1_2` and `TREE_EVENT_LOG_FORMAT_TCG_2`:
    ///    - For `TREE_EVENT_LOG_FORMAT_TCG_1_2`:
    ///      - Assumes that the digest is a SHA-1 hash and returns it directly if within bounds.
    ///    - For `TREE_EVENT_LOG_FORMAT_TCG_2`:
    ///      - Parses the number of digests and iterates through them.
    ///      - Compares each digest's algorithm identifier with `hash_algorithm`.
    ///      - If a matching algorithm is found, it validates and returns the associated digest slice.
    /// 3. Carefully handles memory bounds, returning `None` in case of overflows or invalid data.
    ///
    /// # Parameters
    /// - `&self`: A reference to the context containing the log and configuration.
    ///   Key fields used:
    ///   - `self.current_element_ptr`: The pointer to the current log element (`Option<&'a [u8]>`).
    ///   - `self.log_format`: Indicates the format of the log (`TREE_EVENT_LOG_FORMAT_TCG_1_2` or `TREE_EVENT_LOG_FORMAT_TCG_2`).
    ///   - `self.hash_algorithm`: The target hashing algorithm to find the matching digest.
    ///   - `self.digest_size`: The size of the digest for the `hash_algorithm`.
    ///
    /// # Preconditions
    /// - The `self.current_element_ptr` must point to a valid element in the log.
    /// - Offsets and sizes derived from the log structure must be within valid bounds.
    /// - The `log_format` must be one of the supported formats (`TREE_EVENT_LOG_FORMAT_TCG_1_2` or `TREE_EVENT_LOG_FORMAT_TCG_2`).
    ///
    /// # Limitations
    /// - The function assumes SHA-1 for `TREE_EVENT_LOG_FORMAT_TCG_1_2`.
    /// - For `TREE_EVENT_LOG_FORMAT_TCG_2`, it supports only up to `MAX_NUMBER_OF_DIGESTS`.
    /// - Invalid or unsupported digest algorithms are ignored, and the function continues to search for a match.
    ///
    /// # Example Usage
    /// Assume a log element with the appropriate structure is loaded into `self.current_element_ptr`.
    /// ```
    /// let digest = instance.get_current_element_digest();
    /// if let Some(digest) = digest {
    ///     println!("Successfully extracted digest: {:?}", digest);
    /// } else {
    ///     println!("Failed to extract digest.");
    /// }
    /// ```
    ///
    /// # Errors
    /// - Returns `None` if the log structure is inconsistent, invalid, or out-of-bounds.
    /// - Returns `None` if no matching digest for `hash_algorithm` is found.
    ///
    /// # Related Constants
    /// - `SHA1_DIGEST_SIZE`: The size of the SHA-1 digest.
    /// - `MAX_NUMBER_OF_DIGESTS`: The maximum allowable number of digests.
    /// - `TREE_EVENT_LOG_FORMAT_TCG_1_2`: Log format for SHA-1-based logs.
    /// - `TREE_EVENT_LOG_FORMAT_TCG_2`: Log format supporting multiple algorithms.
    ///
    /// # Safety and Validation
    /// - Ensures all offsets and sizes are validated to prevent out-of-bounds memory access.
    /// - Guards against excessive memory access by respecting the length of `current_element`.
    pub fn get_current_element_digest(&self) -> Option<&'a [u8]> {
        let current_element = self.current_element_ptr?;

        // Move past PCRIndex and EventType
        let mut offset = 2 * size_of::<u32>();

        if self.log_format == TREE_EVENT_LOG_FORMAT_TCG_1_2 as u16 {
            // For SHA-1 log format, return the digest directly
            let digest_end = offset + SHA1_DIGEST_SIZE as usize;
            if digest_end <= current_element.len() {
                return Some(&current_element[offset..digest_end]);
            }
            return None;
        }

        if self.log_format == TREE_EVENT_LOG_FORMAT_TCG_2 as u16 {
            if offset + size_of::<u32>() > current_element.len() {
                return None;
            }

            let number_of_digests = u32::from_le_bytes([
                current_element[offset],
                current_element[offset + 1],
                current_element[offset + 2],
                current_element[offset + 3],
            ]);
            offset += size_of::<u32>();

            if number_of_digests > MAX_NUMBER_OF_DIGESTS {
                return None;
            }

            for _ in 0..number_of_digests {
                if offset + size_of::<WbclDigestAlgId>() > current_element.len() {
                    return None;
                }

                let current_algorithm = WbclDigestAlgId::from_le_bytes([
                    current_element[offset],
                    current_element[offset + 1],
                ]);
                offset += size_of::<WbclDigestAlgId>();

                if current_algorithm == self.hash_algorithm {
                    let digest_size = self.digest_size as usize;
                    if offset + digest_size <= current_element.len() {
                        return Some(&current_element[offset..offset + digest_size]);
                    }
                    return None;
                }

                // Move past this digest
                let current_digest_size = self.get_digest_size(current_algorithm) as usize;
                offset += current_digest_size;

                if offset > current_element.len() {
                    return None;
                }
            }
        }

        None
    }

    /// Retrieves the current element from the internal state or data structure.
    ///
    /// This function extracts various components of the current element, such as
    /// the PCR index, event type, digest, data size, and the data itself. The
    /// function expects the `current_element` buffer to contain at least enough
    /// bytes for two `u32` integers (PCR index and event type) and validates this
    /// requirement. On success, it returns a tuple containing these components.
    ///
    /// # Returns
    ///
    /// - `Ok((u32, u32, Option<&'a [u8]>, u32, Option<&'a [u8]>))`:
    ///   - `u32`: The PCR index extracted from the current element.
    ///   - `u32`: The event type extracted from the current element.
    ///   - `Option<&'a [u8]>`: A reference to the digest, if present, associated with the current element.
    ///   - `u32`: The size of the element data.
    ///   - `Option<&'a [u8]>`: A reference to the element data, if present.
    /// - `Err(u32)`: An error code, where `E_INVALIDARG` (non-zero value) indicates that the internal
    ///   `current_element` pointer is `None` or the buffer is too small to retrieve valid data.
    ///
    /// # Errors
    ///
    /// This method can return an error in the following cases:
    /// - The `current_element_ptr` is `None`, leading to an invalid argument error (`E_INVALIDARG`).
    /// - The buffer length of `current_element` is smaller than the required size (2 * `size_of::<u32>()`).
    /// - Any additional error arising from helper functions (`get_current_element_data_size` or `get_current_element_data`).
    ///
    /// # Panics
    ///
    /// This function will not panic as long as the internal helpers (`get_current_element_digest`,
    /// `get_current_element_data_size`, and `get_current_element_data`) behave as expected.
    ///
    /// # Example
    ///
    /// ```
    /// let result = my_object.get_current_element();
    /// match result {
    ///     Ok((pcr_index, event_type, digest, data_size, data)) => {
    ///         println!("PCR Index: {}", pcr_index);
    ///         println!("Event Type: {}", event_type);
    ///     },
    ///     Err(err_code) => {
    ///         eprintln!("Error retrieving current element: {}", err_code);
    ///     }
    /// }
    /// ```
    pub fn get_current_element(
        &self,
    ) -> Result<(u32, u32, Option<&'a [u8]>, u32, Option<&'a [u8]>), u32> {
        let current_element = self.current_element_ptr.ok_or(E_INVALIDARG)?;

        if current_element.len() < 2 * size_of::<u32>() {
            return Err(E_INVALIDARG);
        }

        let pcr_index = u32::from_le_bytes([
            current_element[0],
            current_element[1],
            current_element[2],
            current_element[3],
        ]);

        let event_type = u32::from_le_bytes([
            current_element[4],
            current_element[5],
            current_element[6],
            current_element[7],
        ]);

        let digest = self.get_current_element_digest();
        let element_data_size = self.get_current_element_data_size()?;
        let element_data = self.get_current_element_data();

        Ok((
            pcr_index,
            event_type,
            digest,
            element_data_size,
            element_data,
        ))
    }

    /// Moves the current element pointer to the next element in the data structure.
    ///
    /// This function calculates the position of the next element based on the current element's
    /// pointer and size. It performs validation to ensure that the calculated position is within
    /// bounds and the next element meets the minimum size requirements. If successful, the function
    /// updates the `current_element_ptr` and `current_element_size` to point to the next element.
    ///
    /// # Returns
    /// * `Ok(())` - If the next element is successfully set and valid.
    /// * `Err(u32)` - If the operation fails, typically returning the error code `S_FALSE`.
    ///
    /// # Errors
    /// This function may return an error in the following cases:
    /// 1. If there is no current element (`self.current_element_ptr` is `None`).
    /// 2. If the `current_element_size` is zero.
    /// 3. If the calculated next element position exceeds the bounds of `self.first_element_ptr`.
    /// 4. If the calculated next element does not satisfy the minimum size requirement.
    /// 5. If the next element's size exceeds the remaining bounds of `self.first_element_ptr`.
    ///
    /// # Implementation Details
    /// - The function derives the positional offset of the next element by considering the size
    ///   of the current element and its offset relative to the start of `self.first_element_ptr`.
    /// - Minimum size requirements depend on the value of `log_format`. Specifically:
    ///   - For `TREE_EVENT_LOG_FORMAT_TCG_2`, the minimum size adjusts based on specific
    ///     field sizes and `self.digest_size`.
    ///   - For other formats, a default minimum size is calculated.
    /// - If the validation checks fail at any step, the function sets `self.current_element_ptr`
    ///   and `self.current_element_size` to `None` and `0` respectively and returns an error.
    ///
    /// # Preconditions
    /// - `self.first_element_ptr` must be a correctly initialized slice of data.
    /// - `self.current_element_ptr` must point to a valid portion of `self.first_element_ptr`
    ///   or be `None`.
    ///
    /// # Side Effects
    /// Updates the following fields if successful:
    /// - `self.current_element_ptr`: Points to the slice of the new current element.
    /// - `self.current_element_size`: Stores the size of the new current element.
    ///
    /// # Example
    /// ```
    /// let mut parser = MyElementParser::new();
    /// if let Err(err) = parser.move_to_next_element() {
    ///     eprintln!("Failed to move to the next element: {}", err);
    /// } else {
    ///     println!("Successfully moved to the next element");
    /// }
    /// ```
    pub fn move_to_next_element(&mut self) -> Result<(), u32> {
        let current_element = self.current_element_ptr.ok_or(S_FALSE)?;

        if self.current_element_size == 0 {
            return Err(S_FALSE);
        }

        // Calculate next element position
        let current_offset =
            current_element.as_ptr() as usize - self.first_element_ptr.as_ptr() as usize;
        let next_offset = current_offset + self.current_element_size as usize;

        if next_offset >= self.first_element_ptr.len() {
            self.current_element_ptr = None;
            self.current_element_size = 0;
            return Err(S_FALSE);
        }

        // Calculate minimum size for next element
        let minimum_size = if self.log_format == TREE_EVENT_LOG_FORMAT_TCG_2 as u16 {
            4 * mem::size_of::<u32>()
                + mem::size_of::<WbclDigestAlgId>()
                + self.digest_size as usize
        } else {
            3 * mem::size_of::<u32>() + SHA1_DIGEST_SIZE as usize
        };

        if next_offset + minimum_size > self.first_element_ptr.len() {
            self.current_element_ptr = None;
            self.current_element_size = 0;
            return Err(S_FALSE);
        }

        // Update current element pointer
        self.current_element_ptr = Some(&self.first_element_ptr[next_offset..]);

        // Get the size of the new current element
        let element_size = self.get_current_element_size()?;

        if next_offset + element_size as usize > self.first_element_ptr.len() {
            self.current_element_ptr = None;
            self.current_element_size = 0;
            return Err(S_FALSE);
        }

        self.current_element_size = element_size;
        Ok(())
    }

    /// Checks whether there is a next element available for processing.
    ///
    /// This function determines if the current pointer (`current_element_ptr`)
    /// points to a valid element and if the current element has a positive size.
    ///
    /// # Returns
    /// - `true` if there is a valid next element (i.e., `current_element_ptr` is `Some`
    ///   and `current_element_size > 0`).
    /// - `false` otherwise.
    ///
    /// # Examples
    /// ```
    /// let iterator = SomeIterator {
    ///     current_element_ptr: Some(42),
    ///     current_element_size: 5,
    /// };
    /// assert!(iterator.has_next());
    ///
    /// let iterator_empty = SomeIterator {
    ///     current_element_ptr: None,
    ///     current_element_size: 0,
    /// };
    /// assert!(!iterator_empty.has_next());
    /// ```
    ///
    /// # Notes
    /// This method relies on both the pointer being non-`None` and the size being
    /// greater than zero, providing a safeguard against empty or invalid states.
    pub fn has_next(&self) -> bool {
        self.current_element_ptr.is_some() && self.current_element_size > 0
    }
}

/// Initializes a WBCL (Windows Boot Configuration Log) iterator for iterating over the log entries
/// in the provided log buffer.
///
/// # Arguments
///
/// * `log_buffer` - A byte slice representing the WBCL data that needs to be parsed.
///
/// # Returns
///
/// Returns a `Result` containing either:
/// * A `WbclIterator` instance if the initialization is successful, or
/// * A `u32` error code if the initialization fails.
///
/// # Errors
///
/// If the provided `log_buffer` is invalid or there is an issue initializing the iterator,
/// this function will return a `u32` error code representing the failure reason.
///
/// # Example
///
/// ```rust
/// let log_buffer: &[u8] = &[/* some WBCL data */];
/// match wbcl_api_init_iterator(log_buffer) {
///     Ok(iterator) => {
///         // Use the iterator to parse WBCL entries
///     }
///     Err(error_code) => {
///         eprintln!("Failed to initialize WBCL iterator: {}", error_code);
///     }
/// }
/// ```
///
/// # Panics
///
/// This function does not panic under normal circumstances. Ensure the input buffer
/// is valid to avoid any runtime errors.
pub fn wbcl_api_init_iterator(log_buffer: &[u8]) -> Result<WbclIterator<'_>, u32> {
    WbclIterator::new(log_buffer)
}

/// Retrieves the current element from a Windows Boot Configuration Log (WBCL) iterator.
///
/// This function provides a safe and convenient way to access the current
/// element in the WBCL iterator. It delegates the call to the `get_current_element`
/// method of the underlying `WbclIterator`.
///
/// # Parameters
///
/// - `iterator`: A reference to a `WbclIterator` instance from which the current element
///   will be retrieved. The lifetime of the returned data is tied to the lifetime of this
///   iterator reference.
///
/// # Returns
///
/// - `Ok((element_type, element_size, element_data, context_size, context_data))`:
///   On success, returns the following tuple:
///   * `element_type` (`u32`): The type identifier of the WBCL element.
///   * `element_size` (`u32`): The size of the WBCL element in bytes.
///   * `element_data` (`Option<&[u8]>`): An optional slice containing the data of the WBCL element.
///   * `context_size` (`u32`): The size of the associated context in bytes.
///   * `context_data` (`Option<&[u8]>`): An optional slice containing the context information of the WBCL element.
///
/// - `Err(error_code)`: On failure, returns an error code (`u32`) indicating the failure reason.
///
/// # Type Parameters
///
/// - `'a`: The lifetime of the `iterator` and any associated data returned by the function.
///
/// # Example
///
/// ```
/// let result = wbcl_api_get_current_element(&wbcl_iterator);
/// match result {
///     Ok((element_type, element_size, element_data, context_size, context_data)) => {
///         println!("Element Type: {}", element_type);
///         println!("Element Size: {}", element_size);
///         if let Some(data) = element_data {
///             println!("Element Data: {:?}", data);
///         }
///         println!("Context Size: {}", context_size);
///         if let Some(context) = context_data {
///             println!("Context Data: {:?}", context);
///         }
///     },
///     Err(error_code) => {
///         println!("Failed to get the current element. Error code: {}", error_code);
///     },
/// }
/// ```
///
/// # Notes
///
/// - This function assumes `iterator` is valid and properly initialized before calling.
/// - The returned slices, if present, will have the same lifetime as the provided iterator.
/// - Ensure proper error handling as errors are represented by the returned error code.
///
/// # Errors
///
/// This function returns an error (`Err(u32)`) in the following scenarios:
/// - If no current element exists in the iterator.
/// - If the iterator encounters internal issues during retrieval.
///
/// # Safety
///
/// This function does not modify the state of the iterator, ensuring read-only operations.
///
/// # See Also
///
/// - [`WbclIterator::get_current_element`]: The method this function delegates to for
///   fetching the current element data.
pub fn wbcl_api_get_current_element<'a>(
    iterator: &'a WbclIterator<'a>,
) -> Result<(u32, u32, Option<&'a [u8]>, u32, Option<&'a [u8]>), u32> {
    iterator.get_current_element()
}

/// Advances the given `WbclIterator` to the next element in the sequence.
///
/// This function attempts to move the iterator to the next element,
/// utilizing the `move_to_next_element` method on the provided `WbclIterator`.
///
/// # Arguments
/// - `iterator`: A mutable reference to a `WbclIterator` instance.
///
/// # Returns
/// - `Ok(())`: If the iterator successfully moves to the next element.
/// - `Err(u32)`: If there is an error moving to the next element. The `u32` value indicates the specific error code.
///
/// # Examples
/// ```
/// let mut iterator = WbclIterator::new();
/// match wbcl_api_move_to_next_element(&mut iterator) {
///     Ok(()) => println!("Successfully moved to the next element."),
///     Err(code) => eprintln!("Error occurred with code: {}", code),
/// }
/// ```
///
/// # Notes
/// Ensure the iterator is properly initialized before calling this function.
/// Any errors returned are dependent on the implementation of `WbclIterator::move_to_next_element`.
///
pub fn wbcl_api_move_to_next_element(iterator: &mut WbclIterator) -> Result<(), u32> {
    iterator.move_to_next_element()
}

