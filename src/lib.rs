//! TCG log parsing functionality for WBCL (Windows Boot Configuration Log)
//!
//! This module provides an API surface for parsing and iterating through TCG event logs.
//! It supports both TCG 1.2 (SHA-1 only) and TCG 2.0 (crypto-agile) formats.

mod collector;

use std::collections::HashMap;
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

const WBCL_DIGEST_ALG_ID_SHA_1: WbclDigestAlgId = 0x0004;
const WBCL_DIGEST_ALG_ID_SHA_2_256: WbclDigestAlgId = 0x000B;
const WBCL_DIGEST_ALG_ID_SHA_2_384: WbclDigestAlgId = 0x000C;
const WBCL_DIGEST_ALG_ID_SHA_2_512: WbclDigestAlgId = 0x000D;
const WBCL_DIGEST_ALG_ID_SM3_256: WbclDigestAlgId = 0x0012;
const WBCL_DIGEST_ALG_ID_SHA3_256: WbclDigestAlgId = 0x0027;
const WBCL_DIGEST_ALG_ID_SHA3_384: WbclDigestAlgId = 0x0028;
const WBCL_DIGEST_ALG_ID_SHA3_512: WbclDigestAlgId = 0x0029;

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
    first_element_ptr: &'a [u8],
    log_size: u32,
    current_element_ptr: Option<&'a [u8]>,
    current_element_size: u32,
    digest_size: u16,
    log_format: u16,
    number_of_digests: u32,
    digest_sizes: Option<&'a [TcgEfiSpecIdEventAlgorithmSize]>,
    hash_algorithm: WbclDigestAlgId,
}

impl<'a> WbclIterator<'a> {
    /// Create a new WBCL iterator from a log buffer
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

    /// Get the current element's data
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

    /// Get the current element's digest for the selected hash algorithm
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

    /// Get information about the current log element
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

    /// Move to the next element in the log
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

    /// Check if there are more elements to process
    pub fn has_next(&self) -> bool {
        self.current_element_ptr.is_some() && self.current_element_size > 0
    }
}

/// Initialize a WBCL iterator from a log buffer
pub fn wbcl_api_init_iterator(log_buffer: &[u8]) -> Result<WbclIterator<'_>, u32> {
    WbclIterator::new(log_buffer)
}

/// Get the current element from the iterator
pub fn wbcl_api_get_current_element<'a>(
    iterator: &'a WbclIterator<'a>,
) -> Result<(u32, u32, Option<&'a [u8]>, u32, Option<&'a [u8]>), u32> {
    iterator.get_current_element()
}

/// Move the iterator to the next element
pub fn wbcl_api_move_to_next_element(iterator: &mut WbclIterator) -> Result<(), u32> {
    iterator.move_to_next_element()
}

pub struct DigestRecords {
    digest: Option<Vec<u8>>,
    digest_string: Option<String>,
}

pub struct EventRecord {
    name: String,
    group: String,
    pcr_index: u32,
    event_type: u32,
    digest_records: Vec<DigestRecords>,
    data: Option<Vec<u8>>,
    raw_data: Option<Vec<u8>>,
}

pub struct Collector {
    events: Option<Vec<EventRecord>>,
    file_buffer: Option<Vec<u8>>,
}
// First, let's define the algorithm translation structure
#[derive(Debug, Clone)]
struct AlgTranslation {
    alg_name: String,
    alg_size: i32,
}

use once_cell::sync::Lazy;

static M_ALG_TRANS_ONCE: Lazy<HashMap<WbclDigestAlgId, AlgTranslation>> = Lazy::new(|| {
    HashMap::from([
        (
            WBCL_DIGEST_ALG_ID_SHA_1,
            AlgTranslation {
                alg_name: "SHA-1".to_string(),
                alg_size: 20,
            },
        ),
        (
            WBCL_DIGEST_ALG_ID_SHA_2_256,
            AlgTranslation {
                alg_name: "SHA-256".to_string(),
                alg_size: 32,
            },
        ),
        (
            WBCL_DIGEST_ALG_ID_SHA_2_384,
            AlgTranslation {
                alg_name: "SHA-384".to_string(),
                alg_size: 48,
            },
        ),
        (
            WBCL_DIGEST_ALG_ID_SHA_2_512,
            AlgTranslation {
                alg_name: "SHA-512".to_string(),
                alg_size: 64,
            },
        ),
        (
            WBCL_DIGEST_ALG_ID_SHA3_256,
            AlgTranslation {
                alg_name: "SHA3-256".to_string(),
                alg_size: 32,
            },
        ),
        (
            WBCL_DIGEST_ALG_ID_SHA3_384,
            AlgTranslation {
                alg_name: "SHA3-384".to_string(),
                alg_size: 48,
            },
        ),
        (
            WBCL_DIGEST_ALG_ID_SHA3_512,
            AlgTranslation {
                alg_name: "SHA3-512".to_string(),
                alg_size: 64,
            },
        ),
        (
            WBCL_DIGEST_ALG_ID_SM3_256,
            AlgTranslation {
                alg_name: "SM3-256".to_string(),
                alg_size: 32,
            },
        ),
    ])
});

impl Collector {
    pub fn hex_convert(buffer: &[u8]) -> String {
        let mut result = String::new();
        for c in buffer {
            result.push_str(&format!("{:02x}", *c));
        }
        result
    }

    fn parse(buffer: &[u8]) -> Result<Vec<EventRecord>, String> {
        let mut events: Vec<EventRecord> = Vec::new();

        let table = [
            WBCL_DIGEST_ALG_ID_SHA_1,
            WBCL_DIGEST_ALG_ID_SHA_2_256,
            WBCL_DIGEST_ALG_ID_SHA_2_384,
            WBCL_DIGEST_ALG_ID_SHA_2_512,
            WBCL_DIGEST_ALG_ID_SHA3_256,
            WBCL_DIGEST_ALG_ID_SHA3_384,
            WBCL_DIGEST_ALG_ID_SHA3_512,
            WBCL_DIGEST_ALG_ID_SM3_256,
        ];

        if let Ok(mut result) = wbcl_api_init_iterator(&buffer) {
            //println!("wbcl format {}", result.log_format);
            while result.has_next() {
                if let Ok(_) = wbcl_api_move_to_next_element(&mut result) {
                    let mut active_record = EventRecord {
                        name: "".to_string(),
                        group: "".to_string(),
                        pcr_index: 0,
                        event_type: 0,
                        digest_records: Vec::new(),
                        data: None,
                        raw_data: None,
                    };

                    for i in table.iter() {
                        if let Some(hash_info) = M_ALG_TRANS_ONCE.get(i) {
                            //println!("{}: {} bytes", hash_info.alg_name, hash_info.alg_size);
                            result.hash_algorithm = *i;
                            result.digest_size = hash_info.alg_size as u16;

                            if let Ok(element) = wbcl_api_get_current_element(&result) {
                                if element.2.is_some() {
                                    active_record.pcr_index = element.0;
                                    active_record.event_type = element.1;
                                    active_record.digest_records.push(DigestRecords {
                                        digest: Some(element.2.unwrap().to_vec()),
                                        digest_string: Some(Self::hex_convert(&element.2.unwrap())),
                                    });

                                    if active_record.data.is_none() {
                                        active_record.data = Some(element.4.unwrap().to_vec());
                                        active_record.raw_data =
                                            Some(result.current_element_ptr.unwrap().to_vec());
                                    }
                                }
                            }
                        }
                    }

                    //println!("pcr: {} event: {:x}", element.0, element.1);
                    events.push(active_record);
                /*
                events.push(EventRecord {
                    name: "".to_string(),
                    group: "".to_string(),
                    pcr_index: element.0,
                    event_type: element.1,
                    digest: if element.2.is_some() {
                        Some(element.2.unwrap().to_vec())
                    } else {
                        None
                    },
                    digest_string: if element.2.is_some() {
                        Some(Self::hex_convert(&element.2.unwrap()))
                    } else {
                        None
                    },
                    data: if element.3 > 0 {
                        Some(element.4.unwrap().to_vec())
                    } else {
                        None
                    },
                    raw_data: Some(result.current_element_ptr.unwrap().to_vec()),
                })

                 */
                } else {
                    break;
                }
            }
            return Ok(events);
        }

        Err("failed to parse input file".to_string())
    }
    pub fn new(tcg_log: String) -> Result<Self, String> {
        if let Ok(buffer) = std::fs::read(tcg_log) {
            if let Ok(parse_result) = Self::parse(&buffer) {
                return Ok(Self {
                    events: Some(parse_result),
                    file_buffer: Some(buffer),
                });
            }
        }

        Err("failed to load input file".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_buffer() {
        let buffer = [];
        let result = WbclIterator::new(&buffer);
        assert!(result.is_err());
        //assert_eq!(result.unwrap_err(), E_INVALIDARG);
    }

    #[test]
    fn test_invalid_log_format() {
        let buffer = vec![0u8; 1024];
        let result = WbclIterator::new(&buffer);
        assert!(result.is_err());
    }

    /*
    #[test]
    fn test_load_file() {
        let buffer = std::fs::read("D://temp//markus.log").unwrap();
        if let Ok(mut result) = wbcl_api_init_iterator(&buffer) {
            println!("wbcl format {}", result.log_format);
            while result.has_next() {
                if let Ok(_) = wbcl_api_move_to_next_element(&mut result) {
                    let element = wbcl_api_get_current_element(&result).unwrap();
                    println!("pcr: {} event: {:x}", element.0, element.1);
                } else {
                    println!("end of log")
                }
            }
        }
    }

     */
    #[test]
    fn test_load_file_2() {
        println!("test");
        if let Ok(collection) = Collector::new("D://temp//markus.log".to_string()) {
            if collection.events.is_some() {
                for event in collection.events.unwrap() {
                    println!("pcr: {:8x} event: {:8x}", event.pcr_index, event.event_type,);
                }
            }
        } else {
            println!("failed to load file");
        }
    }
}
