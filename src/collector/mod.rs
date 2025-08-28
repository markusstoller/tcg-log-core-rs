mod event_defines;

use crate::wbcl::*;
use once_cell::sync::Lazy;
use std::collections::HashMap;
pub use crate::collector::event_defines::*;


/// The `Collector` struct is designed to aggregate and manage data, particularly event records
/// and file contents. It provides storage for event logs and temporary file data, allowing
/// future operations or processing.
///
/// Fields:
///
/// - `events`: An optional `Vec` of `EventRecord` objects.
///   This field is used to store a collection of event logs. If no event logs
///   are currently stored, it will be set to `None`.
///
/// - `file_buffer`: An optional `Vec<u8>`.
///   This field is used to store a buffer of bytes, typically representing the content
///   of a file. If no file data is present, it will be set to `None`.
///
/// Usage:
///
/// The `Collector` struct can be used to accumulate and manage different kinds of data
/// structures during runtime, providing a flexible way to temporarily store data before
/// processing or output. Initialization and mutation of its fields depend on the
/// specific requirements of the application or system.
///
/// Example:
/// ```rust
/// use crate::Collector;
///
/// let mut collector = Collector {
///     events: Some(vec![]),
///     file_buffer: None,
/// };
///
/// // Add events or manipulate buffer as needed
/// ```
pub struct Collector {
    events: Option<Vec<EventRecord>>,
    file_buffer: Option<Vec<u8>>,
}

/// `AlgTranslation` is a simple data structure representing a cryptographic algorithm's
/// name and its corresponding size.
///
/// # Fields
///
/// * `alg_name` - A `String` representing the name of the algorithm.
/// * `alg_size` - An `i32` representing the size of the algorithm, typically indicating
///   the key size or other relevant metric, depending on the context.
///
/// # Attributes
///
/// * `#[derive(Debug, Clone)]` - Automatically implements the `Debug` trait, allowing you to
///   print the structure using the `{:?}` formatter, and the `Clone` trait, enabling
///   easy duplication of the structure.
///
/// # Example
///
/// ```
/// let translation = AlgTranslation {
///     alg_name: String::from("AES"),
///     alg_size: 256,
/// };
///
/// println!("{:?}", translation);
/// ```
#[derive(Debug, Clone)]
struct AlgTranslation {
    alg_name: String,
    alg_size: i32,
}

/// A lazily-initialized static variable containing a mapping of `WbclDigestAlgId` constants
/// to their corresponding `AlgTranslation` structures. Each `WbclDigestAlgId` is associated
/// with its human-readable algorithm name (`alg_name`) and the fixed output size of the
/// digest algorithm in bytes (`alg_size`).
///
/// This mapping is constructed once and remains available for the lifetime of the program.
///
/// The following digest algorithms are included:
/// - `WBCL_DIGEST_ALG_ID_SHA_1` -> Maps to the SHA-1 algorithm with an output size of 20 bytes.
/// - `WBCL_DIGEST_ALG_ID_SHA_2_256` -> Maps to the SHA-256 algorithm with an output size of 32 bytes.
/// - `WBCL_DIGEST_ALG_ID_SHA_2_384` -> Maps to the SHA-384 algorithm with an output size of 48 bytes.
/// - `WBCL_DIGEST_ALG_ID_SHA_2_512` -> Maps to the SHA-512 algorithm with an output size of 64 bytes.
/// - `WBCL_DIGEST_ALG_ID_SHA3_256` -> Maps to the SHA3-256 algorithm with an output size of 32 bytes.
/// - `WBCL_DIGEST_ALG_ID_SHA3_384` -> Maps to the SHA3-384 algorithm with an output size of 48 bytes.
/// - `WBCL_DIGEST_ALG_ID_SHA3_512` -> Maps to the SHA3-512 algorithm with an output size of 64 bytes.
/// - `WBCL_DIGEST_ALG_ID_SM3_256` -> Maps to the SM3-256 algorithm with an output size of 32 bytes.
///
/// # Examples
///
/// Accessing the algorithm translation:
/// ```
/// let sha256_translation = M_ALG_TRANS_ONCE.get(&WBCL_DIGEST_ALG_ID_SHA_2_256);
/// if let Some(translation) = sha256_translation {
///     assert_eq!(translation.alg_name, "SHA-256");
///     assert_eq!(translation.alg_size, 32);
/// }
/// ```
///
/// # Notes
/// - The `std::collections::HashMap` and `std::lazy::Lazy` utilities are used to ensure
///   that the mapping is only initialized when first accessed, improving performance when
///   the map is not used.
/// - The `AlgTranslation` struct stores the human-readable algorithm name as a `String`
///   and its output size as an `usize`.
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

///
/// A constant array defining the supported digest algorithm identifiers.
///
/// This array contains the eight digest algorithms (hash functions) supported
/// by the application, represented by their respective `WbclDigestAlgId` enums.
/// These algorithms can be used for cryptographic operations such as
/// hashing and secure data verification.
///
/// Supported algorithms include:
/// - `WBCL_DIGEST_ALG_ID_SHA_1`: SHA-1, a cryptographic hash function producing a 160-bit hash.
/// - `WBCL_DIGEST_ALG_ID_SHA_2_256`: SHA-256, a member of the SHA-2 family producing a 256-bit hash.
/// - `WBCL_DIGEST_ALG_ID_SHA_2_384`: SHA-384, a member of the SHA-2 family producing a 384-bit hash.
/// - `WBCL_DIGEST_ALG_ID_SHA_2_512`: SHA-512, a member of the SHA-2 family producing a 512-bit hash.
/// - `WBCL_DIGEST_ALG_ID_SHA3_256`: SHA3-256, a member of the SHA-3 family producing a 256-bit hash.
/// - `WBCL_DIGEST_ALG_ID_SHA3_384`: SHA3-384, a member of the SHA-3 family producing a 384-bit hash.
/// - `WBCL_DIGEST_ALG_ID_SHA3_512`: SHA3-512, a member of the SHA-3 family producing a 512-bit hash.
/// - `WBCL_DIGEST_ALG_ID_SM3_256`: SM3-256, a cryptographic hash function standardized in China producing a 256-bit hash.
///
/// This predefined list is useful for applications requiring standardized
/// hashing algorithms for operations such as integrity checks and authentication.
///
/// Example:
/// ```
/// for algorithm in &SUPPORTED_DIGEST_ALGORITHMS {
///     println!("{:?}", algorithm);
/// }
/// ```
///
/// This list ensures consistent implementation of supported digest algorithms across the application.
///
const SUPPORTED_DIGEST_ALGORITHMS: [WbclDigestAlgId; 8] = [
    WBCL_DIGEST_ALG_ID_SHA_1,
    WBCL_DIGEST_ALG_ID_SHA_2_256,
    WBCL_DIGEST_ALG_ID_SHA_2_384,
    WBCL_DIGEST_ALG_ID_SHA_2_512,
    WBCL_DIGEST_ALG_ID_SHA3_256,
    WBCL_DIGEST_ALG_ID_SHA3_384,
    WBCL_DIGEST_ALG_ID_SHA3_512,
    WBCL_DIGEST_ALG_ID_SM3_256,
];

impl Collector {
    pub fn get_events(&self) -> Option<Vec<EventRecord>> {
        self.events.clone()
    }

    /// Converts a slice of bytes into a hexadecimal string representation.
    ///
    /// # Parameters:
    /// - `buffer`: A slice of bytes (`&[u8]`) to be converted into a hexadecimal string.
    ///
    /// # Returns:
    /// A `String` containing the hexadecimal representation of the bytes in the input slice.
    /// Each byte in the slice is converted into two lowercase hexadecimal characters.
    ///
    /// # Examples:
    /// ```rust
    /// let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    /// let hex_string = hex_convert(&bytes);
    /// assert_eq!(hex_string, "deadbeef");
    /// ```
    ///
    /// Each byte will be zero-padded to ensure it is represented by exactly two hexadecimal characters.
    pub fn hex_convert(buffer: &[u8]) -> String {
        let mut result = String::new();
        for c in buffer {
            result.push_str(&format!("{:02x}", *c));
        }
        result
    }

    /// Parses a byte buffer and extracts a vector of `EventRecord` objects.
    ///
    /// This function initializes an iterator to process the binary buffer, which is expected
    /// to conform to the `wbcl_api` specification. It iteratively navigates through elements
    /// in the buffer, processing and extracting meaningful `EventRecord` objects until no more
    /// elements are found or an error occurs.
    ///
    /// # Parameters
    /// - `buffer`: A reference to a byte slice containing the binary data to be parsed.
    ///
    /// # Returns
    /// - `Ok(Vec<EventRecord>)`: A vector of successfully parsed `EventRecord` objects.
    /// - `Err(String)`: An error message string if the initialization of the iterator fails or
    ///                  for other runtime errors during parsing.
    ///
    /// # Process
    /// 1. Initializes an iterator from the provided buffer using the `wbcl_api_init_iterator` function.
    /// 2. Iterates through all elements in the buffer using `wbcl_api_move_to_next_element` to
    ///    navigate to the next element.
    /// 3. Invokes `process_current_element` to extract and validate an `EventRecord` from the
    ///    current element if available.
    /// 4. Gathers all valid `EventRecord` objects in a vector, halting parsing on critical failures.
    ///
    /// # Errors
    /// - Returns an error string if the iterator initialization via `wbcl_api_init_iterator` fails.
    /// - Stops iterating further if `wbcl_api_move_to_next_element` encounters an issue.
    ///
    /// # Notes
    /// Any specific errors encountered during iteration or processing are intentionally
    /// skipped, and the function continues processing subsequent elements.
    ///
    /// # Example
    /// ```
    /// let buffer: &[u8] = /* Input binary data */;
    /// match parse(buffer) {
    ///     Ok(events) => {
    ///         for event in events {
    ///             println!("{:?}", event);
    ///         }
    ///     }
    ///     Err(err) => {
    ///         eprintln!("Failed to parse buffer: {}", err);
    ///     }
    /// }
    /// ```
    fn internal_parse(buffer: &[u8]) -> Result<Vec<EventRecord>, String> {
        let mut iterator =
            wbcl_api_init_iterator(buffer).map_err(|_| "failed to parse input file".to_string())?;

        let mut events: Vec<EventRecord> = Vec::new();

        while iterator.has_next() {
            if wbcl_api_move_to_next_element(&mut iterator).is_err() {
                break;
            }

            if let Some(event_record) = Self::process_current_element(&mut iterator) {
                events.push(event_record);
            }
        }

        Ok(events)
    }

    /// Processes the current element in the WbclIterator, iterating over all supported digest
    /// algorithms to accumulate digest records, and returns an `EventRecord` if applicable.
    ///
    /// # Arguments
    ///
    /// * `iterator` - A mutable reference to a `WbclIterator` from which the current element is processed.
    ///
    /// # Returns
    ///
    /// An `Option<EventRecord>`:
    /// * `Some(EventRecord)` - If one or more digest records are successfully processed and added to the event record.
    /// * `None` - If no digest records were processed.
    ///
    /// # Behavior
    ///
    /// 1. An empty event record is initialized using the `create_empty_event_record` method.
    /// 2. The function iterates over all algorithm IDs in the `SUPPORTED_DIGEST_ALGORITHMS` list.
    /// 3. For each algorithm ID, it attempts to process the algorithm using the `process_algorithm` function.
    ///    - If a digest record is successfully processed, it is pushed into the `digest_records` vector
    ///      of the active event record.
    /// 4. After processing all supported algorithms:
    ///    - If `digest_records` is empty, the function returns `None`.
    ///    - Otherwise, the populated event record is returned wrapped in `Some`.
    ///
    /// # Notes
    ///
    /// - It assumes that `SUPPORTED_DIGEST_ALGORITHMS` is a predefined constant list of supported algorithm IDs.
    /// - The `process_algorithm` function is expected to process a specific algorithm and return either `Some(digest_record)`
    ///   if successful or `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// let mut iterator = WbclIterator::new();
    /// if let Some(event_record) = process_current_element(&mut iterator) {
    ///     println!("Successfully processed an EventRecord with {} digest records.", event_record.digest_records.len());
    /// } else {
    ///     println!("No digest records were processed for the current element.");
    /// }
    /// ```
    fn process_current_element(iterator: &mut WbclIterator) -> Option<EventRecord> {
        let mut active_record = Self::create_empty_event_record();

        for &algorithm_id in SUPPORTED_DIGEST_ALGORITHMS.iter() {
            if let Some(digest_record) =
                Self::process_algorithm(iterator, algorithm_id, &mut active_record)
            {
                active_record.digest_records.push(digest_record);
            }
        }

        if active_record.digest_records.is_empty() {
            None
        } else {
            Some(active_record)
        }
    }

    /// Creates an empty `EventRecord` with default values.
    ///
    /// This function initializes a new `EventRecord` with empty or default fields.
    /// All fields are either set to empty values (e.g., empty strings, empty vectors)
    /// or their default zero-equivalent values.
    ///
    /// # Returns
    ///
    /// An `EventRecord` instance with the following initialized fields:
    /// - `name`: An empty `String`.
    /// - `group`: An empty `String`.
    /// - `pcr_index`: `0` (default numeric value).
    /// - `event_type`: `0` (default numeric value).
    /// - `digest_records`: An empty `Vec`.
    /// - `data`: `None` (no associated optional data).
    /// - `raw_data`: `None` (no associated raw data).
    ///
    /// # Example
    ///
    /// ```rust
    /// let empty_event = create_empty_event_record();
    ///
    /// assert_eq!(empty_event.name, "");
    /// assert_eq!(empty_event.group, "");
    /// assert_eq!(empty_event.pcr_index, 0);
    /// assert_eq!(empty_event.event_type, 0);
    /// assert!(empty_event.digest_records.is_empty());
    /// assert!(empty_event.data.is_none());
    /// assert!(empty_event.raw_data.is_none());
    /// ```
    fn create_empty_event_record() -> EventRecord {
        EventRecord {
            name: "".to_string(),
            group: "".to_string(),
            pcr_index: 0,
            event_type: 0,
            digest_records: Vec::new(),
            data: None,
            raw_data: None,
        }
    }

    /// Processes the algorithm using the given iterator, algorithm ID, and updates the active record
    /// with relevant information.
    ///
    /// # Arguments
    ///
    /// * `iterator` - A mutable reference to a `WbclIterator` that traverses data for processing.
    /// * `algorithm_id` - A `WbclDigestAlgId` representing the specific algorithm being processed.
    /// * `active_record` - A mutable reference to an `EventRecord` that will store information about
    ///   the current processed event.
    ///
    /// # Returns
    ///
    /// This function returns an `Option<DigestRecords>`:
    /// * `Some(DigestRecords)` - Contains the digest data and its hex string representation if the operation
    ///   was successful and the required information is available.
    /// * `None` - If any step of the processing fails (e.g., the hash algorithm is not supported, current
    ///   element fetch fails, or necessary data is not available).
    ///
    /// # Behavior
    ///
    /// 1. Retrieves algorithm-specific information (`alg_size`) from the `M_ALG_TRANS_ONCE` map using `algorithm_id`.
    ///    If the ID is not found, the function returns `None`.
    /// 2. Updates the iterator's `hash_algorithm` and `digest_size` with the current algorithm's values.
    /// 3. Fetches the current processing element from the `wbcl_api_get_current_element` API.
    ///    - Extracts relevant data: `pcr_index`, `event_type`, digest, and possible raw data.
    /// 4. Updates the `active_record` with:
    ///    - `pcr_index`: Assigned from the current element.
    ///    - `event_type`: Assigned from the current element.
    ///    - If `active_record.data` is not yet initialized:
    ///      - Populates `data` with a vector of bytes (if available) from the current element.
    ///      - Populates `raw_data` with raw bytes from the element pointer (if available).
    /// 5. Constructs a `DigestRecords` instance if a valid digest is available:
    ///    - Includes the digest in byte form and its hex string representation (using `Self::hex_convert`).
    ///
    /// # Example
    ///
    /// ```rust
    /// // Assume `iterator`, `algorithm_id`, and `active_record` are predefined appropriately.
    /// let result = process_algorithm(&mut iterator, algorithm_id, &mut active_record);
    /// if let Some(digest_record) = result {
    ///     println!("Digest: {:?}", digest_record.digest_string.unwrap());
    /// } else {
    ///     println!("Processing algorithm failed or data unavailable");
    /// }
    /// ```
    ///
    /// # Dependencies
    ///
    /// * This function depends on the `M_ALG_TRANS_ONCE` map to retrieve the algorithm's properties.
    /// * Expects `wbcl_api_get_current_element` to fetch the current element being processed.
    /// * Uses helper method `hex_convert` to convert digest data into a hex string.
    ///
    /// # Notes
    ///
    /// * The mutable references to `iterator` and `active_record` will directly modify their contents
    ///   during the function execution.
    /// * Proper error handling is implemented; any failed API call or missing data will result in `None`.
    ///
    fn process_algorithm(
        iterator: &mut WbclIterator,
        algorithm_id: WbclDigestAlgId,
        active_record: &mut EventRecord,
    ) -> Option<DigestRecords> {
        let hash_info = M_ALG_TRANS_ONCE.get(&algorithm_id)?;

        iterator.hash_algorithm = algorithm_id;
        iterator.digest_size = hash_info.alg_size as u16;

        let element = wbcl_api_get_current_element(iterator).ok()?;
        let (pcr_index, event_type, digest_opt, _, data_opt) = element;

        let digest = digest_opt?;

        active_record.pcr_index = pcr_index;
        active_record.event_type = event_type;

        if active_record.data.is_none() {
            active_record.data = data_opt.map(|d| d.to_vec());
            active_record.raw_data = iterator.current_element_ptr.map(|ptr| ptr.to_vec());
        }

        Some(DigestRecords {
            digest_type: hash_info.alg_name.to_string(),
            digest: Some(digest.to_vec()),
            digest_string: Some(Self::hex_convert(digest)),
        })
    }

    /// Parses a TCG log file and returns a vector of `EventRecord` or an error message.
    ///
    /// This function takes the path to a Trusted Computing Group (TCG) log file as input,
    /// attempts to read its content, and parses the contents into a vector of `EventRecord` objects.
    /// If the file cannot be read, an error message will be returned.
    ///
    /// # Arguments
    ///
    /// * `tcg_log` - A `String` representing the path to the TCG log file to be parsed.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<EventRecord>)` - If the file is successfully read and parsed, returns a vector of parsed `EventRecord` objects.
    /// * `Err(String)` - If the file could not be loaded, returns an error message as a `String`.
    ///
    /// # Errors
    ///
    /// This function returns an error in the following scenarios:
    ///
    /// * The file specified by the `tcg_log` path cannot be read (e.g., due to the file not existing,
    ///   missing permissions, or any other IO-related issues).
    ///
    /// # Examples
    ///
    /// ```rust
    /// let log_path = String::from("path/to/tcg_log_file");
    /// match parse(log_path) {
    ///     Ok(event_records) => {
    ///         for event in event_records {
    ///             println!("{:?}", event);
    ///         }
    ///     },
    ///     Err(error_msg) => {
    ///         eprintln!("Error: {}", error_msg);
    ///     }
    /// }
    /// ```
    pub fn parse(&self, tcg_log: String) -> Result<Vec<EventRecord>, String> {
        if let Ok(buffer) = std::fs::read(tcg_log) {
            return Self::internal_parse(&buffer);
        }

        Err("failed to load input file".to_string())
    }
    /// Creates a new instance of the struct with default values.
    ///
    /// # Returns
    /// A new instance of the struct with the following properties:
    /// - `events`: Set to `None`, indicating no events are initialized.
    /// - `file_buffer`: Set to `None`, indicating no file buffer is initialized.
    ///
    /// # Example
    /// ```
    /// let instance = StructName::new();
    /// assert!(instance.events.is_none());
    /// assert!(instance.file_buffer.is_none());
    /// ```
    pub fn new() -> Self {
        Self {
            events: None,
            file_buffer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::format;
    use std::ops::Add;

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
}
