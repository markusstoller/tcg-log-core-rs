/// The `DigestRecords` struct holds information about a digest, including its type,
/// the raw digest data as a byte array, and the digest as a string representation.
///
/// # Fields
/// - `digest_type` (`String`):
///   A string indicating the type of digest (e.g., SHA256, MD5).
///
/// - `digest` (`Option<Vec<u8>>`):
///   An optional vector of bytes containing the raw digest data.
///   If `None`, the digest data may not be available or applicable.
///
/// - `digest_string` (`Option<String>`):
///   An optional string representation of the digest. This is typically a
///   hexadecimal or base64-encoded version of the `digest` field.
///   If `None`, the string representation may not be available or applicable.
#[derive(Debug, Clone)]
pub struct DigestRecords {
    pub digest_type: String,
    pub digest: Option<Vec<u8>>,
    pub digest_string: Option<String>,
}

/// Represents a record of an event with details related to its metadata and associated data.
///
/// This structure captures information about an event that has been recorded, such as its name,
/// its associated group, platform configuration register (PCR) index, event type, cryptographic
/// digest records, and optional event data.
///
/// # Fields
///
/// - `name`:
///   A descriptive name for the event.
///
/// - `group`:
///   The group or category to which the event belongs.
///
/// - `pcr_index`:
///   The index of the Platform Configuration Register (PCR) associated with this event.
///   PCRs are used for storing measurements in trusted environments (e.g., TPM).
///
/// - `event_type`:
///   An identifier representing the type of event. This can be used to classify the event
///   or understand what kind of action triggered it.
///
/// - `digest_records`:
///   A collection of cryptographic digest records associated with the event. These represent
///   hashed measurements that are linked to the integrity of the event data.
///
/// - `data`:
///   Optional data payload of the event. This contains additional context or information
///   associated with the event, stored as a vector of bytes. It is optional and may be `None`
///   if no additional data is present.
///
/// - `raw_data`:
///   Optional raw data payload of the event. This may store raw or unprocessed data in
///   the form of a vector of bytes. Like `data`, this field is optional and may
///   also be `None`.
///
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub name: String,
    pub group: String,
    pub pcr_index: u32,
    pub event_type: u32,
    pub digest_records: Vec<DigestRecords>,
    pub data: Option<Vec<u8>>,
    pub raw_data: Option<Vec<u8>>,
}