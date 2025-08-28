mod collector;
mod wbcl;

use crate::collector::Collector;
pub use crate::collector::EventRecord;

/// Parses the content of the given input file and returns a vector of `EventRecord` objects.
///
/// # Arguments
///
/// * `input_file` - A string slice that represents the path to the input file to be parsed.
///
/// # Returns
///
/// * `Ok(Vec<EventRecord>)` - A vector containing the parsed `EventRecord` objects if the parsing is successful.
/// * `Err(String)` - An error message describing the failure if the parsing fails.
///
/// # Errors
///
/// Returns an error if:
/// * The file cannot be read.
/// * The content of the file cannot be parsed into `EventRecord` objects.
///
/// # Example
///
/// ```
/// let input_file = "path/to/input/file.txt";
/// match parse(input_file) {
///     Ok(events) => {
///         println!("Parsed events: {:?}", events);
///     }
///     Err(err) => {
///         eprintln!("Error parsing file: {}", err);
///     }
/// }
/// ```
pub fn parse(input_file: &str) -> Result<Vec<EventRecord>, String> {
    let col = Collector::new();
    col.parse(input_file.to_string())
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let result = parse("D:/temp/markus.log");
    }
}
*/