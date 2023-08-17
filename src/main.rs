use std::{
    fmt,                           // Import formatting traits and structs
    io::{self, Write},              // Import input/output modules
    str::FromStr,                   // Import trait for converting strings to other types
};

use crc::{Crc, CRC_32_JAMCRC};      // Import CRC library for checksum calculations

// Define a struct to represent a RecoveryKey, containing a u64 value
#[derive(Clone, Copy)]
struct RecoveryKey(u64);

// Implement methods for the RecoveryKey struct
impl RecoveryKey {
    // Calculate a password based on the RecoveryKey using CRC checksum
    pub fn calculate_password(&self) -> String {
        let crc = Crc::<u32>::new(&CRC_32_JAMCRC);

        let s = format!("{:016x}", self.0);
        let res = crc.checksum(s.as_bytes());
        format!("{res:x}")  // Return the calculated password
    }
}

// Implement the FromStr trait to allow parsing of a RecoveryKey from a string
impl FromStr for RecoveryKey {
    type Err = InvalidKey;  // Define the associated error type for parsing

    // Parsing logic for RecoveryKey
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('-');  // Split the input string by hyphens

        // Check if the first part is "203c", else return an InvalidKey error
        if split.next() != Some("203c") {
            return Err(InvalidKey);
        }

        // Check if the second part is "d001", else return an InvalidKey error
        if split.next() != Some("d001") {
            return Err(InvalidKey);
        }

        let mut res = 0u64;  // Initialize the result variable to store the parsed key

        // Iterate through the remaining parts and parse them as u16 numbers
        for i in (0..4).rev() {
            let num = split
                .next()
                .and_then(|s| u16::from_str_radix(s, 16).ok())  // Parse hexadecimal u16
                .ok_or(InvalidKey)?;  // Return InvalidKey if parsing fails
            res |= (num as u64) << (i * 16);  // Construct the u64 key value
        }

        Ok(RecoveryKey(res))  // Return the parsed RecoveryKey
    }
}

// Define an error type to represent an invalid key
#[derive(Debug)]
struct InvalidKey;

// Implement Error trait for InvalidKey
impl std::error::Error for InvalidKey {}

// Implement Display trait for InvalidKey to format error messages
impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid key")  // Write "invalid key" to the formatter
    }
}

// Entry point of the program
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Print instructions for the user
    println!("In order to see the recovery key in the form of `203c-d001-xxxx-xxxx-xxxx-xxxx` you have to enter three specific passwords in the right order.");
    println!("For most models they are: ");
    println!("- `23fbb82a` -");
    println!("- `d2f65c29` -");
    println!("- `ca3db92a` -");
    println!("However some models and BIOS versions might need these instead: ");
    println!("- `3hqgo3` -");
    println!("- `jqw534` -");
    println!("- `0qww294e` -");

    println!("\nEnter the recovery key in the format 203c-d001-xxxx-xxxx-xxxx-xxxx:");
    let mut input = String::new();
    io::stdout().flush()?;  // Flush the stdout to display the prompt
    io::stdin().read_line(&mut input)?;  // Read user input

    let recovery_key: RecoveryKey = input.trim().parse()?;  // Parse input into a RecoveryKey

    println!("Password: {}", recovery_key.calculate_password());  // Calculate and print the password

    eprintln!("Press Enter to exit.");
    io::stdin().read_line(&mut String::new()).unwrap();  // Wait for Enter key press

    Ok(())  // Return success
}

// Define test module
#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::RecoveryKey;

    // Test case: short key
    #[test]
    fn short_key() {
        let key = RecoveryKey::from_str("203c-d001-0000-001d-e960-227d").unwrap();
        assert_eq!("494eab7c", key.calculate_password())
    }

    // Test case: known key
    #[test]
    fn known_key() {
        let key = RecoveryKey::from_str("203c-d001-4f30-609d-5125-646a").unwrap();
        assert_eq!("66b14918", key.calculate_password())
    }
}
