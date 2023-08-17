use std::{fmt, io::{self, Write}, str::FromStr};

use crc::{Crc, CRC_32_JAMCRC};

#[derive(Clone, Copy)]
struct RecoveryKey(u64);

impl RecoveryKey {
    pub fn calculate_password(&self) -> String {
        let crc = Crc::<u32>::new(&CRC_32_JAMCRC);

        let s = format!("{:016x}", self.0);
        let res = crc.checksum(s.as_bytes());
        format!("{res:x}")
    }
}

impl FromStr for RecoveryKey {
    type Err = InvalidKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('-');

        if split.next() != Some("203c") {
            return Err(InvalidKey);
        }

        if split.next() != Some("d001") {
            return Err(InvalidKey);
        }

        let mut res = 0u64;

        for i in (0..4).rev() {
            let num = split
                .next()
                .and_then(|s| u16::from_str_radix(s, 16).ok())
                .ok_or(InvalidKey)?;
            res |= (num as u64) << (i * 16);
        }

        Ok(RecoveryKey(res))
    }
}

#[derive(Debug)]
struct InvalidKey;

impl std::error::Error for InvalidKey {}

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid key")
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("In order to see the recovery key in the form of `203c-d001-xxxx-xxxx-xxxx-xxxx` you have to enter three specific passwords in the right order.");
    println!("For my system they are the following:");
    println!("- `23fbb82a`");
    println!("- `d2f65c29`");
    println!("- `ca3db92a`");
    println!("Depending on your model and BIOS version, those might not work for you. Try using these passwords instead:");
    println!("- `3hqgo3`");
    println!("- `jqw534`");
    println!("- `0qww294e`");

    println!("\nEnter the recovery key in the format 203c-d001-xxxx-xxxx-xxxx-xxxx:");
    let mut input = String::new();
    io::stdout().flush()?; // Flush the stdout to make sure the prompt is displayed
    io::stdin().read_line(&mut input)?;

    let recovery_key: RecoveryKey = input.trim().parse()?;

    println!("Password: {}", recovery_key.calculate_password());

    eprintln!("Press Enter to exit.");
    io::stdin().read_line(&mut String::new()).unwrap();

    Ok(())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::RecoveryKey;

    #[test]
    fn short_key() {
        let key = RecoveryKey::from_str("203c-d001-0000-001d-e960-227d").unwrap();
        assert_eq!("494eab7c", key.calculate_password())
    }

    #[test]
    fn known_key() {
        let key = RecoveryKey::from_str("203c-d001-4f30-609d-5125-646a").unwrap();
        assert_eq!("66b14918", key.calculate_password())
    }
}
