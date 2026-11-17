use std::io::{Read, Write};

use umbrawg_config::{Key, KEY_BASE64_LEN};

pub fn warn_world_accessible(file_descriptor: i32) {
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::fstat(file_descriptor, &mut status) };
    if result != 0 {
        return;
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        return;
    }
    if status.st_mode & 0o007 != 0 {
        eprintln!("Warning: writing to world accessible file.");
        eprintln!("Consider setting the umask to 077 and trying again.");
    }
}

pub fn generate_private_key() -> Result<String, String> {
    Key::generate()
        .map(|key| key.to_base64())
        .map_err(|error| format!("getrandom: {error}"))
}

pub fn generate_preshared_key() -> Result<String, String> {
    Key::generate_unclamped()
        .map(|key| key.to_base64())
        .map_err(|error| format!("getrandom: {error}"))
}

pub fn write_stdout(text: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "{text}").map_err(|error| error.to_string())?;
    handle.flush().map_err(|error| error.to_string())
}

pub fn public_key_from_stdin(input: &[u8]) -> Result<String, String> {
    const KEY_MESSAGE: &str = "Key is not the correct length or format";
    if input.len() < KEY_BASE64_LEN {
        return Err(KEY_MESSAGE.to_owned());
    }
    let (key_bytes, trailing) = input.split_at(KEY_BASE64_LEN);
    let text = std::str::from_utf8(key_bytes).map_err(|_| KEY_MESSAGE.to_owned())?;
    if trailing
        .iter()
        .any(|byte| *byte != 0 && !byte.is_ascii_whitespace())
    {
        return Err("Trailing characters found after key".to_owned());
    }
    let key = Key::from_base64(text).map_err(|_| KEY_MESSAGE.to_owned())?;
    Ok(key.public_key().to_base64())
}

pub fn read_stdin() -> Result<Vec<u8>, String> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| error.to_string())?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUBLIC: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    #[test]
    fn computes_public_key() {
        assert_eq!(
            public_key_from_stdin(PRIVATE.as_bytes()).expect("valid"),
            PUBLIC
        );
    }

    #[test]
    fn accepts_trailing_whitespace() {
        let input = format!("{PRIVATE}\r\n\t ");
        assert_eq!(
            public_key_from_stdin(input.as_bytes()).expect("valid"),
            PUBLIC
        );
    }

    #[test]
    fn ignores_trailing_nul() {
        let mut input = PRIVATE.as_bytes().to_vec();
        input.push(0);
        assert_eq!(public_key_from_stdin(&input).expect("valid"), PUBLIC);
    }

    #[test]
    fn rejects_trailing_characters() {
        let input = format!("{PRIVATE}x");
        assert!(public_key_from_stdin(input.as_bytes()).is_err());
    }

    #[test]
    fn rejects_short_input() {
        assert!(public_key_from_stdin(b"short").is_err());
        assert!(public_key_from_stdin(&PRIVATE.as_bytes()[..KEY_BASE64_LEN - 1]).is_err());
    }

    #[test]
    fn rejects_invalid_base64() {
        let input = "!Anz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        assert!(public_key_from_stdin(input.as_bytes()).is_err());
    }
}
