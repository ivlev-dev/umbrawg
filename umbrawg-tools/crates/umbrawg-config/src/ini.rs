use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    Interface,
    Peer,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: String,
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub kind: SectionKind,
    pub line: usize,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Document {
    pub sections: Vec<Section>,
}

impl Document {
    pub fn parse(input: &str) -> Result<Self, Error> {
        let mut document = Self::default();
        for (index, raw) in input.lines().enumerate() {
            let line_number = index + 1;
            let line = clean_line(raw);
            if line.is_empty() {
                continue;
            }
            if let Some(name) = section_name(&line) {
                let kind = match name.to_ascii_lowercase().as_str() {
                    "interface" => SectionKind::Interface,
                    "peer" => SectionKind::Peer,
                    _ => SectionKind::Other,
                };
                document.sections.push(Section {
                    name: name.to_owned(),
                    kind,
                    line: line_number,
                    entries: Vec::new(),
                });
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(Error::UnrecognizedLine {
                    line: line_number,
                    text: raw.trim().to_owned(),
                });
            };
            if key.is_empty() {
                return Err(Error::UnrecognizedLine {
                    line: line_number,
                    text: raw.trim().to_owned(),
                });
            }
            let Some(section) = document.sections.last_mut() else {
                return Err(Error::UnrecognizedLine {
                    line: line_number,
                    text: raw.trim().to_owned(),
                });
            };
            section.entries.push(Entry {
                key: key.to_owned(),
                value: value.to_owned(),
                line: line_number,
            });
        }
        Ok(document)
    }
}

impl std::fmt::Display for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, section) in self.sections.iter().enumerate() {
            if index > 0 {
                f.write_str("\n")?;
            }
            writeln!(f, "[{}]", section.name)?;
            for entry in &section.entries {
                writeln!(f, "{} = {}", entry.key, entry.value)?;
            }
        }
        Ok(())
    }
}

fn section_name(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    if inner.is_empty() {
        None
    } else {
        Some(inner)
    }
}

fn clean_line(raw: &str) -> String {
    let line = match raw.find('#') {
        Some(index) => &raw[..index],
        None => raw,
    };
    if preserves_value_whitespace(line) {
        clean_special_handshake_line(line)
    } else {
        line.chars().filter(|value| !is_space(*value)).collect()
    }
}

fn preserves_value_whitespace(line: &str) -> bool {
    let key = line
        .trim_start()
        .split_once('=')
        .map_or(line.trim_start(), |(key, _)| key)
        .trim()
        .to_ascii_lowercase();
    matches!(
        key.as_str(),
        "i1" | "i2"
            | "i3"
            | "i4"
            | "i5"
            | "address"
            | "dns"
            | "mtu"
            | "table"
            | "preup"
            | "postup"
            | "predown"
            | "postdown"
            | "saveconfig"
    )
}

fn clean_special_handshake_line(line: &str) -> String {
    let line = line.trim_end();
    let mut output = String::with_capacity(line.len());
    let mut before_equals = true;
    let mut value_started = false;
    for value in line.chars() {
        if before_equals {
            if value == '=' {
                output.push(value);
                before_equals = false;
            } else if !is_space(value) {
                output.push(value);
            }
        } else if !value_started {
            if !is_space(value) {
                output.push(value);
                value_started = true;
            }
        } else {
            output.push(value);
        }
    }
    output
}

fn is_space(value: char) -> bool {
    matches!(value, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_sections_and_order() {
        let input = "# comment\n[Interface]\nPrivateKey = A\nListenPort = 1\n\n[Peer]\nPublicKey = B\n[Peer]\nPublicKey = C\n";
        let document = Document::parse(input).expect("valid");
        assert_eq!(document.sections.len(), 3);
        assert_eq!(document.sections[0].kind, SectionKind::Interface);
        assert_eq!(document.sections[1].kind, SectionKind::Peer);
        assert_eq!(document.sections[2].kind, SectionKind::Peer);
        assert_eq!(document.sections[2].entries[0].value, "C");
        assert_eq!(document.to_string(), "[Interface]\nPrivateKey = A\nListenPort = 1\n\n[Peer]\nPublicKey = B\n\n[Peer]\nPublicKey = C\n");
    }

    #[test]
    fn trims_spaces_but_keeps_inline_values() {
        let input =
            "[Interface]\n  ListenPort  =  51820  # inline\nI1 =<b 0x1234><c>\nI2 =  <r 10>  \n";
        let document = Document::parse(input).expect("valid");
        let entries = &document.sections[0].entries;
        assert_eq!(entries[0].key, "ListenPort");
        assert_eq!(entries[0].value, "51820");
        assert_eq!(entries[1].key, "I1");
        assert_eq!(entries[1].value, "<b 0x1234><c>");
        assert_eq!(entries[2].key, "I2");
        assert_eq!(entries[2].value, "<r 10>");
    }

    #[test]
    fn rejects_line_outside_section() {
        assert!(Document::parse("PrivateKey = A\n").is_err());
    }

    #[test]
    fn rejects_line_without_equals() {
        assert!(Document::parse("[Interface]\nbroken\n").is_err());
    }

    #[test]
    fn empty_document() {
        let document = Document::parse("\n# only comments\n").expect("valid");
        assert!(document.sections.is_empty());
        assert_eq!(document.to_string(), "");
    }
}
