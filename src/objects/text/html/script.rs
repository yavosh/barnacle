//! Tokenize ordinary inline JavaScript into the stock identifier and literal forms.
use super::{ChildSink, View};
use std::collections::{HashMap, HashSet};
use std::io;

#[derive(Default)]
struct Scope<'a> {
    names: HashMap<&'a [u8], usize>,
    references: HashSet<&'a [u8]>,
}

impl<'a> Scope<'a> {
    // A redeclaration or forward reference can change earlier tokens. Withhold the
    // entire JavaScript view if encoding it requires that second binding pass.
    fn bind(&mut self, name: &'a [u8], next: &mut usize) -> bool {
        if *next >= 4096 || self.references.contains(name) || self.names.contains_key(name) {
            return false;
        }
        self.names.insert(name, *next);
        *next += 1;
        true
    }
}

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$')
}

pub(super) fn normalize(
    mut input: &[u8],
    out: &mut View,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    input = input.trim_ascii();
    if input.is_empty() {
        return Ok(true);
    }
    if out.count > 0 {
        out.write(b"\n")?;
    }
    out.write(b"<script>")?;
    let mut globals = Scope::default();
    let mut locals: Option<Scope> = None;
    let mut next = 0;
    let mut bind_next = false;
    let mut variable_depth = None;
    let mut parameters = false;
    let mut function_body = None;
    let mut delimiters = Vec::new();
    let mut last_word = false;
    let mut last_string = false;
    let mut string_plus = false;
    let mut member = false;
    let mut step = 0;
    while let Some(&b) = input.first() {
        if step == 0 {
            sink.check()?;
        }
        step = (step + 1) % 256;
        if b.is_ascii_whitespace() {
            input = input.trim_ascii_start();
            continue;
        }
        if word(b) && !b.is_ascii_digit() {
            let n = input.iter().take_while(|b| word(**b)).count();
            if n > 255 {
                return Ok(false);
            }
            let name = &input[..n];
            input = &input[n..];
            if matches!(name, b"eval" | b"unescape" | b"fromCharCode") {
                return Ok(false);
            }
            if last_word {
                out.write(b" ")?;
            }
            if !member && name == b"function" {
                if locals.is_some() {
                    return Ok(false);
                }
                locals = Some(Scope::default());
                parameters = true;
                function_body = Some(delimiters.len());
                bind_next = true;
                out.write(name)?;
            } else if !member && name == b"var" {
                bind_next = true;
                variable_depth = Some(delimiters.len());
                out.write(name)?;
            } else {
                let scope = locals.as_mut().unwrap_or(&mut globals);
                if (bind_next || parameters) && !scope.bind(name, &mut next) {
                    return Ok(false);
                }
                bind_next = false;
                let local = (!member).then(|| scope.names.get(name)).flatten().copied();
                let binding = local.or_else(|| {
                    (!member)
                        .then(|| globals.names.get(name))
                        .flatten()
                        .copied()
                });
                if let Some(n) = binding {
                    out.write(format!("n{n:03}").as_bytes())?;
                } else {
                    if !member {
                        let scope = locals.as_mut().unwrap_or(&mut globals);
                        if scope.references.len() >= 4096 {
                            return Ok(false);
                        }
                        scope.references.insert(name);
                    }
                    for &c in name {
                        out.write(&[c.to_ascii_lowercase()])?;
                    }
                }
            }
            last_word = true;
            last_string = false;
            string_plus = false;
            member = false;
            continue;
        }
        if b.is_ascii_digit() {
            let n = input.iter().take_while(|b| b.is_ascii_digit()).count();
            if n > 9
                || (n > 1 && b == b'0')
                || (b == b'0' && matches!(input.get(n), Some(b'x' | b'X')))
            {
                return Ok(false);
            }
            if last_word {
                out.write(b" ")?;
            }
            out.write(&input[..n])?;
            input = &input[n..];
            last_word = true;
            last_string = false;
            string_plus = false;
            member = false;
            continue;
        }
        if bind_next {
            return Ok(false);
        }
        if b == b'"' || b == b'\'' {
            if string_plus {
                return Ok(false);
            }
            let Some(end) = input[1..].iter().position(|&c| c == b) else {
                return Ok(false);
            };
            let value = &input[1..1 + end];
            if !value
                .iter()
                .all(|b| (32..=126).contains(b) && !matches!(b, b'\\' | b'"'))
            {
                return Ok(false);
            }
            out.write(b"\"")?;
            for &c in value {
                out.write(&[c.to_ascii_lowercase()])?;
            }
            out.write(b"\"")?;
            input = &input[end + 2..];
            last_string = true;
            string_plus = false;
            last_word = false;
            member = false;
            continue;
        }
        match b {
            b'(' | b'{' | b'[' if delimiters.len() < 64 => delimiters.push(b),
            b')' | b'}' | b']' => {
                let open = match b {
                    b')' => b'(',
                    b'}' => b'{',
                    _ => b'[',
                };
                if delimiters.pop() != Some(open) {
                    return Ok(false);
                }
                if b == b')' && parameters {
                    parameters = false;
                }
                if b == b'}' && function_body == Some(delimiters.len()) {
                    function_body = None;
                    locals = None;
                }
            }
            b'+' | b'-' | b'*' | b'.' | b',' | b';' | b'=' | b'>' | b'<' | b'!' | b':' | b'?' => (),
            _ => return Ok(false),
        }
        if b == b',' && variable_depth == Some(delimiters.len()) {
            bind_next = true;
        } else if b == b';' {
            variable_depth = None;
        }
        string_plus = b == b'+' && last_string;
        last_string = false;
        last_word = false;
        member = b == b'.';
        out.write(&[b])?;
        input = &input[1..];
    }
    if !delimiters.is_empty() || bind_next || locals.is_some() {
        return Ok(false);
    }
    out.write(b"</script>")?;
    Ok(true)
}
