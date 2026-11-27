//! Logical-signature expressions evaluated against one object's occurrence counts.
use super::invalid;
use std::io;

// The pinned main and daily archives use at most 187 expression bytes.
// Bound compiler and evaluator scratch even when called outside the database reader.
const MAX_BYTES: usize = 8191;

#[derive(Clone, Copy, Debug)]
enum Binary {
    And,
    Or,
}

#[derive(Clone, Copy, Debug)]
enum Comparison {
    Equal,
    Less,
    Greater,
}

impl Comparison {
    fn accepts(self, actual: u32, expected: u32) -> bool {
        match self {
            Self::Equal => actual == expected,
            Self::Less => actual < expected,
            Self::Greater => actual > expected,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Instruction {
    Child(u8),
    Combine {
        op: Binary,
        keep_last: bool,
    },
    Compare {
        op: Comparison,
        count: u32,
        distinct: u8,
        group: bool,
    },
}

#[derive(Debug)]
pub(super) struct Expression(Program);

#[derive(Debug)]
enum Program {
    // Most pinned rules are plain conjunctions, including single children.
    All(u64),
    Postfix {
        steps: Box<[Instruction]>,
        slots: usize,
    },
}

impl Expression {
    pub(super) fn parse(input: &str, children: usize) -> io::Result<Self> {
        Self::compile(input, children, true)
    }

    pub(super) fn trigger(input: &str, slot: usize) -> io::Result<Self> {
        Self::compile(input, slot, false)
    }

    fn compile(input: &str, children: usize, exact_count: bool) -> io::Result<Self> {
        if !(1..=64).contains(&children) || input.is_empty() || input.len() > MAX_BYTES {
            return Err(invalid("invalid logical expression size or child count"));
        }
        let mut input = input.as_bytes();
        let mut steps = Vec::new();
        let mut operators = Vec::new();
        let mut groups = Vec::new();
        let mut ids = 0u64;
        let mut need_operand = true;
        while let Some(&token) = trim(&mut input).first() {
            if need_operand {
                if token == b'(' {
                    groups.push(operators.len());
                    input = &input[1..];
                    continue;
                }
                let id = number(&mut input)?;
                if id >= children as u32 {
                    return Err(invalid("logical expression refers to an unknown child"));
                }
                ids |= 1u64 << id;
                steps.push(Instruction::Child(id as u8));
                leaf_qualifiers(&mut input)?;
                if let Some(test) = comparison(&mut input, false)? {
                    steps.push(test);
                }
                need_operand = false;
            } else {
                input = &input[1..];
                match token {
                    b'&' | b'|' => {
                        operators.push(if token == b'&' {
                            Binary::And
                        } else {
                            Binary::Or
                        });
                        need_operand = true;
                    }
                    b')' => {
                        let start = groups
                            .pop()
                            .ok_or_else(|| invalid("unexpected closing parenthesis"))?;
                        let has_operator = operators.len() > start;
                        reduce(&mut steps, &operators[start..], true);
                        operators.truncate(start);
                        if let Some(test) = comparison(&mut input, true)? {
                            if !has_operator {
                                return Err(invalid(
                                    "counted group needs a direct binary operator",
                                ));
                            }
                            steps.push(test);
                        }
                    }
                    _ => return Err(invalid("expected a logical operator")),
                }
            }
        }
        if need_operand || !groups.is_empty() {
            return Err(invalid("unfinished logical expression"));
        }
        if exact_count && (64 - ids.leading_zeros()) as usize != children {
            return Err(invalid(
                "logical expression and subsignature count disagree",
            ));
        }
        reduce(&mut steps, &operators, false);
        let mut depth = 0usize;
        let mut slots = 0;
        let mut all = true;
        for &step in &steps {
            match step {
                Instruction::Child(_) => {
                    depth += 1;
                    slots = slots.max(depth);
                }
                Instruction::Combine { op, .. } => {
                    depth -= 1;
                    all &= matches!(op, Binary::And);
                }
                Instruction::Compare { .. } => all = false,
            }
        }
        debug_assert_eq!(depth, 1);
        Ok(Self(if all {
            Program::All(ids)
        } else {
            Program::Postfix {
                steps: steps.into(),
                slots,
            }
        }))
    }

    pub(super) fn matches(&self, counts: &[u32]) -> bool {
        match &self.0 {
            Program::All(mask) => {
                let mut ids = *mask;
                while ids != 0 {
                    let id = ids.trailing_zeros() as usize;
                    if counts.get(id).copied().unwrap_or(0) == 0 {
                        return false;
                    }
                    ids &= ids - 1;
                }
                true
            }
            Program::Postfix { steps, slots } => {
                if *slots <= 8 {
                    evaluate(steps, counts, &mut [Evidence::default(); 8])
                } else {
                    evaluate(steps, counts, &mut vec![Evidence::default(); *slots])
                }
            }
        }
    }
}

fn trim<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    while let [b' ' | b'\t', tail @ ..] = *input {
        *input = tail;
    }
    input
}

fn number(input: &mut &[u8]) -> io::Result<u32> {
    let bytes = trim(input);
    let n = bytes.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return Err(invalid("expected decimal number in logical expression"));
    }
    let mut value = 0u32;
    for &b in &bytes[..n] {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u32::from(b - b'0')))
            .ok_or_else(|| invalid("logical expression number exceeds u32"))?;
    }
    *input = &bytes[n..];
    Ok(value)
}

// Stock uses only the leading ID and the last comparison on a leaf. The
// verified archives include numeric qualifiers, a trailing comma and "8==9".
fn leaf_qualifiers(input: &mut &[u8]) -> io::Result<()> {
    while matches!(trim(input).first(), Some(b':' | b',')) {
        *input = &input[1..];
        if trim(input).first().is_some_and(u8::is_ascii_digit) {
            number(input)?;
        }
    }
    Ok(())
}

fn comparison(input: &mut &[u8], group: bool) -> io::Result<Option<Instruction>> {
    let mut test = None;
    loop {
        // A group modifier must immediately follow the closing parenthesis.
        let op = match if group {
            input.first()
        } else {
            trim(input).first()
        } {
            Some(b'=') => Comparison::Equal,
            Some(b'<') => Comparison::Less,
            Some(b'>') => Comparison::Greater,
            _ => return Ok(test),
        };
        *input = &input[1..];
        if !group && matches!(trim(input).first(), Some(b'=' | b'<' | b'>')) {
            continue;
        }
        let count = number(input)?;
        let mut distinct = 0;
        if group {
            if let Some(rest) = input.strip_prefix(b",") {
                *input = rest;
                distinct = number(input)?.min(65) as u8;
            }
        } else {
            leaf_qualifiers(input)?;
        }
        test = Some(Instruction::Compare {
            op,
            count,
            distinct,
            group,
        });
        if group {
            return Ok(test);
        }
    }
}

// Bare expressions split at the first operator. Parenthesized blocks split
// at the last operator, then evaluate the prefix as a bare expression.
fn reduce(steps: &mut Vec<Instruction>, ops: &[Binary], group: bool) {
    let (within, last) = if group {
        ops.split_last()
            .map_or((ops, None), |(op, rest)| (rest, Some(*op)))
    } else {
        (ops, None)
    };
    for &op in within.iter().rev() {
        steps.push(Instruction::Combine {
            op,
            keep_last: last.is_some(),
        });
    }
    if let Some(op) = last {
        steps.push(Instruction::Combine {
            op,
            keep_last: false,
        });
    }
}

#[derive(Clone, Copy, Default)]
struct Evidence {
    ids: u64,
    hits: u32,
    matched: bool,
}

fn evaluate(steps: &[Instruction], counts: &[u32], stack: &mut [Evidence]) -> bool {
    let mut len = 0usize;
    for &step in steps {
        match step {
            Instruction::Child(id) => {
                let Some(&hits) = counts.get(usize::from(id)) else {
                    return false;
                };
                // Keep the ID until the leaf comparison runs. A successful =0
                // contributes its distinct ID even when it contributes no hits.
                stack[len] = Evidence {
                    ids: 1u64 << id,
                    hits,
                    matched: hits != 0,
                };
                len += 1;
            }
            Instruction::Compare {
                op,
                count,
                distinct,
                group,
            } => {
                let evidence = &mut stack[len - 1];
                evidence.matched = op.accepts(evidence.hits, count)
                    && (!group || evidence.ids.count_ones() >= u32::from(distinct));
                if group {
                    evidence.ids = 0;
                } // Counted groups only export their hit count.
            }
            Instruction::Combine { op, keep_last } => {
                let at = len - 2 - usize::from(keep_last);
                let left = stack[at];
                let right = stack[at + 1];
                let matched = match op {
                    Binary::And => left.matched && right.matched,
                    Binary::Or => left.matched || right.matched,
                };
                let mut result = Evidence {
                    matched,
                    ..Evidence::default()
                };
                if matched {
                    for child in [left, right] {
                        if child.matched {
                            result.hits = result.hits.wrapping_add(child.hits);
                            result.ids |= child.ids;
                        }
                    }
                }
                stack[at] = result;
                if keep_last {
                    stack[at + 1] = stack[len - 1];
                }
                len -= 1;
            }
        }
    }
    stack[0].matched
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(expression: &str, counts: &[u32]) -> bool {
        Expression::parse(expression, counts.len())
            .unwrap()
            .matches(counts)
    }

    #[test]
    fn grouping_and_equal_precedence() {
        assert!(matched("0|1&2", &[1, 0, 0]));
        assert!(!matched("(0|1)&2", &[1, 0, 0]));
        assert!(!matched("0&1|2", &[0, 0, 1]));
        assert!(matched("(0&1|2)", &[0, 0, 1]));
        assert!(!matched("(0&1|2|3)", &[0, 0, 1, 0]));
        assert!(matched("(0&(1|2))", &[1, 0, 1]));
    }

    #[test]
    fn comparisons_count_occurrences_and_distinct_ids() {
        assert!(matched("(0|1)=2,1", &[2, 0]));
        assert!(!matched("(0|1)=2,2", &[2, 0]));
        assert!(matched("(0|1)>1,2", &[3, 1]));
        assert!(!matched("(0|1)<3,2", &[2, 1]));
        assert!(matched("(0|0)=2", &[1]));
        assert!(!matched("(0|0)=2,2", &[1]));
        assert!(matched("0=2,50", &[2]));
        assert!(matched("0=3=2", &[2]));
        assert!(matched("0==2", &[2]));
        assert!(matched("0=2,&1", &[2, 1]));
    }

    #[test]
    fn nested_comparisons_only_export_successful_evidence() {
        assert!(matched("(0&1)=0", &[4, 0]));
        assert!(!matched("(0&1)=0,1", &[4, 0]));
        assert!(matched("(0=0&1)=1,2", &[0, 1]));
        assert!(!matched("(0>1|1)=2", &[1, 1]));
        assert!(matched("((0&1)|2)=1,1", &[1, 0, 1]));
        assert!(matched("((0|1)>0&2)=3,1", &[1, 1, 1]));
        assert!(!matched("((0|1)>0&2)=3,2", &[1, 1, 1]));
        assert!(matched("((0|1)|2)=3,3", &[1, 1, 1]));
    }

    #[test]
    fn pinned_spellings_and_child_boundaries() {
        assert!(matched("0 & 1 > 200", &[1, 201]));
        assert!(matched("0:0&((1>20&2>10&3)|(4))", &[1, 0, 0, 0, 1]));
        assert!(matched("0|2", &[0, 0, 1]));
        let mut counts = [0; 64];
        counts[63] = 3;
        assert!(matched("63=3", &counts));
        assert!(!Expression::parse("63=0", 64).unwrap().matches(&[]));
        assert!(matched("0=0", &[0]));
        assert!(matched("(0|1)=0", &[0, 0]));
        assert!(!matched("(0|1)=0,1", &[0, 0]));
        assert!(matched("(0|0)=4294967294", &[u32::MAX]));
    }

    #[test]
    fn rejects_invalid_expressions() {
        for (text, children) in [
            ("", 1),
            ("!0", 1),
            ("0", 0),
            ("0", 2),
            ("2", 2),
            ("64", 65),
            ("(0", 1),
            ("0)", 1),
            ("0&&1", 2),
            ("(0)=2", 1),
            ("((0|1))=2", 2),
            ("(0|1)>", 2),
            ("(0|1)>1,", 2),
            ("0|1&", 2),
            ("0 1", 2),
            ("0>4294967296", 1),
        ] {
            assert!(Expression::parse(text, children).is_err(), "{text}");
        }
    }

    #[test]
    fn deep_and_wide_input_uses_bounded_iterative_stacks() {
        let nested = format!("{}0{}", "(".repeat(4095), ")".repeat(4095));
        assert!(matched(&nested, &[1]));
        assert!(Expression::parse(&format!("({nested})"), 1).is_err());
        let wide = vec!["0"; 4096].join("|");
        assert!(matched(&wide, &[1]));
        assert!(!matched(&wide, &[0]));
    }
}
