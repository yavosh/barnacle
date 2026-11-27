use super::{IconMetric, invalid};
use crate::IgnoreSet;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

const MAX_LINE: u64 = 8192;

#[derive(Default)]
pub(super) struct IconDatabase {
    groups: [HashMap<Box<str>, u8>; 2],
    rows: Vec<Reference>,
}

struct Reference {
    groups: [u8; 2],
    metric: IconMetric,
}

impl IconDatabase {
    pub(super) fn load(
        paths: &[&Path],
        ignores: &IgnoreSet,
        mut open: impl FnMut(&Path) -> io::Result<File>,
    ) -> io::Result<Self> {
        let mut database = Self::default();
        for &path in paths {
            let file = open(path).map_err(|error| {
                io::Error::new(error.kind(), format!("{}: {error}", path.display()))
            })?;
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            // Each loaded file replaces the previous table in stock clamd.
            database.rows.clear();
            database.groups.iter_mut().for_each(HashMap::clear);
            for number in 1.. {
                line.clear();
                let located = |error: io::Error| {
                    io::Error::new(
                        error.kind(),
                        format!("{}:{number}: {error}", path.display()),
                    )
                };
                let read = reader
                    .by_ref()
                    .take(MAX_LINE + 1)
                    .read_line(&mut line)
                    .map_err(located)?;
                if read == 0 {
                    if number == 1 {
                        return Err(located(invalid("empty icon database")));
                    }
                    break;
                }
                if read as u64 > MAX_LINE {
                    return Err(located(invalid("icon database line exceeds 8192 bytes")));
                }
                if line.starts_with('#') {
                    continue;
                }
                let record = line.trim_end_matches(['\r', '\n']);
                let mut fields = record.split(':');
                match (
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                ) {
                    (Some(name), Some(first), Some(second), Some(hash), None)
                        if hash.len() == 124 =>
                    {
                        if !ignores.matches(name, record) {
                            database.rows.push(Reference {
                                groups: [
                                    group_id(&mut database.groups[0], first).map_err(located)?,
                                    group_id(&mut database.groups[1], second).map_err(located)?,
                                ],
                                metric: IconMetric::parse(hash).map_err(located)?,
                            });
                        }
                    }
                    _ => {
                        return Err(located(invalid(
                            "expected an icon name, two groups, and a 124-digit hash",
                        )));
                    }
                }
            }
        }
        Ok(database)
    }

    pub(super) fn select(&self, names: [Option<&str>; 2]) -> Option<[Option<u8>; 2]> {
        if self.rows.is_empty() {
            return None;
        }
        let mut ids = [None; 2];
        for (index, name) in names.into_iter().enumerate() {
            if let Some(name) = name.filter(|&name| name != "*") {
                ids[index] = Some(*self.groups[index].get(name)?);
            }
        }
        Some(ids)
    }

    pub(super) fn matches(
        &self,
        groups: [Option<u8>; 2],
        samples: &[IconMetric],
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<bool> {
        for (i, row) in self.rows.iter().enumerate() {
            if i % 64 == 0 {
                check()?;
            }
            if groups
                .into_iter()
                .zip(row.groups)
                .all(|(query, actual)| query.is_none_or(|group| group == actual))
            {
                for (index, sample) in samples.iter().enumerate() {
                    if index % 64 == 0 {
                        check()?;
                    }
                    if row.metric.matches(sample) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

fn group_id(groups: &mut HashMap<Box<str>, u8>, name: &str) -> io::Result<u8> {
    if let Some(&id) = groups.get(name) {
        return Ok(id);
    }
    let id = u8::try_from(groups.len()).map_err(|_| invalid("too many icon groups"))?;
    groups.insert(name.into(), id);
    Ok(id)
}
