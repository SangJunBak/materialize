// Copyright Materialize, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

//! pprof format utilities for dataflow profiling.

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::Result;
use flate2::Compression;
use flate2::write::GzEncoder;

pub mod profile {
    // Re-export the profile types from mz-prof if available
    // For now, we'll create minimal types
    #[derive(Debug, Default)]
    pub struct Profile {
        pub time_nanos: i64,
        pub function: Vec<Function>,
        pub location: Vec<Location>,
        pub sample_type: Vec<ValueType>,
        pub sample: Vec<Sample>,
        pub string_table: Vec<String>,
    }

    #[derive(Debug, Default)]
    pub struct Function {
        pub id: u64,
        pub name: i64,
    }

    #[derive(Debug, Default)]
    pub struct Location {
        pub id: u64,
        pub address: u64,
        pub line: Vec<Line>,
    }

    #[derive(Debug, Default)]
    pub struct Line {
        pub function_id: u64,
    }

    #[derive(Debug, Default)]
    pub struct ValueType {
        pub type_: i64,
        pub unit: i64,
    }

    #[derive(Debug, Default)]
    pub struct Sample {
        pub location_id: Vec<u64>,
        pub value: Vec<i64>,
        pub label: Vec<Label>,
    }

    #[derive(Debug, Default)]
    pub struct Label {
        pub key: i64,
        pub str: i64,
    }

    impl Profile {
        pub fn new() -> Self {
            Self::default()
        }
    }
}

pub struct StringTable {
    strings: BTreeMap<String, i64>,
    next_id: i64,
}

impl StringTable {
    pub fn new() -> Self {
        let mut table = Self {
            strings: BTreeMap::new(),
            next_id: 0,
        };
        // String table must start with empty string at index 0
        table.insert("");
        table
    }

    pub fn insert(&mut self, s: &str) -> i64 {
        if let Some(&id) = self.strings.get(s) {
            id
        } else {
            let id = self.next_id;
            self.strings.insert(s.to_string(), id);
            self.next_id += 1;
            id
        }
    }

    pub fn finish(self) -> Vec<String> {
        let mut result = vec![String::new(); self.strings.len()];
        for (string, id) in self.strings {
            result[id as usize] = string;
        }
        result
    }
}

/// Serialize a profile to the pprof format
pub fn serialize(prof: &profile::Profile) -> Result<Vec<u8>> {
    // TODO: Implement actual protobuf serialization
    // For now, return a placeholder
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"pprof profile placeholder")?;
    Ok(encoder.finish()?)
}

// /// Write profile to file (for compatibility with CLI interface)
// pub fn write_file(prof: &profile::Profile, path: &str) -> Result<()> {
//     let data = serialize(prof)?;
//     std::fs::write(path, data)?;
//     Ok(())
// }

pub fn stream_pprof_to_http(prof: &profile::Profile) {
    // TODO: Implement streaming pprof profile data to HTTP response
}
