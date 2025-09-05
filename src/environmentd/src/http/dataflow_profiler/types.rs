// Copyright Materialize, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

//! Types used in dataflow profiling.

use std::fmt;

/// Operator identifier
pub type OpId = u64;

/// Worker identifier  
pub type WorkerId = u64;

/// Operator information
#[derive(Debug, Clone)]
pub struct OpInfo {
    pub address: Address,
    pub name: String,
}

/// Address of an operator in the dataflow graph
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    path: Vec<usize>,
}

impl Address {
    pub fn new(path: Vec<usize>) -> Self {
        Self { path }
    }

    /// Get the parent address by removing the last element
    pub fn parent(&self) -> Option<Address> {
        if self.path.len() > 1 {
            Some(Address {
                path: self.path[..self.path.len() - 1].to_vec(),
            })
        } else {
            None
        }
    }

    /// Get all ancestor addresses
    pub fn ancestors(&self) -> impl Iterator<Item = Address> {
        (1..self.path.len()).rev().map(move |len| Address {
            path: self.path[..len].to_vec(),
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.path)
    }
}
