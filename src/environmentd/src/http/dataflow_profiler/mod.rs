// Copyright Materialize, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

//! Dataflow profiling HTTP endpoint.

use std::time::Duration;

use axum::Json;
use axum::response::IntoResponse;
use futures::TryStreamExt;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderValue, StatusCode};
use serde::Deserialize;

use crate::http::AuthedClient;

mod aggregate;
mod collect;
mod pprof;
mod subscribe;
mod types;

// use self::aggregate::Aggregator;
// use self::collect::{Collector, subscribe};

/// Request for dataflow profiling
#[derive(Debug, Deserialize)]
pub struct DataflowProfileRequest {
    /// Target cluster name
    cluster: String,
    /// Target replica name
    replica: String,
    /// Type of profile to collect
    profile: ProfileType,
    /// Profiling duration in seconds (optional, defaults to snapshot)
    duration: Option<u64>,
}

/// Types of profiles that can be collected
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ProfileType {
    /// elapsed time
    Time,
    /// heap size
    Size,
    /// heap capacity
    Capacity,
    /// record count
    Records,
}

/// Handle dataflow profiling requests
pub async fn handle_dataflow_profile(
    client: AuthedClient,
    Json(request): Json<DataflowProfileRequest>,
) -> impl IntoResponse {
    match profile_dataflow(client, request).await {
        Ok(profile_data) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            (StatusCode::OK, headers, profile_data)
        }
        Err(e) => {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                headers,
                e.to_string().into_bytes(),
            )
        }
    }
}

/// Core dataflow profiling function
async fn profile_dataflow(
    client: AuthedClient,
    request: DataflowProfileRequest,
) -> anyhow::Result<Vec<u8>> {
    let mode = match request.duration {
        Some(secs) => {
            let duration = Some(Duration::from_secs(secs));
            subscribe::Mode::Continual { duration }
        }
        None => subscribe::Mode::Snapshot,
    };

    // TODO: Just issue a subscribe of select 1, put results in a gzip file then send bakc.

    // let mut collector = Collector::new(sql_url, &request.cluster, &request.replica)?;
    // collector.subscribe(subscribe::Operator, mode).await?;

    // match request.profile {
    //     ProfileType::Time => collector.subscribe(subscribe::Elapsed, mode).await?,
    //     ProfileType::Size => collector.subscribe(subscribe::Size, mode).await?,
    //     ProfileType::Capacity => collector.subscribe(subscribe::Capacity, mode).await?,
    //     ProfileType::Records => collector.subscribe(subscribe::Records, mode).await?,
    // }

    // let mut stream = collector.into_stream();
    // let mut aggregator = Aggregator::new();

    // while let Some(batch) = stream.try_next().await? {
    //     aggregator.update(batch);
    // }

    // let prof = aggregator.build_pprof();
    // let profile_data = pprof::serialize(&prof)?;

    // Return the raw bytes instead of wrapping in a response struct
    Ok(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    // Ok(profile_data)
}
