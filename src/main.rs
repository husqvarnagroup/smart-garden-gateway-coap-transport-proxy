#![forbid(unsafe_code)]

// SPDX-FileCopyrightText: 2026 GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::Parser;
use coap_transport_proxy::{run, Args};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    gardenalog::init_tracing();
    if let Err(error) = run(args).await {
        tracing::error!(?error, "Error running server.");
    }
}
