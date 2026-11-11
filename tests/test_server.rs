// SPDX-FileCopyrightText: 2026 GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use coap_transport_proxy::{run, Args};
use std::process::Command;
use std::thread;

#[test]
fn test_server() {
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(run(Args::default()))
    });

    let status = Command::new("pytest")
        .arg("tests/test_server.py")
        .status()
        .expect("failed to run pytest");
    println!("{status}");
    assert!(status.success())
}
