#![forbid(unsafe_code)]

// SPDX-FileCopyrightText: 2026 GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use ::coap::Server as CoapServer;
use clap::Parser;
use coap_client::{ClientOptions, TokioClient, Transport};
use coap_lite::{CoapRequest as Request, CoapResponse as Response};
use once_cell::unsync::OnceCell;
use std::net::SocketAddr;
use tokio::task::LocalSet;

mod coap;
mod wakaama;

use crate::coap::Server as ServerState;

/// see <https://confluence-husqvarna.riada.se/x/grGqC>
const SERVER_BIND_ADDRESS: &str = "[::]:20024";
const CLIENT_BIND_ADDRESS: &str = "[::]:20025";

#[derive(Parser, Default)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Disable the Nagle algorithm
    #[arg(long)]
    tcp_nodelay: bool,
}

thread_local! {
    static SERVER_STATE: OnceCell<&'static ServerState> = const { OnceCell::new() };
}

async fn handle_request(request: Request<SocketAddr>) -> Option<Response> {
    // We could have made this simpler if the coap crate didn't require the handler to implement the
    // Send trait.
    let server_state = SERVER_STATE.with(|s| *s.get().unwrap());
    // add device id for logging
    let device = match request.source {
        Some(SocketAddr::V6(addr)) => wakaama::get_device_id(*addr.ip())
            .await
            .unwrap_or_default()
            .unwrap_or_else(|| "unknown".to_string()),
        _ => "unknown".to_string(),
    };
    Some(ServerState::handle_request(server_state, request, &device).await)
}

/// Run the CoAP transport proxy server.
///
/// # Errors
///
/// Will return `Err` if the server could not be started, e.g. when the port is already in use.
pub async fn run(args: Args) -> Result<(), std::io::Error> {
    let local = LocalSet::new();
    local
        .run_until(async move {
            let client_options = ClientOptions::default();
            let coap_client =
                TokioClient::new(Transport::Udp, CLIENT_BIND_ADDRESS, &client_options).await?;
            let _ = SERVER_STATE.with(|s| s.set(ServerState::new(coap_client, args.tcp_nodelay)));

            let mut server = CoapServer::new(SERVER_BIND_ADDRESS)?;
            tracing::info!("Server running on {SERVER_BIND_ADDRESS}.");

            server.run(handle_request).await
        })
        .await
}
