// SPDX-FileCopyrightText: 2026 GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::de::{self, Unexpected};
use serde::{Deserialize, Deserializer, Serialize};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct CoapTxParams {
    #[serde(rename = "cs")]
    pub max_payload_size: Option<usize>,
    #[serde(
        rename = "ca",
        default,
        deserialize_with = "option_duration_from_millis"
    )]
    pub ack_timeout: Option<Duration>,
    #[serde(rename = "cf")]
    pub ack_random_factor: Option<f32>,
    #[serde(rename = "cr")]
    pub max_retransmit: Option<usize>,
    #[serde(
        rename = "ct",
        default,
        deserialize_with = "option_duration_from_millis"
    )]
    pub response_timeout: Option<Duration>,
    #[serde(rename = "cb")]
    pub backoff_factor: Option<f32>,
}

#[derive(Debug, Deserialize)]
pub struct OpenTunnelMessage {
    // TODO: ensure leading '/'?
    #[serde(rename = "c")]
    pub client_uri: String,
    #[serde(rename = "h")]
    pub host: String,
    #[serde(rename = "p")]
    pub port: u16,
    #[serde(rename = "t", default, deserialize_with = "bool_from_int")]
    pub use_tls: bool,
    #[serde(
        rename = "v",
        default = "default_verify_certificate",
        deserialize_with = "bool_from_int"
    )]
    pub verify_certificate: bool,
    #[serde(flatten)]
    pub coap_tx_params: CoapTxParams,
}

#[derive(Debug, Serialize)]
pub struct ServerStateMessage {
    pub is_network_connected: bool,
    #[serde(rename = "sockets")]
    pub tunnels: Vec<TunnelInfo>,
}

#[derive(Debug, Serialize)]
pub struct TunnelInfo {
    pub client_uri: String,
    pub id: String,
    pub host: String,
    pub port: u16,
    pub state: TunnelStatus,
}

#[derive(Debug, Serialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum TunnelStatus {
    Connecting,
    Failed,
    Connected,
    Closed,
}

fn default_verify_certificate() -> bool {
    // TODO: better default to the value of use_tls
    true
}

fn option_duration_from_millis<'a, D: Deserializer<'a>>(
    deserializer: D,
) -> Result<Option<Duration>, D::Error> {
    let millis = u64::deserialize(deserializer)?;
    Ok(Some(Duration::from_millis(millis)))
}

fn bool_from_int<'a, D: Deserializer<'a>>(deserializer: D) -> Result<bool, D::Error> {
    match u8::deserialize(deserializer)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(u64::from(other)),
            &"zero or one",
        )),
    }
}
