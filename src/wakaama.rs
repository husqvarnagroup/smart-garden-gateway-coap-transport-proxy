// SPDX-FileCopyrightText: 2026 GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::de::IgnoredAny;
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::Ipv6Addr;
use std::rc::Rc;
use std::time::{Duration, Instant};

const WAKAAMA_STATE_FILE: &str = "/var/lib/lwm2mserver/wakaama.json";
const READ_FILE_COOLDOWN_TIME: Duration = Duration::from_secs(1);

#[derive(Debug, Deserialize)]
struct WakaamaState {
    clients: Vec<WakaamaClient>,
}

#[derive(Debug, Deserialize)]
struct WakaamaClient {
    #[serde(rename = "ep")]
    client_name: String,
    session: WakaamaSession,
}

#[derive(Debug, Deserialize)]
struct WakaamaSession {
    id: (Ipv6Addr, IgnoredAny),
}

type DeviceIdMap = HashMap<Ipv6Addr, String>;

thread_local! {
    static DEVICE_ID_MAP: RefCell<DeviceIdMap> = RefCell::new(DeviceIdMap::new());
    static MAP_LAST_UPDATED: Rc<tokio::sync::Mutex<Instant>> = Rc::new(tokio::sync::Mutex::new(Instant::now() - READ_FILE_COOLDOWN_TIME));
    static NOT_FOUND_DEVICE_IDS: RefCell<HashSet<Ipv6Addr>> = RefCell::new(HashSet::new());
}

async fn get_wakaama_device_ids() -> Result<Vec<(Ipv6Addr, String)>, std::io::Error> {
    tokio::task::spawn_blocking(|| {
        let file = File::open(WAKAAMA_STATE_FILE)?;
        let reader = BufReader::new(file);
        let data: WakaamaState = serde_json::from_reader(reader)?;
        let ids = data
            .clients
            .iter()
            .filter_map(|c| {
                Some((
                    c.session.id.0,
                    c.client_name.strip_prefix("urn:dev:sg:")?.to_string(),
                ))
            })
            .collect();
        Ok(ids)
    })
    .await?
}

pub async fn get_device_id(device_address: Ipv6Addr) -> Result<Option<String>, std::io::Error> {
    let result = get_device_id_impl(device_address).await;
    if result.is_err() || result.as_ref().unwrap().is_none() {
        // only warn once per device ID
        NOT_FOUND_DEVICE_IDS.with(|s| {
            if s.borrow_mut().insert(device_address) {
                if let Err(error) = result.as_ref() {
                    tracing::warn!(?error, %device_address,
                        "Could not load Device IDs from Wakaama state file, while finding device ID"
                    );
                } else {
                    tracing::warn!(%device_address, "Could not find device ID");
                }
            }
        });
    }
    result
}

async fn get_device_id_impl(device_address: Ipv6Addr) -> Result<Option<String>, std::io::Error> {
    if let Some(device_id) = DEVICE_ID_MAP.with(|m| m.borrow().get(&device_address).cloned()) {
        return Ok(Some(device_id));
    }

    // not found in map, waiting to get lock
    let mutex = MAP_LAST_UPDATED.with(Rc::clone);
    let mut last_updated = mutex.lock().await;

    // try again, maybe the file was loaded while we were waiting for the lock
    if let Some(device_id) = DEVICE_ID_MAP.with(|m| m.borrow().get(&device_address).cloned()) {
        return Ok(Some(device_id));
    }

    // file already read recently, returning with not found
    if last_updated.elapsed() < READ_FILE_COOLDOWN_TIME {
        return Ok(None);
    }

    // load new data from file
    let ids = get_wakaama_device_ids().await?;
    tracing::info!("Loaded {} device IDs from Wakaama state file.", ids.len());
    *last_updated = Instant::now();

    // we run single-threaded and there is no await in between, so we won't get interrupted and
    // having the map emptied in between is not a problem.
    let device_id = DEVICE_ID_MAP.with(|m| {
        let mut m = m.borrow_mut();
        m.clear();
        m.extend(ids);
        m.get(&device_address).cloned()
    });
    Ok(device_id)
}
