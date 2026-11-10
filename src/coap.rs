// SPDX-FileCopyrightText: 2026 GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use coap_client::{Method, Packet, RequestOptions, TokioClient};
use coap_lite::{
    CoapOption, CoapRequest as Request, CoapResponse as Response, RequestType, ResponseType,
};
use serde_json::from_slice as json_from_slice;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Error;
use std::net::SocketAddr;
use std::rc::Rc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep_until, Duration, Instant};
use tracing::Level;

mod messages;

use messages::{OpenTunnelMessage, ServerStateMessage, TunnelStatus};

mod tunnel;

// use crate::COAP_BUFFER_SIZE;
use crate::coap::messages::CoapTxParams;
use crate::coap::tunnel::Options as TunnelOptions;
use crate::coap::RxTx::{Rx, Tx};
use tunnel::{Id as TunnelId, Tunnel, Tunnels};

// Optimized for CBT11 via Lemonbeat
// See comment in mower repo SW/ComBoard/36.12_Com_App_T11/Config/CoapClientServerCfg.h
const COAP_SERVER_EXCHANGE_LIFETIME: u64 = 100;

const COAP_CLIENT_MAX_RETRANSMIT: usize = 5;
const COAP_CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(180);

type DuplicatesCacheKey = (Option<SocketAddr>, u16);

enum DuplicatesCacheValueOrGuard {
    Value(Response),
    Guard(broadcast::Receiver<Response>),
}

enum RxTx<T> {
    Rx(broadcast::Receiver<T>),
    Tx(broadcast::Sender<T>),
}

pub struct Server {
    tunnels: Tunnels,
    coap_client: TokioClient,
    duplicates_cache: RefCell<HashMap<DuplicatesCacheKey, DuplicatesCacheValueOrGuard>>,
    duplicates_cache_expirations: mpsc::UnboundedSender<(Instant, DuplicatesCacheKey)>,
    tcp_nodelay: bool,
}

impl Server {
    pub fn new(coap_client: TokioClient, tcp_nodelay: bool) -> &'static Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let instance = Self {
            tunnels: Tunnels::new(),
            coap_client,
            duplicates_cache: RefCell::new(HashMap::new()),
            duplicates_cache_expirations: tx,
            tcp_nodelay,
        };
        let instance = Box::leak(Box::new(instance));
        tokio::task::spawn_local(instance.duplicates_cache_cleaner(rx));
        instance
    }

    #[tracing::instrument(ret(level = Level::DEBUG), skip_all, fields(%device, ?request.message.header, request.path = ?request.get_path(), request.message.token = ?hex::encode(request.message.get_token()), request.message.options = ?request.message.options().collect::<Vec<_>>(), request.message.payload_len = request.message.payload.len(), ?request.source))]
    pub async fn handle_request(
        &'static self,
        request: Request<SocketAddr>,
        device: &str,
    ) -> Response {
        tracing::debug!("Handling CoAP request.");

        // The coap library is dumb and does not filter duplicates :-( so we have to do it
        // This is a simple solution. I wanted to use some fancy crate like quick_cache, but our
        // rust compiler is too old :-( With quick_cache I could have used get_value_or_guard_async
        // which would have solved a lot of my problems.
        let key = (request.source, request.message.header.message_id);

        let rx_tx = {
            let mut cache = self.duplicates_cache.borrow_mut();
            if let Some(response_or_guard) = cache.get(&key) {
                match response_or_guard {
                    DuplicatesCacheValueOrGuard::Value(response) => {
                        tracing::debug!("Duplicates cache hit.");
                        return response.clone();
                    }
                    DuplicatesCacheValueOrGuard::Guard(guard) => {
                        tracing::debug!("Duplicates cache hit, waiting for worker.");
                        Rx(guard.resubscribe())
                    }
                }
            } else {
                // no entry found in cache, insert a guard
                let (tx, rx) = broadcast::channel(1);
                cache.insert(key, DuplicatesCacheValueOrGuard::Guard(rx));
                Tx(tx)
            }
        };

        let tx = match rx_tx {
            Rx(mut rx) => {
                let res = rx.recv().await.unwrap();
                tracing::debug!("Duplicates cache waiting for worker completed.");
                return res;
            }
            Tx(tx) => tx,
        };

        let response = self.handle_request_inner(request, device).await;

        // update cache and inform guard watchers
        {
            let mut cache = self.duplicates_cache.borrow_mut();
            cache.insert(key, DuplicatesCacheValueOrGuard::Value(response.clone()));
            let _ = tx.send(response.clone()); // ignore when there is no listener
        }

        // inform duplicates cleaner task
        let exp_time = Instant::now() + Duration::new(COAP_SERVER_EXCHANGE_LIFETIME, 0);
        self.duplicates_cache_expirations
            .send((exp_time, key))
            .unwrap();

        response
    }

    async fn duplicates_cache_cleaner(
        &'static self,
        mut rx: mpsc::UnboundedReceiver<(Instant, DuplicatesCacheKey)>,
    ) {
        while let Some((deadline, key)) = rx.recv().await {
            sleep_until(deadline).await;
            let mut cache = self.duplicates_cache.borrow_mut();
            cache.remove(&key);
        }
    }

    pub async fn handle_request_inner(
        &'static self,
        request: Request<SocketAddr>,
        device: &str,
    ) -> Response {
        let client_addr = request.source.unwrap();
        let path = request.get_path();

        if Server::is_root(&path) {
            self.handle_request_root(request, client_addr, device).await
        } else {
            self.handle_request_tunnel(request, client_addr, path).await
        }
    }

    async fn handle_request_root(
        &'static self,
        request: Request<SocketAddr>,
        client_addr: SocketAddr,
        device: &str,
    ) -> Response {
        match request.get_method() {
            RequestType::Get => {
                let tunnel_info = self.tunnels.to_tunnel_info_vec(&client_addr);
                let state = ServerStateMessage {
                    is_network_connected: true, // TODO: replace with actual value
                    tunnels: tunnel_info,
                };
                match serde_json::to_vec(&state) {
                    Ok(state) => {
                        Server::create_response(request, Some(state), ResponseType::Content)
                    }
                    Err(error) => {
                        tracing::warn!(?error, "Could not serialize server state.");
                        Server::create_response(request, None, ResponseType::InternalServerError)
                    }
                }
            }
            RequestType::Post => self.handle_open_tunnel(request, device),
            RequestType::Delete => {
                let response = Server::create_response(request, None, ResponseType::Deleted);
                self.delete_tunnels(&client_addr).await;
                response
            }
            _ => {
                tracing::warn!(method=?request.get_method(), "Method is not allowed.");
                Server::create_response(request, None, ResponseType::MethodNotAllowed)
            }
        }
    }

    async fn handle_request_tunnel(
        &'static self,
        request: Request<SocketAddr>,
        client_addr: SocketAddr,
        path: String,
    ) -> Response {
        let Some(tunnel_id) = Server::tunnel_id_from_path(&path) else {
            return Server::create_response(request, None, ResponseType::BadRequest);
        };
        let (response, write_op) = match request.get_method() {
            RequestType::Post => {
                if let Some(tunnel) = self.tunnels.get(&client_addr, tunnel_id) {
                    if let Some(tunnel) = &*tunnel.borrow() {
                        match tunnel.status() {
                            TunnelStatus::Connecting => {
                                let response = Server::create_response(
                                    request,
                                    None,
                                    ResponseType::MethodNotAllowed,
                                );
                                (response, None)
                            }
                            TunnelStatus::Connected => {
                                let mut request = request;
                                let payload = std::mem::take(&mut request.message.payload);
                                let response =
                                    Server::create_response(request, None, ResponseType::Changed);
                                (response, Some((Rc::clone(&tunnel.writer), payload)))
                            }
                            TunnelStatus::Closed | TunnelStatus::Failed => {
                                let response = Server::create_response(
                                    request,
                                    None,
                                    ResponseType::BadGateway,
                                );
                                (response, None)
                            }
                        }
                    } else {
                        let response =
                            Server::create_response(request, None, ResponseType::NotFound);
                        (response, None)
                    }
                } else {
                    let response = Server::create_response(request, None, ResponseType::NotFound);
                    (response, None)
                }
            }
            RequestType::Delete => {
                let response = Server::create_response(request, None, ResponseType::Deleted);
                self.delete_tunnel(&client_addr, tunnel_id).await;
                (response, None)
            }
            _ => {
                tracing::warn!(method=?request.get_method(), "Method is not allowed.");
                let response =
                    Server::create_response(request, None, ResponseType::MethodNotAllowed);
                (response, None)
            }
        };

        // This block contains an await, we must not await while the RefCell `tunnel` is borrowed,
        // so we do the write operation here after we dropped the borrowed Ref.
        if let Some((writer, buf)) = write_op {
            if let Some(w) = writer.lock().await.as_mut() {
                if let Err(error) = w.write_all(&buf).await {
                    tracing::warn!(?error, "Could not send TCP data.");
                }
            }
        }

        response
    }

    pub fn create_response(
        request: Request<SocketAddr>,
        payload: Option<Vec<u8>>,
        status: ResponseType,
    ) -> Response {
        let mut response = request.response.unwrap();
        match payload {
            Some(payload) => response.message.payload = payload,
            None => response.message.payload.clear(),
        }
        response.set_status(status);
        response
    }

    // TODO: return result type
    pub fn handle_open_tunnel(
        &'static self,
        request: Request<SocketAddr>,
        device: &str,
    ) -> Response {
        let client_addr = request.source.unwrap();

        let msg_res: Result<OpenTunnelMessage, _> = json_from_slice(&request.message.payload[..]);
        let mut response = Self::create_response(request, None, ResponseType::Created);
        let msg = match msg_res {
            Err(error) => {
                tracing::warn!(?error, "Could not deserialize \"open tunnel\" message.");
                response.set_status(ResponseType::BadRequest);
                return response;
            }
            Ok(msg) => msg,
        };

        if let Err(()) = self.tunnels.add(client_addr, |tunnel_id| {
            response
                .message
                .add_option(CoapOption::LocationPath, tunnel_id.to_string().into_bytes());

            Tunnel::new(
                client_addr,
                msg.client_uri,
                (msg.host, msg.port),
                TunnelOptions {
                    enable_tls: msg.use_tls,
                    verify_certificate: msg.verify_certificate,
                    tcp_nodelay: self.tcp_nodelay,
                    coap_tx_params: msg.coap_tx_params,
                },
                self,
                device,
            )
        }) {
            response.set_status(ResponseType::InternalServerError);
        }

        response
    }

    /// Closes and deletes all tunnels associated with a clients address.
    async fn delete_tunnels(&self, client_addr: &SocketAddr) {
        if let Some(mut tunnels) = self.tunnels.remove(client_addr) {
            for (_, tunnel) in tunnels.drain() {
                let tunnel = tunnel.borrow_mut().take();
                if let Some(mut t) = tunnel {
                    t.close().await;
                }
            }
        }
    }

    /// Closes and deletes tunnel.
    async fn delete_tunnel(&self, client_addr: &SocketAddr, tunnel_id: TunnelId) {
        if let Some(mut tunnel) = self.tunnels.take(client_addr, tunnel_id) {
            tunnel.close().await;
        }
    }

    pub fn is_root(path: &str) -> bool {
        path.is_empty() || path == "/"
    }

    // TODO: return result type
    pub fn tunnel_id_from_path(path: &str) -> Option<TunnelId> {
        match path.parse() {
            Ok(t) => Some(t),
            Err(error) => {
                tracing::warn!(?error, "Failed to convert path to tunnel id.");
                None
            }
        }
    }

    #[tracing::instrument(ret(level = Level::DEBUG), err(level = Level::WARN), skip(self, data), name = "send_request", fields(data_len = data.unwrap_or_default().len()))]
    pub async fn coap_request(
        &self,
        peer_addr: SocketAddr,
        path: &str,
        method: Method,
        data: Option<&[u8]>,
        tx_params: CoapTxParams,
    ) -> Result<Packet, coap_client::Error<Error>> {
        tracing::debug!("Sending CoAP request.");

        let path = path.to_string();

        let request_options = RequestOptions {
            non_confirmable: false,
            retries: tx_params
                .max_retransmit
                .unwrap_or(COAP_CLIENT_MAX_RETRANSMIT),
            ack_timeout: tx_params
                .ack_timeout
                .unwrap_or(RequestOptions::default().ack_timeout),
            ack_random_factor: tx_params
                .ack_random_factor
                .unwrap_or(RequestOptions::default().ack_random_factor),
            response_timeout: tx_params
                .response_timeout
                .unwrap_or(COAP_CLIENT_RESPONSE_TIMEOUT),
            backoff_factor: tx_params
                .backoff_factor
                .unwrap_or(RequestOptions::default().backoff_factor),
        };

        self.coap_client
            .request(method, peer_addr, &path, data, &request_options)
            .await
    }
}
