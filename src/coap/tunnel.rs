// SPDX-FileCopyrightText: 2026 GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::coap::Server;
use coap_client::{MessageClass, Method, Packet, ResponseType};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use rand::random;
use std::cell::{Cell, RefCell};
use std::cmp::min;
use std::collections::{hash_map::Entry, HashMap};
use std::fmt::Display;
use std::io::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use tokio::io::split;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tracing::{info_span, Instrument, Span};

use super::messages::{CoapTxParams, TunnelInfo, TunnelStatus};

/// Size of buffer used for storing data from the tunnel endpoint.
///
/// The CBT11 can handle up to 1024 bytes. To make sure the whole ip packet fits
/// in 1024 bytes we chose
///
/// - IPv6 header: 40 Bytes
/// - UDP header:   8 Bytes
/// - CoAP header: 13 Bytes
/// _______________________
///   Total        61 Bytes => 64 bytes
///
/// although fitting all in 1024 bytes might not be a criteria anymore...
const NET_HEADER_SIZE_RESERVED: usize = 64; // Reserved size for header
const MAX_CBT11_NET_BUFFER: usize = 1024; // Network buffer size of CBT11
const TCP_BUFFER_SIZE: usize = MAX_CBT11_NET_BUFFER - NET_HEADER_SIZE_RESERVED;

/// Type for identifying tunnels.
///
/// A tunnels ID represents a CoAP resource that the client can use to tunnel
/// data. This type limits the maximum number of allowed tunnels per client.
pub type Id = u8;

type ClientInfoMap = HashMap<SocketAddr, ClientInfo>;

/// Tunnels are stored in a hash map. Almost always the Option is Some, only for a short period of
/// time while cleaning up the Option is None.
type TunnelMap = HashMap<Id, Rc<RefCell<Option<Tunnel>>>>;

// write_all() and shutdown() from AsyncWriteExt need Unpin
pub type Writer = Option<Pin<Box<dyn AsyncWrite>>>;

struct ClientInfo {
    next_tunnel_id: Id,
    tunnels: TunnelMap,
}

impl ClientInfo {
    fn new() -> Self {
        ClientInfo {
            next_tunnel_id: random(),
            tunnels: HashMap::default(),
        }
    }
}

#[derive(Clone)]
pub struct Tunnel {
    remote_addr: (String, u16),
    client_addr: SocketAddr,
    client_uri: String,
    coap_tx_params: CoapTxParams,
    task: Rc<Cell<Option<tokio::task::JoinHandle<()>>>>,
    // this needs to be a tokio Mutex, such that pending writes are queued in the correct order
    pub writer: Rc<tokio::sync::Mutex<Writer>>,
    status: Rc<Cell<TunnelStatus>>,
    server_state: &'static Server,
    device: String,
}

#[derive(Debug)]
pub struct Options {
    pub enable_tls: bool,
    pub verify_certificate: bool,
    pub tcp_nodelay: bool,
    pub coap_tx_params: CoapTxParams,
}

impl Tunnel {
    pub fn new(
        client_addr: SocketAddr,
        client_uri: String,
        remote_addr: (String, u16),
        tunnel_options: Options,
        server_state: &'static Server,
        device: &str,
    ) -> Self {
        let writer = Rc::new(tokio::sync::Mutex::new(None));
        let status = Rc::new(Cell::new(TunnelStatus::Connecting));

        let tunnel = Self {
            remote_addr: remote_addr.clone(),
            client_addr,
            client_uri: client_uri.clone(),
            coap_tx_params: tunnel_options.coap_tx_params,
            task: Rc::new(Cell::new(None)),
            writer: Rc::clone(&writer),
            status: Rc::clone(&status),
            server_state,
            device: device.to_string(),
        };

        // start connection
        let span = info_span!(parent:None, "connect", %device, %client_addr, client_uri, ?remote_addr, coap_tx_params = ?tunnel_options.coap_tx_params);
        span.follows_from(Span::current());
        tunnel.task.replace(Some(tokio::task::spawn_local(
            tunnel
                .clone()
                .connect(client_addr, client_uri, remote_addr, tunnel_options, writer)
                .instrument(span),
        )));

        tunnel
    }

    async fn connect(
        self,
        client_addr: SocketAddr,
        client_uri: String,
        remote_addr: (String, u16),
        tunnel_options: Options,
        writer: Rc<tokio::sync::Mutex<Writer>>,
    ) {
        tracing::info!("Establishing TCP connection.");
        let (reader, span) = match TcpStream::connect(remote_addr.clone()).await {
            Ok(stream) => {
                let tcp_local_addr = stream
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                // tcp_peer_addr is distinct from remote_addr, former contains the resolved
                // addresses, latter is the unresolved input from the client. Both may contain
                // useful information for debugging.
                let tcp_peer_addr = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                let span = info_span!("tcp_connected", tcp_local_addr, tcp_peer_addr);
                let enter = span.enter();

                if tunnel_options.tcp_nodelay {
                    if let Err(err) = stream.set_nodelay(true) {
                        tracing::error!(?err, "Cannot set TCP_NODELAY option. Ignoring.");
                    }
                }

                let reader = if tunnel_options.enable_tls {
                    tracing::info!(
                        verify_certificate = tunnel_options.verify_certificate,
                        "TCP connected. Initiating TLS."
                    );
                    let mut ssl_builder = SslConnector::builder(SslMethod::tls()).unwrap();
                    if !tunnel_options.verify_certificate {
                        ssl_builder.set_verify(SslVerifyMode::NONE);
                    }
                    let ssl = ssl_builder
                        .build()
                        .configure()
                        .unwrap()
                        .into_ssl(&remote_addr.0)
                        .unwrap();
                    let mut stream = SslStream::new(ssl, stream).unwrap();
                    if let Err(error) = Pin::new(&mut stream).connect().await {
                        tracing::warn!(
                            ?error,
                            verify_certificate = tunnel_options.verify_certificate,
                            "TLS setup failed."
                        );
                        self.status.set(TunnelStatus::Failed);
                        self.notify_closed().await;
                        return;
                    }
                    tracing::info!(
                        verify_certificate = tunnel_options.verify_certificate,
                        "TLS setup complete."
                    );
                    self.status.set(TunnelStatus::Connected);
                    let (reader, writer2) = split(stream);
                    writer.lock().await.replace(Box::pin(writer2));
                    // read() from AsyncReadExt needs Unpin
                    let reader: Pin<Box<dyn AsyncRead>> = Box::pin(reader);
                    reader
                } else {
                    tracing::info!("TCP connected.");
                    self.status.set(TunnelStatus::Connected);
                    let (reader, writer2) = split(stream);
                    writer.lock().await.replace(Box::pin(writer2));
                    Box::pin(reader)
                };

                let forward_span = info_span!(parent:None, "forward", device = %self.device, %client_addr, client_uri, ?remote_addr, tcp_local_addr, tcp_peer_addr);
                drop(enter);
                forward_span.follows_from(span);
                (reader, forward_span)
            }
            Err(error) => {
                tracing::warn!(?error, "Failed to establish TCP connection to remote host.");
                self.status.set(TunnelStatus::Failed);
                self.notify_closed().await;
                return;
            }
        };

        // start listening on tunnel
        self.task.replace(Some(tokio::task::spawn_local(
            self.clone()
                .forward(client_addr, client_uri, reader)
                .instrument(span),
        )));
    }

    async fn forward(
        mut self,
        client_addr: SocketAddr,
        client_uri: String,
        mut reader: Pin<Box<dyn AsyncRead>>,
    ) {
        // send empty tunnel data packet to signal successful connection
        match self.coap_request(Method::Post, Some([].as_ref())).await {
            Err(error) => {
                tracing::warn!(?error, "Failure sending CoAP request. Closing tunnel.");
                self.close().await;
            }
            Ok(response2) => {
                if let MessageClass::Response(ResponseType::Changed) = response2.header.code {
                } else {
                    tracing::warn!(response = ?response2, "Invalid CoAP response. Closing tunnel.");
                    self.close().await;
                }
            }
        }

        loop {
            let mut buf = [0u8; TCP_BUFFER_SIZE];
            let max_payload_size = min(
                self.coap_tx_params.max_payload_size.unwrap_or(usize::MAX),
                buf.len(),
            );
            let buf = &mut buf[..max_payload_size];
            let len = reader.read(buf).await.unwrap_or_else(|error| {
                tracing::warn!(?error, "Error while reading from TCP.");
                0
            });

            if len == 0 || self.status() != TunnelStatus::Connected {
                tracing::info!(
                    ?client_addr,
                    client_uri,
                    "TCP connection closed by remote server."
                );
                self.close().await;
                break;
            }

            // forward data to client
            let res = self.coap_request(Method::Post, Some(&buf[..len])).await;
            match res {
                Err(_err) => {
                    self.close().await;
                }
                Ok(response) => {
                    if let MessageClass::Response(ResponseType::Changed) = response.header.code {
                    } else {
                        tracing::warn!(?response, "Invalid CoAP response. Closing tunnel.");
                        self.close().await;
                    }
                }
            }
        }
    }

    pub fn client_uri(&self) -> String {
        self.client_uri.clone()
    }

    /// Closes TCP connection.
    ///
    /// Returns false if tunnel was already closed.
    pub async fn close(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }

        let writer_opt = self.writer.lock().await.take();
        if let Some(mut writer) = writer_opt {
            let res = writer.shutdown().await;
            if let Err(error) = res {
                tracing::warn!(?error, "Could not shut down TCP socket.");
            }
        }

        let do_notify_closed = {
            if self.status.get() == TunnelStatus::Closed {
                false
            } else {
                self.status.set(TunnelStatus::Closed);
                true
            }
        };

        if do_notify_closed {
            self.notify_closed().await;
        }
    }

    /// Notifies client about  closed tunnel.
    pub async fn notify_closed(&self) {
        let _ = self.coap_request(Method::Delete, None).await;
    }

    pub fn status(&self) -> TunnelStatus {
        self.status.get()
    }

    pub fn remote_addr(&self) -> (String, u16) {
        self.remote_addr.clone()
    }

    pub async fn coap_request(
        &self,
        method: Method,
        data: Option<&[u8]>,
    ) -> Result<Packet, coap_client::Error<Error>> {
        self.server_state
            .coap_request(
                self.client_addr,
                &self.client_uri,
                method,
                data,
                self.coap_tx_params,
            )
            .await
    }
}

impl Display for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (host, port) = self.remote_addr();
        write!(f, "tunnel to [{host}]:{port}")
    }
}

#[derive(Default)]
pub struct Tunnels {
    map: RefCell<ClientInfoMap>,
}

impl Tunnels {
    pub fn new() -> Self {
        Self {
            map: RefCell::new(ClientInfoMap::new()),
        }
    }

    pub fn add<F>(&self, client_addr: SocketAddr, tunnel_factory: F) -> Result<(), ()>
    where
        F: FnOnce(Id) -> Tunnel,
    {
        // TODO: Client  are never cleaned up, do some cleanup.
        let mut client_info_map = self.map.borrow_mut();
        let client_info = client_info_map
            .entry(client_addr)
            .or_insert_with(ClientInfo::new);

        // find unused tunnel id
        for _ in 0..Id::MAX {
            let tunnel_id = client_info.next_tunnel_id;
            client_info.next_tunnel_id = client_info.next_tunnel_id.wrapping_add(1);
            match client_info.tunnels.entry(tunnel_id) {
                Entry::Occupied(_) => continue,
                Entry::Vacant(entry) => {
                    entry.insert(Rc::new(RefCell::new(Some(tunnel_factory(tunnel_id)))));
                    return Ok(());
                }
            }
        }

        // no free tunnel id found
        Err(())
    }

    pub fn get(
        &self,
        client_addr: &SocketAddr,
        tunnel_id: Id,
    ) -> Option<Rc<RefCell<Option<Tunnel>>>> {
        self.map
            .borrow()
            .get(client_addr)
            .and_then(|x| x.tunnels.get(&tunnel_id).cloned())
    }

    /// Remove tunnel from collection
    pub fn take(&self, client_addr: &SocketAddr, tunnel_id: Id) -> Option<Tunnel> {
        self.map
            .borrow_mut()
            .get_mut(client_addr)?
            .tunnels
            .remove(&tunnel_id)?
            .take()
    }

    /// Remove all tunnels associated with a client.
    ///
    /// An optional tunnel list is returned, those tunnels should then be closed by the caller if
    /// not used anymore.
    pub fn remove(&self, client_addr: &SocketAddr) -> Option<TunnelMap> {
        self.map.borrow_mut().remove(client_addr).map(|x| x.tunnels)
    }

    pub fn to_tunnel_info_vec(&self, client_addr: &SocketAddr) -> Vec<TunnelInfo> {
        let client_info_map = self.map.borrow();
        let client_tunnels = if let Some(p) = client_info_map.get(client_addr) {
            &p.tunnels
        } else {
            return Vec::new();
        };

        let mut tunnel_infos: Vec<TunnelInfo> = Vec::with_capacity(client_tunnels.len());

        for (index, tunnel) in client_tunnels {
            match tunnel.borrow().as_ref() {
                Some(tunnel) => {
                    let client_host = match tunnel.client_addr {
                        SocketAddr::V4(a) => format!("{}", a.ip()),
                        SocketAddr::V6(a) => format!("[{}]", a.ip()),
                    };
                    let (host, port) = tunnel.remote_addr();
                    tunnel_infos.push(TunnelInfo {
                        client_uri: format!(
                            "coap://{}:{}/{}",
                            client_host,
                            tunnel.client_addr.port(),
                            tunnel.client_uri()
                        ),
                        id: index.to_string(),
                        host,
                        port,
                        state: tunnel.status(),
                    });
                }
                None => continue,
            }
        }
        tunnel_infos
    }
}
