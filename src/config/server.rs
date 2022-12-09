use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use rustls::{
    cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    },
    server::{NoClientAuth, ResolvesServerCertUsingSni},
    sign::{any_supported_type, CertifiedKey},
    ServerConfig, ALL_CIPHER_SUITES, ALL_KX_GROUPS, ALL_VERSIONS,
};
use tokio::net::TcpSocket;

use super::{
    certificate::{CertificateResolver, TLS12_VERSION, TLS13_VERSION},
    utils::ParseKey,
    Config, Server, ServerProtocol,
};

impl Config {
    pub fn build_servers(&self) -> super::Result<Vec<Server>> {
        let mut servers: Vec<Server> = Vec::new();

        for array_pos in self.sub_keys("server.listener") {
            let server = self.build_server(array_pos)?;
            if !servers.iter().any(|s| s.id == server.id) {
                servers.push(server);
            } else {
                return Err(format!("Duplicate listener id {:?}.", server.id));
            }
        }

        if !servers.is_empty() {
            Ok(servers)
        } else {
            Err("No server directives found in config file.".to_string())
        }
    }

    fn build_server(&self, array_pos: &str) -> super::Result<Server> {
        // Obtain server id
        let id = self.property_require::<String>(("server.listeners", array_pos, "id"))?;

        // Build TLS config
        let (tls, tls_implicit) = if self
            .property_or_default(
                ("server.listener", array_pos, "tls.enable"),
                "server.tls.enable",
            )?
            .unwrap_or(false)
        {
            // Parse protocol versions
            let mut tls_v2 = false;
            let mut tls_v3 = false;
            for (key, protocol) in self.properties_or_default::<String>(
                ("server.listener", array_pos, "tls.protocols"),
                "server.tls.protocols",
            ) {
                match protocol?.as_str() {
                    "TLSv1.2" | "0x0303" => tls_v2 = true,
                    "TLSv1.3" | "0x0304" => tls_v3 = true,
                    protocol => {
                        return Err(format!(
                            "Unsupported TLS protocol {:?} found in key {:?}",
                            protocol, key
                        ))
                    }
                }
            }
            if !tls_v2 && !tls_v3 {
                return Err(format!("No TLS protocols configured for listener {:?}", id));
            }

            // Parse cipher suites
            let mut ciphers = Vec::new();
            for (key, protocol) in self.properties_or_default::<String>(
                ("server.listener", array_pos, "tls.cipher"),
                "server.tls.cipher",
            ) {
                ciphers.push(match protocol?.as_str() {
                    // TLS1.3 suites
                    "TLS13_AES_256_GCM_SHA384" => TLS13_AES_256_GCM_SHA384,
                    "TLS13_AES_128_GCM_SHA256" => TLS13_AES_128_GCM_SHA256,
                    "TLS13_CHACHA20_POLY1305_SHA256" => TLS13_CHACHA20_POLY1305_SHA256,
                    // TLS1.2 suites
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    }
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    }
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                    }
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    }
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    }
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                    }
                    cipher => {
                        return Err(format!(
                            "Unsupported TLS cipher suite {:?} found in key {:?}",
                            cipher, key
                        ))
                    }
                });
            }

            // Obtain default certificate
            let cert_id = self
                .property_or_default::<String>(
                    ("server.listener", array_pos, "tls.certificate"),
                    "server.tls.certificate",
                )?
                .ok_or_else(|| format!("Undefined certificate id for listener {:?}.", id))?;
            let cert = self.rustls_certificate(&cert_id)?;
            let pki = self.rustls_private_key(&cert_id)?;

            // Add SNI certificates
            let mut resolver = ResolvesServerCertUsingSni::new();
            for (key, value) in self.properties_or_default::<String>(
                ("server.listener", array_pos, "tls.sni"),
                "server.tls.sni",
            ) {
                if let Some(prefix) = key.strip_suffix(".subject") {
                    resolver
                        .add(
                            value?.as_str(),
                            match self.property::<String>((prefix, "cert"))? {
                                Some(sni_cert_id) if sni_cert_id != cert_id => CertifiedKey {
                                    cert: vec![self.rustls_certificate(&sni_cert_id)?],
                                    key: any_supported_type(
                                        &self.rustls_private_key(&sni_cert_id)?,
                                    )
                                    .map_err(|err| {
                                        format!(
                                            "Failed to sign SNI certificate for {:?}: {}",
                                            key, err
                                        )
                                    })?,
                                    ocsp: None,
                                    sct_list: None,
                                },
                                _ => CertifiedKey {
                                    cert: vec![cert.clone()],
                                    key: any_supported_type(&pki).map_err(|err| {
                                        format!(
                                            "Failed to sign SNI certificate for {:?}: {}",
                                            key, err
                                        )
                                    })?,
                                    ocsp: None,
                                    sct_list: None,
                                },
                            },
                        )
                        .map_err(|err| {
                            format!("Failed to add SNI certificate for {:?}: {}", key, err)
                        })?;
                }
            }

            // Add default certificate
            let default_cert = Some(Arc::new(CertifiedKey {
                cert: vec![cert],
                key: any_supported_type(&pki).map_err(|err| {
                    format!("Failed to sign certificate id {:?}: {}", cert_id, err)
                })?,
                ocsp: None,
                sct_list: None,
            }));

            // Build server config
            let mut config = ServerConfig::builder()
                .with_cipher_suites(if !ciphers.is_empty() {
                    &ciphers
                } else {
                    ALL_CIPHER_SUITES
                })
                .with_kx_groups(&ALL_KX_GROUPS)
                .with_protocol_versions(if tls_v3 && tls_v2 {
                    ALL_VERSIONS
                } else if tls_v3 {
                    TLS13_VERSION
                } else {
                    TLS12_VERSION
                })
                .map_err(|err| format!("Failed to build TLS config: {}", err))?
                .with_client_cert_verifier(NoClientAuth::new())
                .with_cert_resolver(Arc::new(CertificateResolver {
                    resolver,
                    default_cert,
                }));

            //config.key_log = Arc::new(KeyLogger::default());
            config.ignore_client_order = self
                .property_or_default(
                    ("server.listener", array_pos, "tls.ignore_client_order"),
                    "server.tls.ignore_client_order",
                )?
                .unwrap_or(true);
            (
                config.into(),
                self.property_or_default(
                    ("server.listener", array_pos, "tls.implicit"),
                    "server.tls.implicit",
                )?
                .unwrap_or(true),
            )
        } else {
            (None, false)
        };

        // Build listeners
        let mut listeners = Vec::new();
        for (_, addr) in self.properties::<SocketAddr>(("server.listener", array_pos, "bind")) {
            // Parse bind address and build socket
            let addr = addr?;
            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .map_err(|err| format!("Failed to create socket: {}", err))?;

            // Set socket options
            for option in [
                "reuse-addr",
                "reuse-port",
                "send-buffer-size",
                "recv-buffer-size",
                "linger",
                "tos",
            ] {
                if let Some(value) = self.property_or_default::<String>(
                    ("server.listener", array_pos, "socket", option),
                    ("server.socket", option),
                )? {
                    match option {
                        "reuse-addr" => socket.set_reuseaddr(value.parse_key(option)?),
                        "reuse-port" => socket.set_reuseport(value.parse_key(option)?),
                        "send-buffer-size" => socket.set_send_buffer_size(value.parse_key(option)?),
                        "recv-buffer-size" => socket.set_recv_buffer_size(value.parse_key(option)?),
                        "linger" => socket
                            .set_linger(Duration::from_millis(value.parse_key(option)?).into()),
                        "tos" => socket.set_tos(value.parse_key(option)?),
                        _ => unreachable!(),
                    }
                    .map_err(|err| {
                        format!(
                            "Failed to set socket option '{}' for listener '{}': {}",
                            option, id, err
                        )
                    })?;
                }
            }

            // Bind socket
            socket.bind(addr).map_err(|err| {
                format!(
                    "Failed to bind to '{}' for listener '{}': {}",
                    addr, id, err
                )
            })?;

            // Listen
            let listener = socket
                .listen(
                    self.property_or_default(
                        ("server.listener", array_pos, "socket.backlog"),
                        "server.socket.backlog",
                    )?
                    .unwrap_or(1024),
                )
                .map_err(|err| {
                    format!(
                        "Failed to listen on '{}' for listener '{}': {}",
                        addr, id, err
                    )
                })?;

            // Set TTL parameter
            if let Some(ttl) = self.property_or_default(
                ("server.listener", array_pos, "socket.ttl"),
                "server.socket.ttl",
            )? {
                listener.set_ttl(ttl).map_err(|err| {
                    format!(
                        "Failed to set socket option 'ttl' for listener '{}': {}",
                        id, err
                    )
                })?;
            }
            listeners.push(listener);
        }

        if listeners.is_empty() {
            return Err(format!(
                "No 'bind' directive found for listener id {:?}",
                id
            ));
        }

        Ok(Server {
            id,
            hostname: self
                .property_or_default(
                    ("server.listener", array_pos, "hostname"),
                    "server.hostname",
                )?
                .ok_or("Hostname directive not found.")?,
            greeting: self
                .property_or_default(
                    ("server.listener", array_pos, "greeting"),
                    "server.greeting",
                )?
                .unwrap_or_else(|| "Stalwart SMTP at your service".to_string()),
            protocol: self
                .property_or_default(
                    ("server.listener", array_pos, "protocol"),
                    "server.protocol",
                )?
                .unwrap_or(ServerProtocol::Smtp),
            listeners,
            tls,
            tls_implicit,
        })
    }
}

impl FromStr for ServerProtocol {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("smtp") {
            Ok(Self::Smtp)
        } else if s.eq_ignore_ascii_case("lmtp") {
            Ok(Self::Lmtp)
        } else {
            Err(())
        }
    }
}
