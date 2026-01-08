use crate::domain::protocol::discovery::{Discovery, Peer};
use local_ip_address::local_ip;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::time::Duration;

pub const SERVICE_PORT: u16 = 65432;

pub struct MdnsDiscovery {
    daemon: ServiceDaemon,
}

impl MdnsDiscovery {
    pub fn new() -> Self {
        let daemon = ServiceDaemon::new().expect("failed to start mdns daemon");
        Self { daemon }
    }
}

impl Discovery for MdnsDiscovery {
    fn advertise(&self, service_name: &str, hash: &[u8]) {
        let service_type = format!("_{}._udp.local.", service_name);
        let hash = hex::encode(hash);
        let txt_props: &[(&str, &str)] = &[("hash", &hash)];
        let hostname = format!("{}.local.", gethostname::gethostname().to_string_lossy());
        let ip = local_ip().expect("failed to get ip address");

        let info = ServiceInfo::new(&service_type, service_name, &hostname, ip, SERVICE_PORT, txt_props)
            .expect("invalid mdns service info");

        self.daemon
            .register(info)
            .expect("failed to register mdns service");
    }

    fn discover(&self, service_name: &str, hash: &[u8]) -> Vec<Peer> {
        let mut peers = Vec::new();

        let service_type = format!("_{}._udp.local.", service_name);
        let receiver = self.daemon.browse(&service_type).expect("failed to browse");

        let timeout = Duration::from_secs(3);

        while let Ok(event) = receiver.recv_timeout(timeout) {
            if let ServiceEvent::ServiceResolved(info) = event {
                if info
                    .get_property_val_str("hash")
                    .map(|service_hash| service_hash == hex::encode(&hash))
                    .unwrap_or(false)
                {
                    peers.push(Peer {
                        host: info.host,
                        port: info.port,
                    });
                }
            }
        }

        peers
    }
}
