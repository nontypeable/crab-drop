#[derive(Debug, Clone)]
pub struct Peer {
    pub host: String,
    pub port: u16,
}

pub trait Discovery {
    fn advertise(&self, service_name: &str, hash: &[u8]);
    fn discover(&self, service_name: &str, hash: &[u8]) -> Vec<Peer>;
}
