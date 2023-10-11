use std::net::SocketAddr;
use std::str::FromStr;
use crate::xdr::lengthed_array::LengthedArray;

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_info: NodeInfo,
    pub ip: String,
    pub listening_port: u32,
}
impl NodeConfig {
    pub fn local() -> Self {
        NodeConfig {
            node_info: NodeInfo::local(),
            ip: "127.0.0.1".into(),
            listening_port: 11625,
        }
    }
    pub(crate) fn sock_addr(&self) -> SocketAddr {
        SocketAddr::from_str(&format!("{}:{}", self.ip, self.listening_port)).unwrap()
    }
}
impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            node_info: NodeInfo::default(),
            ip: "35.233.35.143".into(),
            listening_port: 11625,
        }
    }
}
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub version_string: LengthedArray,
    pub network_id: String,
}
impl NodeInfo {
    fn local() -> Self {
        Self {
            ledger_version: 19,
            overlay_version: 29,
            overlay_min_version: 27,
            version_string: "v19.13.0".try_into().unwrap(),
            network_id: "Test SDF Network ; September 2015".to_string(),
        }
    }
}
impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            ledger_version: 19,
            overlay_version: 29,
            overlay_min_version: 27,
            version_string: "v19.13.0".try_into().unwrap(),
            network_id: "Public Global Stellar Network ; September 2015".to_string(),
        }
    }
}