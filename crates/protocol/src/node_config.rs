use std::net::SocketAddr;
use std::str::FromStr;
use xdr::compound_types::LimitedString;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_info: NodeInfo,
    pub ip: String,
    pub listening_port: i32,
}
#[allow(dead_code)]
impl NodeConfig {
    /// Using the public mainnet node taken from here:
    /// https://stellarbeat.io/nodes/GAAV2GCVFLNN522ORUYFV33E76VPC22E72S75AQ6MBR5V45Z5DWVPWEU?center=1
    pub fn mainnet() -> Self {
        let node = NodeConfig {
            node_info: NodeInfo::mainnet(),
            ip: "35.233.35.143".into(),
            listening_port: 11625,
        };
        println!("Connecting to MAINNET node {:?}", node.sock_addr());
        node
    }

    pub fn local() -> Self {
        NodeConfig {
            node_info: NodeInfo::local(),
            ip: "127.0.0.1".into(),
            listening_port: 11625,
        }
    }
    pub fn sock_addr(&self) -> SocketAddr {
        SocketAddr::from_str(&format!("{}:{}", self.ip, self.listening_port)).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub version_string: LimitedString<100>,
    pub network_id: String,
}
#[allow(dead_code)]
impl NodeInfo {
    fn local() -> Self {
        Self {
            ledger_version: 19,
            overlay_version: 29,
            overlay_min_version: 27,
            version_string: LimitedString::new("v19.13.0".as_bytes().to_vec()).unwrap(),
            network_id: "Test SDF Network ; September 2015".to_string(),
        }
    }
    fn mainnet() -> Self {
        Self {
            ledger_version: 19,
            overlay_version: 29,
            overlay_min_version: 27,
            version_string: LimitedString::new("v19.13.0".as_bytes().to_vec()).unwrap(),
            network_id: "Public Global Stellar Network ; September 2015".to_string(),
        }
    }
}