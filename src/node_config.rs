use crate::xdr::compound_types::LimitedVarOpaque;

#[derive(Debug)]
pub struct NodeConfig {
    pub network: String,
    pub node_info: NodeInfo,
    pub listening_port: u32,
    //TODO: should I generate this?
    private_key: Option<String>,
}
impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            ledger_version: 17,
            overlay_version: 29,
            overlay_min_version: 17,
            version_string: "v19.13.0".try_into().unwrap(),
            network_id: Some("Test SDF Network ; September 2015".to_string()),
        }
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            node_info: NodeInfo::default(),
            listening_port: 11602,
            private_key: Some("SCL4SDOGTLHEJ6OMDIMYXRC4JA75P2SY3F2X7ZJ2TMNCXT3FSJVGS2BO".to_string()),
            network: "Test SDF Network ; September 2015".to_string(),
        }
    }
}
#[derive(Debug)]
pub struct NodeInfo {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub version_string: LimitedVarOpaque<100>,
    pub network_id: Option<String>,
}