use crate::xdr::lengthed_array::LengthedArray;

#[derive(Debug)]
pub struct NodeConfig {
    pub network: String,
    pub node_info: NodeInfo,
    pub listening_port: u32,
}
impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            ledger_version: 17,
            overlay_version: 29,
            overlay_min_version: 17,
            version_string: "v19.13.0".try_into().unwrap(),
            network_id: "Test SDF Network ; September 2015".to_string(),
        }
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            node_info: NodeInfo::default(),
            listening_port: 11602,
            network: "Test SDF Network ; September 2015".to_string(),
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