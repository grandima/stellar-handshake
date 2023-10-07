use crate::xdr::lengthed_array::LengthedArray;

#[derive(Debug)]
pub struct NodeConfig {
    pub node_info: NodeInfo,
    pub listening_port: u32,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            node_info: NodeInfo::default(),
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
impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            ledger_version: 19,
            overlay_version: 29,
            overlay_min_version: 27,
            version_string: "v19.14.0".try_into().unwrap(),
            network_id: "Public Global Stellar Network ; September 2015".to_string(),
        }
    }
}