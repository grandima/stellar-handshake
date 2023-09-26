use crate::xdr::compound_types::LimitedVarOpaque;

#[derive(Debug)]
pub struct NodeConfig {
    pub network: String,
    pub node_info: NodeInfo,
    pub listening_port: u32,
    private_key: Option<String>,
    receive_transaction_messages: bool,
    receive_scp_messages: bool,
    max_flood_message_capacity: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            node_info: NodeInfo {
                ledger_version: 17,
                overlay_version: 29,
                overlay_min_version: 17,
                version_string: "v19.13.0".try_into().unwrap(),
                network_id: Some("Test SDF Network ; September 2015".to_string()),
            },
            listening_port: 11602,
            private_key: Some("SCL4SDOGTLHEJ6OMDIMYXRC4JA75P2SY3F2X7ZJ2TMNCXT3FSJVGS2BO".to_string()),
            //TODO: check if these fields are needed
            receive_transaction_messages: true,
            receive_scp_messages: true,
            network: "Test SDF Network ; September 2015".to_string(),
            max_flood_message_capacity: 2000,
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