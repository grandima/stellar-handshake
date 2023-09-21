#[derive(Debug)]
pub struct NodeConfig {
    pub network: String,
    node_info: NodeInfo,
    listening_port: u32,
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
                version_string: "v19.13.0".to_string(),
                network_id: Some("Test SDF Network ; September 2015".to_string()),
            },
            listening_port: 11602,
            private_key: Some("SCL4SDOGTLHEJ6OMDIMYXRC4JA75P2SY3F2X7ZJ2TMNCXT3FSJVGS2BO".to_string()),
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
    pub version_string: String,
    pub network_id: Option<String>,
}