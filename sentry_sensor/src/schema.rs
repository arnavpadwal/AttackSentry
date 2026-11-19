use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct FlowRecord {
    #[serde(rename = "Sensor_ID")]
    pub sensor_id: Option<String>,
    // Core Network Features (T1)
    #[serde(rename = "Src_IP")]
    pub src_ip: String,
    #[serde(rename = "Dst_IP")]
    pub dst_ip: String,
    #[serde(rename = "Src_Port")]
    pub src_port: u16,
    #[serde(rename = "Dst_Port")]
    pub dst_port: u16,
    #[serde(rename = "Protocol")]
    pub protocol: u8,
    #[serde(rename = "Flow_Duration")]
    pub flow_duration: f64,
    #[serde(rename = "Total_Fwd_Packets")]
    pub total_fwd_packets: u32,
    #[serde(rename = "Total_Bwd_Packets")]
    pub total_bwd_packets: u32,
    #[serde(rename = "Total_Fwd_Bytes")]
    pub total_fwd_bytes: u64,
    #[serde(rename = "Total_Bwd_Bytes")]
    pub total_bwd_bytes: u64,
    #[serde(rename = "Flow_IAT_Mean")]
    pub flow_iat_mean: f64,
    #[serde(rename = "FIN_Flag_Count")]
    pub fin_flag_count: u32,
    #[serde(rename = "SYN_Flag_Count")]
    pub syn_flag_count: u32,
    #[serde(rename = "RST_Flag_Count")]
    pub rst_flag_count: u32,
    #[serde(rename = "PSH_Flag_Count")]
    pub psh_flag_count: u32,
    #[serde(rename = "ACK_Flag_Count")]
    pub ack_flag_count: u32,
    #[serde(rename = "URG_Flag_Count")]
    pub urg_flag_count: u32,
    #[serde(rename = "TTL")]
    pub ttl: u8,

    // Identity & Context (T3)
    #[serde(rename = "User_ID")]
    pub user_id: Option<String>,
    #[serde(rename = "Identity_Type")]
    pub identity_type: Option<String>,
    #[serde(rename = "Process_Name")]
    pub process_name: Option<String>,
    #[serde(rename = "Process_ID")]
    pub process_id: Option<u32>,

    // Behavioral Features (Pre-calculated by Sensor)
    #[serde(rename = "Flow_IAT_Max")]
    pub flow_iat_max: Option<f64>,
    #[serde(rename = "Flow_IAT_Min")]
    pub flow_iat_min: Option<f64>,
    #[serde(rename = "Flow_IAT_Std")]
    pub flow_iat_std: Option<f64>,
    #[serde(rename = "Pkt_Len_Mean")]
    pub pkt_len_mean: Option<f64>,
    #[serde(rename = "Pkt_Len_Std")]
    pub pkt_len_std: Option<f64>,
    #[serde(rename = "Max_Pkt_Len")]
    pub max_pkt_len: Option<f64>,
    #[serde(rename = "Flow_Bytes_Sec")]
    pub flow_bytes_sec: Option<f64>,
    #[serde(rename = "Flow_Packets_Sec")]
    pub flow_packets_sec: Option<f64>,

    // Directional packet-length statistics (canonical schema alignment)
    #[serde(rename = "Fwd_Pkt_Len_Min")]
    pub fwd_pkt_len_min: Option<f64>,
    #[serde(rename = "Fwd_Pkt_Len_Max")]
    pub fwd_pkt_len_max: Option<f64>,
    #[serde(rename = "Fwd_Pkt_Len_Mean")]
    pub fwd_pkt_len_mean: Option<f64>,
    #[serde(rename = "Fwd_Pkt_Len_Std")]
    pub fwd_pkt_len_std: Option<f64>,
    #[serde(rename = "Bwd_Pkt_Len_Min")]
    pub bwd_pkt_len_min: Option<f64>,
    #[serde(rename = "Bwd_Pkt_Len_Max")]
    pub bwd_pkt_len_max: Option<f64>,
    #[serde(rename = "Bwd_Pkt_Len_Mean")]
    pub bwd_pkt_len_mean: Option<f64>,
    #[serde(rename = "Bwd_Pkt_Len_Std")]
    pub bwd_pkt_len_std: Option<f64>,

    // Metadata
    #[serde(rename = "Subnet_Group")]
    pub subnet_group: Option<String>,
    #[serde(rename = "Source_Subnet")]
    pub source_subnet: Option<String>,

    #[serde(rename = "Timestamp")]
    pub timestamp: String,
}
