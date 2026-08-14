"""
NIDS Flow Feature Extraction Utilities
======================================
Computes the 79 CICFlowMeter-style features from raw bidirectional
network flows, mirroring the exact feature set used during training.
"""

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
import time
import struct

# Minimum packet count to consider a flow ready for classification
MIN_FLOW_PACKETS = 2
# Flow timeout in seconds (flows idle for this long are considered finished)
FLOW_TIMEOUT = 120
# Maximum flow duration in seconds
MAX_FLOW_DURATION = 300

# Well-known ports list for heuristic protocol detection
WELL_KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465,
    514, 515, 520, 546, 547, 587, 636, 993, 995, 1194, 1433,
    1434, 1521, 1701, 1723, 1812, 1813, 2049, 2082, 2083,
    3306, 3389, 5060, 5061, 5432, 5900, 5984, 6379, 6443,
    6881, 6888, 8000, 8008, 8080, 8443, 8888, 9000, 9090,
    9200, 9300, 11211, 27017, 27018, 27019, 50000, 50070,
}


@dataclass
class PacketInfo:
    """Lightweight representation of a single captured packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # IP protocol number (6=TCP, 17=UDP)
    length: int  # IP total length
    flags: int = 0  # TCP flags bitmap
    header_len: int = 0  # IP header length + transport header length
    tcp_window: int = 0  # TCP window size
    urgent: bool = False
    push: bool = False


@dataclass
class FlowFeatures:
    """All 79 features extracted from a bidirectional flow, in the EXACT order the XGBoost model expects."""
    # Source Port is dropped by training pipeline
    Destination_Port: float = 0.0
    Protocol: float = 0.0
    Flow_Duration: float = 0.0
    Total_Fwd_Packets: float = 0.0
    Total_Backward_Packets: float = 0.0
    Total_Length_of_Fwd_Packets: float = 0.0
    Total_Length_of_Bwd_Packets: float = 0.0
    Fwd_Packet_Length_Max: float = 0.0
    Fwd_Packet_Length_Min: float = 0.0
    Fwd_Packet_Length_Mean: float = 0.0
    Fwd_Packet_Length_Std: float = 0.0
    Bwd_Packet_Length_Max: float = 0.0
    Bwd_Packet_Length_Min: float = 0.0
    Bwd_Packet_Length_Mean: float = 0.0
    Bwd_Packet_Length_Std: float = 0.0
    Flow_Bytess: float = 0.0
    Flow_Packetss: float = 0.0
    Flow_IAT_Mean: float = 0.0
    Flow_IAT_Std: float = 0.0
    Flow_IAT_Max: float = 0.0
    Flow_IAT_Min: float = 0.0
    Fwd_IAT_Total: float = 0.0
    Fwd_IAT_Mean: float = 0.0
    Fwd_IAT_Std: float = 0.0
    Fwd_IAT_Max: float = 0.0
    Fwd_IAT_Min: float = 0.0
    Bwd_IAT_Total: float = 0.0
    Bwd_IAT_Mean: float = 0.0
    Bwd_IAT_Std: float = 0.0
    Bwd_IAT_Max: float = 0.0
    Bwd_IAT_Min: float = 0.0
    Fwd_PSH_Flags: float = 0.0
    Bwd_PSH_Flags: float = 0.0
    Fwd_URG_Flags: float = 0.0
    Bwd_URG_Flags: float = 0.0
    Fwd_Header_Length: float = 0.0
    Bwd_Header_Length: float = 0.0
    Fwd_Packetss: float = 0.0
    Bwd_Packetss: float = 0.0
    Min_Packet_Length: float = 0.0
    Max_Packet_Length: float = 0.0
    Packet_Length_Mean: float = 0.0
    Packet_Length_Std: float = 0.0
    Packet_Length_Variance: float = 0.0
    FIN_Flag_Count: float = 0.0
    SYN_Flag_Count: float = 0.0
    RST_Flag_Count: float = 0.0
    PSH_Flag_Count: float = 0.0
    ACK_Flag_Count: float = 0.0
    URG_Flag_Count: float = 0.0
    CWE_Flag_Count: float = 0.0
    ECE_Flag_Count: float = 0.0
    Down_Up_Ratio: float = 0.0
    Average_Packet_Size: float = 0.0
    Avg_Fwd_Segment_Size: float = 0.0
    Avg_Bwd_Segment_Size: float = 0.0
    Fwd_Avg_Bytes_Bulk: float = 0.0
    Fwd_Avg_Packets_Bulk: float = 0.0
    Fwd_Avg_Bulk_Rate: float = 0.0
    Bwd_Avg_Bytes_Bulk: float = 0.0
    Bwd_Avg_Packets_Bulk: float = 0.0
    Bwd_Avg_Bulk_Rate: float = 0.0
    Subflow_Fwd_Packets: float = 0.0
    Subflow_Fwd_Bytes: float = 0.0
    Subflow_Bwd_Packets: float = 0.0
    Subflow_Bwd_Bytes: float = 0.0
    Init_Win_bytes_forward: float = 0.0
    Init_Win_bytes_backward: float = 0.0
    act_data_pkt_fwd: float = 0.0
    min_seg_size_forward: float = 0.0
    Active_Mean: float = 0.0
    Active_Std: float = 0.0
    Active_Max: float = 0.0
    Active_Min: float = 0.0
    Idle_Mean: float = 0.0
    Idle_Std: float = 0.0
    Idle_Max: float = 0.0
    Idle_Min: float = 0.0

    def to_list(self) -> List[float]:
        """Return features as a list in the EXACT order the model expects (matching CSV column order)."""
        return [
            self.Destination_Port,
            self.Protocol,
            self.Flow_Duration,
            self.Total_Fwd_Packets,
            self.Total_Backward_Packets,
            self.Total_Length_of_Fwd_Packets,
            self.Total_Length_of_Bwd_Packets,
            self.Fwd_Packet_Length_Max,
            self.Fwd_Packet_Length_Min,
            self.Fwd_Packet_Length_Mean,
            self.Fwd_Packet_Length_Std,
            self.Bwd_Packet_Length_Max,
            self.Bwd_Packet_Length_Min,
            self.Bwd_Packet_Length_Mean,
            self.Bwd_Packet_Length_Std,
            self.Flow_Bytess,
            self.Flow_Packetss,
            self.Flow_IAT_Mean,
            self.Flow_IAT_Std,
            self.Flow_IAT_Max,
            self.Flow_IAT_Min,
            self.Fwd_IAT_Total,
            self.Fwd_IAT_Mean,
            self.Fwd_IAT_Std,
            self.Fwd_IAT_Max,
            self.Fwd_IAT_Min,
            self.Bwd_IAT_Total,
            self.Bwd_IAT_Mean,
            self.Bwd_IAT_Std,
            self.Bwd_IAT_Max,
            self.Bwd_IAT_Min,
            self.Fwd_PSH_Flags,
            self.Bwd_PSH_Flags,
            self.Fwd_URG_Flags,
            self.Bwd_URG_Flags,
            self.Fwd_Header_Length,
            self.Bwd_Header_Length,
            self.Fwd_Packetss,
            self.Bwd_Packetss,
            self.Min_Packet_Length,
            self.Max_Packet_Length,
            self.Packet_Length_Mean,
            self.Packet_Length_Std,
            self.Packet_Length_Variance,
            self.FIN_Flag_Count,
            self.SYN_Flag_Count,
            self.RST_Flag_Count,
            self.PSH_Flag_Count,
            self.ACK_Flag_Count,
            self.URG_Flag_Count,
            self.CWE_Flag_Count,
            self.ECE_Flag_Count,
            self.Down_Up_Ratio,
            self.Average_Packet_Size,
            self.Avg_Fwd_Segment_Size,
            self.Avg_Bwd_Segment_Size,
            self.Fwd_Avg_Bytes_Bulk,
            self.Fwd_Avg_Packets_Bulk,
            self.Fwd_Avg_Bulk_Rate,
            self.Bwd_Avg_Bytes_Bulk,
            self.Bwd_Avg_Packets_Bulk,
            self.Bwd_Avg_Bulk_Rate,
            self.Subflow_Fwd_Packets,
            self.Subflow_Fwd_Bytes,
            self.Subflow_Bwd_Packets,
            self.Subflow_Bwd_Bytes,
            self.Init_Win_bytes_forward,
            self.Init_Win_bytes_backward,
            self.act_data_pkt_fwd,
            self.min_seg_size_forward,
            self.Active_Mean,
            self.Active_Std,
            self.Active_Max,
            self.Active_Min,
            self.Idle_Mean,
            self.Idle_Std,
            self.Idle_Max,
            self.Idle_Min,
        ]


class WelfordStats:
    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.min_val = float('inf')
        self.max_val = float('-inf')
        
    def update(self, val: float):
        self.count += 1
        delta = val - self.mean
        self.mean += delta / self.count
        delta2 = val - self.mean
        self.m2 += delta * delta2
        if val < self.min_val: self.min_val = val
        if val > self.max_val: self.max_val = val
            
    def get_variance(self) -> float:
        if self.count < 2: return 0.0
        return self.m2 / (self.count - 1)
        
    def get_std(self) -> float:
        return math.sqrt(self.get_variance())

    def get_mean(self) -> float:
        return self.mean if self.count > 0 else 0.0

    def get_max(self) -> float:
        return self.max_val if self.count > 0 else 0.0

    def get_min(self) -> float:
        return self.min_val if self.count > 0 else 0.0

@dataclass
class FlowState:
    # State flags
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0
    
    dst_port: int = 0
    protocol: int = 0
    
    # Packet and Byte counts
    total_pkts: int = 0
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    
    total_bytes: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    
    # Length stats
    fwd_len_stats: WelfordStats = field(default_factory=WelfordStats)
    bwd_len_stats: WelfordStats = field(default_factory=WelfordStats)
    all_len_stats: WelfordStats = field(default_factory=WelfordStats)
    
    # IAT Stats
    flow_iat_stats: WelfordStats = field(default_factory=WelfordStats)
    fwd_iat_stats: WelfordStats = field(default_factory=WelfordStats)
    bwd_iat_stats: WelfordStats = field(default_factory=WelfordStats)
    
    last_fwd_timestamp: float = 0.0
    last_bwd_timestamp: float = 0.0
    
    # Flag counts
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0
    
    fwd_psh: int = 0
    bwd_psh: int = 0
    fwd_urg: int = 0
    bwd_urg: int = 0
    
    # Headers
    fwd_header_len: int = 0
    bwd_header_len: int = 0
    
    # Windows
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    
    # Segment sizes
    act_data_pkt_fwd: int = 0
    min_seg_size_fwd: int = float('inf')
    
    # Active/Idle periods
    active_stats: WelfordStats = field(default_factory=WelfordStats)
    idle_stats: WelfordStats = field(default_factory=WelfordStats)
    current_active_start: float = 0.0
    
    # Bulk Transfer States
    BULK_THRESHOLD: float = 1.0
    
    fwd_bulk_bytes: int = 0
    fwd_bulk_pkts: int = 0
    fwd_bulk_start: float = 0.0
    fwd_bulk_size_stats: WelfordStats = field(default_factory=WelfordStats)
    fwd_bulk_pkts_stats: WelfordStats = field(default_factory=WelfordStats)
    fwd_bulk_rate_stats: WelfordStats = field(default_factory=WelfordStats)
    
    bwd_bulk_bytes: int = 0
    bwd_bulk_pkts: int = 0
    bwd_bulk_start: float = 0.0
    bwd_bulk_size_stats: WelfordStats = field(default_factory=WelfordStats)
    bwd_bulk_pkts_stats: WelfordStats = field(default_factory=WelfordStats)
    bwd_bulk_rate_stats: WelfordStats = field(default_factory=WelfordStats)
    
    # Subflow states
    current_subflow_dir: Optional[str] = None
    current_subflow_pkts: int = 0
    current_subflow_bytes: int = 0
    
    fwd_subflow_pkts_stats: WelfordStats = field(default_factory=WelfordStats)
    fwd_subflow_bytes_stats: WelfordStats = field(default_factory=WelfordStats)
    bwd_subflow_pkts_stats: WelfordStats = field(default_factory=WelfordStats)
    bwd_subflow_bytes_stats: WelfordStats = field(default_factory=WelfordStats)
    
    has_fin_or_rst: bool = False

    def update_subflow(self, direction: str, pkt_len: int):
        if self.current_subflow_dir is None:
            self.current_subflow_dir = direction
            self.current_subflow_pkts = 1
            self.current_subflow_bytes = pkt_len
        elif direction == self.current_subflow_dir:
            self.current_subflow_pkts += 1
            self.current_subflow_bytes += pkt_len
        else:
            # End current subflow
            if self.current_subflow_dir == 'fwd':
                self.fwd_subflow_pkts_stats.update(self.current_subflow_pkts)
                self.fwd_subflow_bytes_stats.update(self.current_subflow_bytes)
            else:
                self.bwd_subflow_pkts_stats.update(self.current_subflow_pkts)
                self.bwd_subflow_bytes_stats.update(self.current_subflow_bytes)
            
            # Start new subflow
            self.current_subflow_dir = direction
            self.current_subflow_pkts = 1
            self.current_subflow_bytes = pkt_len

    def finalize_subflow(self):
        if self.current_subflow_dir == 'fwd':
            self.fwd_subflow_pkts_stats.update(self.current_subflow_pkts)
            self.fwd_subflow_bytes_stats.update(self.current_subflow_bytes)
        elif self.current_subflow_dir == 'bwd':
            self.bwd_subflow_pkts_stats.update(self.current_subflow_pkts)
            self.bwd_subflow_bytes_stats.update(self.current_subflow_bytes)

    def update_bulk(self, direction: str, pkt_len: int, timestamp: float):
        if direction == 'fwd':
            if self.fwd_bulk_pkts == 0:
                self.fwd_bulk_start = timestamp
                self.fwd_bulk_bytes = pkt_len
                self.fwd_bulk_pkts = 1
            elif (timestamp - self.fwd_bulk_start) <= self.BULK_THRESHOLD:
                self.fwd_bulk_bytes += pkt_len
                self.fwd_bulk_pkts += 1
            else:
                # End fwd bulk
                self.fwd_bulk_size_stats.update(self.fwd_bulk_bytes)
                self.fwd_bulk_pkts_stats.update(self.fwd_bulk_pkts)
                dur = timestamp - self.fwd_bulk_start
                dur = dur if dur > 0 else 1e-6
                self.fwd_bulk_rate_stats.update(self.fwd_bulk_bytes / dur)
                # Start new
                self.fwd_bulk_start = timestamp
                self.fwd_bulk_bytes = pkt_len
                self.fwd_bulk_pkts = 1
        else:
            if self.bwd_bulk_pkts == 0:
                self.bwd_bulk_start = timestamp
                self.bwd_bulk_bytes = pkt_len
                self.bwd_bulk_pkts = 1
            elif (timestamp - self.bwd_bulk_start) <= self.BULK_THRESHOLD:
                self.bwd_bulk_bytes += pkt_len
                self.bwd_bulk_pkts += 1
            else:
                # End bwd bulk
                self.bwd_bulk_size_stats.update(self.bwd_bulk_bytes)
                self.bwd_bulk_pkts_stats.update(self.bwd_bulk_pkts)
                dur = timestamp - self.bwd_bulk_start
                dur = dur if dur > 0 else 1e-6
                self.bwd_bulk_rate_stats.update(self.bwd_bulk_bytes / dur)
                # Start new
                self.bwd_bulk_start = timestamp
                self.bwd_bulk_bytes = pkt_len
                self.bwd_bulk_pkts = 1

    def finalize_bulk(self):
        if self.fwd_bulk_pkts > 0:
            self.fwd_bulk_size_stats.update(self.fwd_bulk_bytes)
            self.fwd_bulk_pkts_stats.update(self.fwd_bulk_pkts)
            self.fwd_bulk_rate_stats.update(self.fwd_bulk_bytes / 0.001)
        if self.bwd_bulk_pkts > 0:
            self.bwd_bulk_size_stats.update(self.bwd_bulk_bytes)
            self.bwd_bulk_pkts_stats.update(self.bwd_bulk_pkts)
            self.bwd_bulk_rate_stats.update(self.bwd_bulk_bytes / 0.001)

class FlowCollector:
    """Aggregates packets into bidirectional flows and computes CICFlowMeter features in O(1) memory."""

    def __init__(self):
        self.flows: Dict[Tuple[str, int, str, int, int], FlowState] = defaultdict(FlowState)

    @staticmethod
    def flow_key(pkt: PacketInfo) -> Tuple[str, int, str, int, int]:
        """Generate a bidirectional flow key (src_ip, src_port, dst_ip, dst_port, proto).
        Forward/backward are determined per-packet by direction."""
        return (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol)

    def add_packet(self, pkt_info: PacketInfo):
        """Add a packet to its flow and update O(1) rolling statistics."""
        key = self.flow_key(pkt_info)
        is_first = key not in self.flows
        state = self.flows[key]
        now = pkt_info.timestamp
        length = pkt_info.length
        
        # Check termination condition
        if pkt_info.flags & 0x01 or pkt_info.flags & 0x04:
            state.has_fin_or_rst = True
            
        # Determine direction
        is_fwd = (pkt_info.src_ip == key[0] and pkt_info.src_port == key[1])
        direction = 'fwd' if is_fwd else 'bwd'

        if is_first:
            state.first_timestamp = now
            state.last_timestamp = now
            state.dst_port = key[3]
            state.protocol = key[4]
            state.current_active_start = now
        else:
            # IAT Global
            gap = now - state.last_timestamp
            state.flow_iat_stats.update(gap * 1_000_000)
            
            # Active/Idle
            ACTIVE_THRESHOLD = 1.0
            if gap > ACTIVE_THRESHOLD:
                # idle period
                state.active_stats.update((state.last_timestamp - state.current_active_start) * 1_000_000)
                state.idle_stats.update(gap * 1_000_000)
                state.current_active_start = now

        state.last_timestamp = now
        
        # Global length stats
        state.total_pkts += 1
        state.total_bytes += length
        state.all_len_stats.update(length)
        
        # TCP Flags
        if pkt_info.flags & 0x01: state.fin_count += 1
        if pkt_info.flags & 0x02: state.syn_count += 1
        if pkt_info.flags & 0x04: state.rst_count += 1
        if pkt_info.flags & 0x08: state.psh_count += 1
        if pkt_info.flags & 0x10: state.ack_count += 1
        if pkt_info.flags & 0x20: state.urg_count += 1
        if pkt_info.flags & 0x40: state.ece_count += 1
        if pkt_info.flags & 0x80: state.cwe_count += 1
        
        if is_fwd:
            # IAT Fwd
            if state.fwd_pkts > 0:
                fwd_gap = now - state.last_fwd_timestamp
                state.fwd_iat_stats.update(fwd_gap * 1_000_000)
            state.last_fwd_timestamp = now
            
            state.fwd_pkts += 1
            state.fwd_bytes += length
            state.fwd_len_stats.update(length)
            state.fwd_header_len += pkt_info.header_len
            
            if pkt_info.flags & 0x08: state.fwd_psh += 1
            if pkt_info.flags & 0x20: state.fwd_urg += 1
            
            if state.init_win_fwd == -1:
                state.init_win_fwd = pkt_info.tcp_window
                
            if length > 0 and not (pkt_info.flags & 0x02):
                state.act_data_pkt_fwd += 1
                
            if length < state.min_seg_size_fwd:
                state.min_seg_size_fwd = length
                
        else:
            # IAT Bwd
            if state.bwd_pkts > 0:
                bwd_gap = now - state.last_bwd_timestamp
                state.bwd_iat_stats.update(bwd_gap * 1_000_000)
            state.last_bwd_timestamp = now
            
            state.bwd_pkts += 1
            state.bwd_bytes += length
            state.bwd_len_stats.update(length)
            state.bwd_header_len += pkt_info.header_len
            
            if pkt_info.flags & 0x08: state.bwd_psh += 1
            if pkt_info.flags & 0x20: state.bwd_urg += 1
            
            if state.init_win_bwd == -1:
                state.init_win_bwd = pkt_info.tcp_window

        # Bulk and Subflow streaming
        state.update_bulk(direction, length, now)
        state.update_subflow(direction, length)

    def extract_features(self, state: FlowState) -> FlowFeatures:
        """Compute all 79 flow-level features from O(1) state."""
        f = FlowFeatures()

        if state.total_pkts < 2:
            return f

        f.Destination_Port = float(state.dst_port)
        f.Protocol = float(state.protocol)
        f.Flow_Duration = (state.last_timestamp - state.first_timestamp) * 1_000_000
        f.Flow_Bytess = float(state.total_bytes)
        f.Flow_Packetss = float(state.total_pkts)

        f.Total_Fwd_Packets = float(state.fwd_pkts)
        f.Total_Length_of_Fwd_Packets = float(state.fwd_bytes)
        f.Fwd_Packetss = float(state.fwd_pkts)

        if state.fwd_pkts > 0:
            f.Fwd_Packet_Length_Max = state.fwd_len_stats.get_max()
            f.Fwd_Packet_Length_Min = state.fwd_len_stats.get_min()
            f.Fwd_Packet_Length_Mean = state.fwd_len_stats.get_mean()
            f.Fwd_Packet_Length_Std = state.fwd_len_stats.get_std()

        f.Total_Backward_Packets = float(state.bwd_pkts)
        f.Total_Length_of_Bwd_Packets = float(state.bwd_bytes)
        f.Bwd_Packetss = float(state.bwd_pkts)

        if state.bwd_pkts > 0:
            f.Bwd_Packet_Length_Max = state.bwd_len_stats.get_max()
            f.Bwd_Packet_Length_Min = state.bwd_len_stats.get_min()
            f.Bwd_Packet_Length_Mean = state.bwd_len_stats.get_mean()
            f.Bwd_Packet_Length_Std = state.bwd_len_stats.get_std()

        f.Min_Packet_Length = state.all_len_stats.get_min()
        f.Max_Packet_Length = state.all_len_stats.get_max()
        f.Packet_Length_Mean = state.all_len_stats.get_mean()
        f.Packet_Length_Std = state.all_len_stats.get_std()
        f.Packet_Length_Variance = state.all_len_stats.get_variance()

        if state.flow_iat_stats.count > 0:
            f.Flow_IAT_Mean = state.flow_iat_stats.get_mean()
            f.Flow_IAT_Std = state.flow_iat_stats.get_std()
            f.Flow_IAT_Max = state.flow_iat_stats.get_max()
            f.Flow_IAT_Min = state.flow_iat_stats.get_min()

        if state.fwd_iat_stats.count > 0:
            f.Fwd_IAT_Total = state.fwd_iat_stats.get_mean() * state.fwd_iat_stats.count
            f.Fwd_IAT_Mean = state.fwd_iat_stats.get_mean()
            f.Fwd_IAT_Std = state.fwd_iat_stats.get_std()
            f.Fwd_IAT_Max = state.fwd_iat_stats.get_max()
            f.Fwd_IAT_Min = state.fwd_iat_stats.get_min()

        if state.bwd_iat_stats.count > 0:
            f.Bwd_IAT_Total = state.bwd_iat_stats.get_mean() * state.bwd_iat_stats.count
            f.Bwd_IAT_Mean = state.bwd_iat_stats.get_mean()
            f.Bwd_IAT_Std = state.bwd_iat_stats.get_std()
            f.Bwd_IAT_Max = state.bwd_iat_stats.get_max()
            f.Bwd_IAT_Min = state.bwd_iat_stats.get_min()

        f.FIN_Flag_Count = float(state.fin_count)
        f.SYN_Flag_Count = float(state.syn_count)
        f.RST_Flag_Count = float(state.rst_count)
        f.PSH_Flag_Count = float(state.psh_count)
        f.ACK_Flag_Count = float(state.ack_count)
        f.URG_Flag_Count = float(state.urg_count)
        f.CWE_Flag_Count = float(state.cwe_count)
        f.ECE_Flag_Count = float(state.ece_count)
        f.Fwd_PSH_Flags = float(state.fwd_psh)
        f.Bwd_PSH_Flags = float(state.bwd_psh)
        f.Fwd_URG_Flags = float(state.fwd_urg)
        f.Bwd_URG_Flags = float(state.bwd_urg)

        f.Fwd_Header_Length = float(state.fwd_header_len)
        f.Bwd_Header_Length = float(state.bwd_header_len)

        if state.fwd_bytes > 0 and state.bwd_bytes > 0:
            f.Down_Up_Ratio = state.fwd_bytes / state.bwd_bytes
        elif state.bwd_bytes > 0:
            f.Down_Up_Ratio = float(state.fwd_bytes)
        else:
            f.Down_Up_Ratio = 0.0

        if state.total_pkts > 0:
            f.Average_Packet_Size = state.total_bytes / state.total_pkts

        if state.fwd_pkts > 0:
            f.Avg_Fwd_Segment_Size = state.fwd_bytes / state.fwd_pkts
        if state.bwd_pkts > 0:
            f.Avg_Bwd_Segment_Size = state.bwd_bytes / state.bwd_pkts

        # Copy state to finalize
        import copy
        final_state = copy.deepcopy(state)
        final_state.finalize_bulk()
        final_state.finalize_subflow()
        final_state.active_stats.update((final_state.last_timestamp - final_state.current_active_start) * 1_000_000)

        f.Fwd_Avg_Bytes_Bulk = final_state.fwd_bulk_size_stats.get_mean()
        f.Fwd_Avg_Packets_Bulk = final_state.fwd_bulk_pkts_stats.get_mean()
        f.Fwd_Avg_Bulk_Rate = final_state.fwd_bulk_rate_stats.get_mean()
        
        f.Bwd_Avg_Bytes_Bulk = final_state.bwd_bulk_size_stats.get_mean()
        f.Bwd_Avg_Packets_Bulk = final_state.bwd_bulk_pkts_stats.get_mean()
        f.Bwd_Avg_Bulk_Rate = final_state.bwd_bulk_rate_stats.get_mean()

        f.Subflow_Fwd_Packets = final_state.fwd_subflow_pkts_stats.get_mean()
        f.Subflow_Fwd_Bytes = final_state.fwd_subflow_bytes_stats.get_mean()
        f.Subflow_Bwd_Packets = final_state.bwd_subflow_pkts_stats.get_mean()
        f.Subflow_Bwd_Bytes = final_state.bwd_subflow_bytes_stats.get_mean()

        f.Init_Win_bytes_forward = float(state.init_win_fwd) if state.init_win_fwd != -1 else 0.0
        f.Init_Win_bytes_backward = float(state.init_win_bwd) if state.init_win_bwd != -1 else 0.0

        f.act_data_pkt_fwd = float(state.act_data_pkt_fwd)
        f.min_seg_size_forward = float(state.min_seg_size_fwd) if state.min_seg_size_fwd != float('inf') else 0.0

        if final_state.active_stats.count > 0:
            f.Active_Mean = final_state.active_stats.get_mean()
            f.Active_Std = final_state.active_stats.get_std()
            f.Active_Max = final_state.active_stats.get_max()
            f.Active_Min = final_state.active_stats.get_min()

        if final_state.idle_stats.count > 0:
            f.Idle_Mean = final_state.idle_stats.get_mean()
            f.Idle_Std = final_state.idle_stats.get_std()
            f.Idle_Max = final_state.idle_stats.get_max()
            f.Idle_Min = final_state.idle_stats.get_min()

        return f

    def get_ready_flows(self) -> Dict[Tuple, FlowFeatures]:
        """Return FlowFeatures for flows that are complete (timed out or finished)."""
        now = time.time()
        ready = {}

        for key, state in list(self.flows.items()):
            if state.total_pkts == 0:
                continue

            flow_duration = now - state.first_timestamp
            idle_time = now - state.last_timestamp

            if (state.has_fin_or_rst and state.total_pkts >= MIN_FLOW_PACKETS) or \
               (idle_time > FLOW_TIMEOUT and state.total_pkts >= MIN_FLOW_PACKETS) or \
               (flow_duration > MAX_FLOW_DURATION and state.total_pkts >= MIN_FLOW_PACKETS):
                ready[key] = self.extract_features(state)
                del self.flows[key]

        return ready

    def cleanup_stale_flows(self, max_age: float = 600):
        """Remove very old incomplete flows."""
        now = time.time()
        stale_keys = [
            key for key, state in self.flows.items()
            if now - state.first_timestamp > max_age and state.total_pkts < MIN_FLOW_PACKETS
        ]
        for key in stale_keys:
            del self.flows[key]


def decode_tcp_flags(flags_byte: int) -> int:
    """Decode TCP flags byte into our flag bitmap (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWE=0x80)."""
    result = 0
    if flags_byte & 0x01:
        result |= 0x01  # FIN
    if flags_byte & 0x02:
        result |= 0x02  # SYN
    if flags_byte & 0x04:
        result |= 0x04  # RST
    if flags_byte & 0x08:
        result |= 0x08  # PSH
    if flags_byte & 0x10:
        result |= 0x10  # ACK
    if flags_byte & 0x20:
        result |= 0x20  # URG
    if flags_byte & 0x40:
        result |= 0x40  # ECE  (ECN-Echo)
    if flags_byte & 0x80:
        result |= 0x80  # CWE (CWR / Congestion Window Reduced)
    return result