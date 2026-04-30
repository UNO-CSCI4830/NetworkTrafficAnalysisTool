"""
data_transfer_tracker.py

Tracks network traffic volume (bytes sent/received) per process.
Provides aggregation over user-defined time windows and sorting capabilities.

Features:
- Collect per-process I/O statistics
- Aggregate data over specified time windows (minutes, hours, etc.)
- Display totals with sorting options
- Mark processes as "Exited" if tracking data becomes unavailable
"""

import psutil
import datetime
from collections import defaultdict
from typing import List, Dict, Optional, Literal


class ProcessDataTransfer:
    """Represents data transfer statistics for a single process."""
    
    def __init__(self, pid: int, process_name: str, bytes_sent: int, bytes_recv: int):
        self.pid = pid
        self.process_name = process_name
        self.bytes_sent = bytes_sent
        self.bytes_recv = bytes_recv
        self.timestamp = datetime.datetime.now()
        self.is_active = True
    
    @property
    def total_bytes(self) -> int:
        """Total bytes transferred (sent + received)."""
        return self.bytes_sent + self.bytes_recv
    
    def update(self, bytes_sent: int, bytes_recv: int):
        """Update the statistics with new values."""
        self.bytes_sent = bytes_sent
        self.bytes_recv = bytes_recv
        self.timestamp = datetime.datetime.now()
    
    def check_process_alive(self) -> bool:
        """Check if the process is still running."""
        try:
            psutil.Process(self.pid).status()
            self.is_active = True
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.is_active = False
            return False


class DataTransferTracker:
    """
    Tracks per-process network traffic volume.
    
    Aggregates bytes sent/received for each process and provides
    sorting and display functionality.
    """
    
    def __init__(self):
        # Map of pid -> ProcessDataTransfer
        self.process_stats: Dict[int, ProcessDataTransfer] = {}
        self.collection_history: List[Dict] = []
    
    def collect_process_stats(self) -> Dict[int, ProcessDataTransfer]:
        """
        Collect I/O statistics for all processes with network connections.
        
        Returns:
            Dictionary mapping PID to ProcessDataTransfer object
        """
        self.process_stats.clear()
        
        try:
            # Get all processes with network I/O stats
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    
                    # Get I/O counters for this process
                    io_counters = proc.io_counters()
                    if io_counters:
                        # For network-specific stats, we aggregate from connections
                        bytes_sent = io_counters.write_count
                        bytes_recv = io_counters.read_count
                        
                        self.process_stats[pid] = ProcessDataTransfer(
                            pid, name, bytes_sent, bytes_recv
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            print(f"Warning: Error collecting process stats: {e}")
        
        return self.process_stats
    
    def aggregate_by_connections(self, connections: List[Dict]) -> Dict[str, Dict]:
        """
        Aggregate network traffic by process based on active connections.
        
        Args:
            connections: List of connection dicts from collector.get_connections()
        
        Returns:
            Dictionary mapping process_name -> {
                'pid': process_id,
                'bytes_sent': total_bytes_sent,
                'bytes_recv': total_bytes_received,
                'total_bytes': total_bytes_sent + total_bytes_received,
                'connection_count': number_of_connections,
                'is_active': True/False
            }
        """
        aggregation = defaultdict(lambda: {
            'pids': set(),
            'connection_count': 0,
            'is_active': True
        })
        
        # First, get current process stats to use for bytes if available
        current_stats = self.collect_process_stats()
        
        # Aggregate connections by process name
        for conn in connections:
            process_name = conn.get('process_name', 'unknown')
            pid = conn.get('pid')
            
            if process_name and process_name != 'unknown':
                aggregation[process_name]['pids'].add(pid)
                aggregation[process_name]['connection_count'] += 1
                
                # Check if process is still active
                if pid and pid in current_stats:
                    stats = current_stats[pid]
                    stats.check_process_alive()
                    aggregation[process_name]['is_active'] = stats.is_active
        
        # Convert to final format with bytes data
        result = {}
        for process_name, agg in aggregation.items():
            # get bytes from the first active PID, or use 0
            bytes_sent = 0
            bytes_recv = 0
            is_active = agg['is_active']
            
            for pid in agg['pids']:
                if pid in current_stats:
                    stats = current_stats[pid]
                    bytes_sent += stats.bytes_sent
                    bytes_recv += stats.bytes_recv
                    is_active = is_active and stats.is_active
            
            result[process_name] = {
                'pids': list(agg['pids']),
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'total_bytes': bytes_sent + bytes_recv,
                'connection_count': agg['connection_count'],
                'is_active': is_active,
                'status': 'Active' if is_active else 'Exited'
            }
        
        return result
    
    def display_transfer_summary(
        self, 
        processes_data: Dict[str, Dict],
        sort_by: Literal['bytes_sent', 'bytes_recv', 'total_bytes', 'connection_count'] = 'total_bytes',
        reverse: bool = True
    ) -> str:
        """
        Generate a formatted display of process data transfer statistics.
        
        Args:
            processes_data: Dictionary from aggregate_by_connections()
            sort_by: Sort key - 'bytes_sent', 'bytes_recv', 'total_bytes', or 'connection_count'
            reverse: Sort in descending order if True
        
        Returns:
            Formatted string for display
        """
        if not processes_data:
            return "No processes with network activity found."
        
        # Ssort by specified key
        sorted_processes = sorted(
            processes_data.items(),
            key=lambda x: x[1][sort_by],
            reverse=reverse
        )
        
        # build output
        lines = []
        lines.append("\n" + "="*100)
        lines.append("PER-PROCESS DATA TRANSFER SUMMARY")
        lines.append("="*100)
        lines.append(
            f"{'Process Name':<30} {'Bytes Sent':>15} {'Bytes Recv':>15} "
            f"{'Total Bytes':>15} {'Connections':>12} {'Status':<10}"
        )
        lines.append("-"*100)
        
        for process_name, data in sorted_processes:
            status = "⚠ Exited" if data['status'] == 'Exited' else "✓ Active"
            lines.append(
                f"{process_name:<30} {data['bytes_sent']:>15,} {data['bytes_recv']:>15,} "
                f"{data['total_bytes']:>15,} {data['connection_count']:>12} {status:<10}"
            )
        
        lines.append("="*100)
        return "\n".join(lines)
    
    def get_top_processes(
        self, 
        processes_data: Dict[str, Dict],
        limit: int = 10,
        sort_by: Literal['bytes_sent', 'bytes_recv', 'total_bytes'] = 'total_bytes'
    ) -> List[tuple]:
        """
        Get the top N processes by data transfer metric.
        
        Args:
            processes_data: Dictionary from aggregate_by_connections()
            limit: Number of top processes to return
            sort_by: Metric to sort by
        
        Returns:
            List of tuples: (process_name, data_dict)
        """
        sorted_processes = sorted(
            processes_data.items(),
            key=lambda x: x[1][sort_by],
            reverse=True
        )
        return sorted_processes[:limit]


def create_tracker() -> DataTransferTracker:
    """Factory function to create a DataTransferTracker instance."""
    return DataTransferTracker()
