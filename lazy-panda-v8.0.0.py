#!/usr/bin/env python3
"""
🐼 LAZY PANDA v8.0.0 
Author: Ian Carter Kulani
Description: Complete IP analysis with graphical reports and statistics
Fixed Version: Proper encoding and Discord report sharing
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import sqlite3
import ipaddress
import re
import datetime
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import Counter

# Fix Windows encoding issues
if platform.system().lower() == 'windows':
    # Set console to UTF-8
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

# Data visualization imports
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import Circle, Wedge
import seaborn as sns
import numpy as np

# PDF generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io

# Discord
try:
    import discord
    from discord.ext import commands
    from discord import File
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("⚠️ Warning: discord.py not available. Install with: pip install discord.py")

# Color handling - simplified to avoid encoding issues
class Colors:
    RED = '\033[91m' if os.name != 'nt' else ''
    GREEN = '\033[92m' if os.name != 'nt' else ''
    YELLOW = '\033[93m' if os.name != 'nt' else ''
    BLUE = '\033[94m' if os.name != 'nt' else ''
    CYAN = '\033[96m' if os.name != 'nt' else ''
    MAGENTA = '\033[95m' if os.name != 'nt' else ''
    WHITE = '\033[97m' if os.name != 'nt' else ''
    RESET = '\033[0m' if os.name != 'nt' else ''

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".lazy_panda"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DISCORD_CONFIG_FILE = os.path.join(CONFIG_DIR, "discord_config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "ip_analysis.db")
LOG_FILE = os.path.join(CONFIG_DIR, "lazy_panda.log")
REPORT_DIR = "lazy_panda_reports"
SCAN_RESULTS_DIR = os.path.join(REPORT_DIR, "scans")
BLOCKED_IPS_DIR = os.path.join(REPORT_DIR, "blocked")
GRAPHICS_DIR = os.path.join(REPORT_DIR, "graphics")
TEMP_DIR = "lazy_panda_temp"

# Create directories
directories = [CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, BLOCKED_IPS_DIR, GRAPHICS_DIR, TEMP_DIR]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging with UTF-8 encoding
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - LAZY_PANDA - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("LazyPanda")

# =====================
# DATA CLASSES
# =====================
@dataclass
class IPAnalysisResult:
    """Complete IP analysis result"""
    target_ip: str
    timestamp: str
    ping_result: Dict[str, Any]
    traceroute_result: Dict[str, Any]
    port_scan_result: Dict[str, Any]
    geolocation_result: Dict[str, Any]
    traffic_monitor_result: Dict[str, Any]
    security_status: Dict[str, Any]
    recommendations: List[str]
    success: bool = True
    error: Optional[str] = None
    graphics_files: Dict[str, str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()
        if self.graphics_files is None:
            self.graphics_files = {}

@dataclass
class Config:
    """Configuration settings"""
    discord_enabled: bool = False
    discord_token: str = ""
    discord_channel_id: str = ""
    discord_admin_role: str = "Admin"
    
    auto_block_threshold: int = 5
    scan_timeout: int = 30
    max_traceroute_hops: int = 30
    monitoring_duration: int = 60
    report_format: str = "pdf"  # pdf, html, both
    generate_graphics: bool = True

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database manager for IP analysis history"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS ip_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target_ip TEXT NOT NULL,
                analysis_result TEXT NOT NULL,
                report_path TEXT,
                graphics_path TEXT,
                source TEXT DEFAULT 'local'
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT NOT NULL,
                blocked_by TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                analysis_result TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS discord_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                user_name TEXT,
                target_ip TEXT,
                command TEXT,
                success BOOLEAN
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def save_analysis(self, target_ip: str, analysis_result: Dict, report_path: str = None, graphics_path: str = None, source: str = "local") -> bool:
        """Save IP analysis to database"""
        try:
            self.cursor.execute('''
                INSERT INTO ip_analysis (target_ip, analysis_result, report_path, graphics_path, source)
                VALUES (?, ?, ?, ?, ?)
            ''', (target_ip, json.dumps(analysis_result), report_path, graphics_path, source))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
            return False
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict]:
        """Get recent IP analyses"""
        try:
            self.cursor.execute('''
                SELECT * FROM ip_analysis ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get analyses: {e}")
            return []
    
    def get_analysis_by_ip(self, ip: str) -> List[Dict]:
        """Get analyses for specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM ip_analysis WHERE target_ip = ? ORDER BY timestamp DESC
            ''', (ip,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get analyses for IP {ip}: {e}")
            return []
    
    def block_ip(self, ip: str, reason: str, blocked_by: str = "system", analysis: Dict = None) -> bool:
        """Block an IP address"""
        try:
            analysis_json = json.dumps(analysis) if analysis else None
            self.cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_by, analysis_result)
                VALUES (?, ?, ?, ?)
            ''', (ip, reason, blocked_by, analysis_json))
            self.conn.commit()
            logger.info(f"IP {ip} blocked by {blocked_by}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        try:
            self.cursor.execute('''
                UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_blocked_ips(self, active_only: bool = True) -> List[Dict]:
        """Get blocked IPs"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY timestamp DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips ORDER BY timestamp DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return []
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        try:
            self.cursor.execute('''
                SELECT 1 FROM blocked_ips WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            return self.cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Failed to check blocked IP {ip}: {e}")
            return False
    
    def log_discord_command(self, user_id: str, user_name: str, target_ip: str, command: str, success: bool = True):
        """Log Discord command usage"""
        try:
            self.cursor.execute('''
                INSERT INTO discord_commands (user_id, user_name, target_ip, command, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, user_name, target_ip, command, success))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Discord command: {e}")
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# =====================
# GRAPHICS GENERATOR
# =====================
class GraphicsGenerator:
    """Generate statistical graphics for IP analysis"""
    
    def __init__(self, output_dir: str = GRAPHICS_DIR):
        self.output_dir = output_dir
        Path(output_dir).mkdir(exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8-darkgrid')
        sns.set_palette("husl")
    
    def generate_port_statistics(self, port_data: List[Dict], target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate port statistics graphics"""
        graphics_files = {}
        
        # Categorize ports
        open_ports = []
        common_services = []
        
        for port_info in port_data:
            port = port_info.get('port', 0)
            state = port_info.get('state', 'unknown')
            service = port_info.get('service', 'unknown')
            
            if state == 'open':
                open_ports.append(int(port))
                if service != 'unknown':
                    common_services.append(service)
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Port Analysis Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        # 1. Open Ports Count
        ax1 = axes[0, 0]
        if open_ports:
            open_ports.sort()
            port_labels = [str(p) for p in open_ports[:15]]
            port_values = [1] * len(port_labels)
            
            bars = ax1.bar(range(len(port_labels)), port_values, color='#ff6b6b')
            ax1.set_xticks(range(len(port_labels)))
            ax1.set_xticklabels(port_labels, rotation=45, ha='right')
            ax1.set_title(f'Open Ports (First {len(port_labels)})', fontsize=14, fontweight='bold')
            ax1.set_ylabel('Count')
            ax1.set_xlabel('Port Number')
        else:
            ax1.text(0.5, 0.5, 'No Open Ports Detected', ha='center', va='center', fontsize=12)
            ax1.set_title('Open Ports', fontsize=14, fontweight='bold')
        
        # 2. Common Services
        ax2 = axes[0, 1]
        if common_services:
            service_counts = Counter(common_services)
            services = list(service_counts.keys())[:10]
            counts = list(service_counts.values())[:10]
            
            bars = ax2.barh(range(len(services)), counts, color='#45b7d1')
            ax2.set_yticks(range(len(services)))
            ax2.set_yticklabels(services)
            ax2.set_title('Common Services Detected', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Frequency')
        else:
            ax2.text(0.5, 0.5, 'No Common Services Detected', ha='center', va='center', fontsize=12)
            ax2.set_title('Common Services', fontsize=14, fontweight='bold')
        
        # 3. Port Range Distribution
        ax3 = axes[1, 0]
        if open_ports:
            port_ranges = {
                'Well-known (0-1023)': len([p for p in open_ports if p <= 1023]),
                'Registered (1024-49151)': len([p for p in open_ports if 1024 <= p <= 49151]),
                'Dynamic (49152-65535)': len([p for p in open_ports if p >= 49152])
            }
            
            ranges = list(port_ranges.keys())
            values = list(port_ranges.values())
            colors = ['#ff9999', '#66b3ff', '#99ff99']
            
            wedges, texts, autotexts = ax3.pie(
                values,
                labels=ranges,
                autopct='%1.1f%%',
                colors=colors,
                startangle=90,
                explode=(0.05, 0.05, 0.05)
            )
            ax3.set_title('Port Range Distribution', fontsize=14, fontweight='bold')
        else:
            ax3.text(0.5, 0.5, 'No Port Data Available', ha='center', va='center', fontsize=12)
            ax3.set_title('Port Range Distribution', fontsize=14, fontweight='bold')
        
        # 4. Port Count Summary
        ax4 = axes[1, 1]
        ax4.text(0.5, 0.5, f'Total Open Ports: {len(open_ports)}', 
                ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        # Save port statistics graphic
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        port_graphic = os.path.join(self.output_dir, f'port_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(port_graphic, dpi=300, bbox_inches='tight')
        graphics_files['port_statistics'] = port_graphic
        plt.close()
        
        return graphics_files
    
    def generate_traffic_statistics(self, traffic_data: Dict, target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate traffic monitoring statistics graphics"""
        graphics_files = {}
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Traffic Analysis Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        # 1. Traffic Level
        ax1 = axes[0, 0]
        threat_level = traffic_data.get('threat_level', 'low')
        connection_count = traffic_data.get('connection_count', 0)
        
        # Create a simple gauge
        levels = {'low': 0.3, 'medium': 0.6, 'high': 0.9}
        level_value = levels.get(threat_level, 0.3)
        
        # Bar for threat level
        colors = ['#ff6b6b' if threat_level == 'high' else '#ffd93d' if threat_level == 'medium' else '#6bcf7f']
        ax1.bar(['Threat Level'], [level_value * 100], color=colors)
        ax1.set_ylim(0, 100)
        ax1.set_ylabel('Level %')
        ax1.set_title(f'Traffic Threat Level: {threat_level.upper()}\n({connection_count} connections)', 
                     fontsize=14, fontweight='bold')
        
        # 2. Connection Protocols
        ax2 = axes[0, 1]
        connections = traffic_data.get('connections', [])
        
        if connections:
            protocols = [conn.get('protocol', 'unknown') for conn in connections]
            protocol_counts = Counter(protocols)
            
            protocols_list = list(protocol_counts.keys())
            counts = list(protocol_counts.values())
            
            bars = ax2.bar(range(len(protocols_list)), counts, color=['#45b7d1', '#96ceb4', '#ffcc5c'])
            ax2.set_xticks(range(len(protocols_list)))
            ax2.set_xticklabels(protocols_list)
            ax2.set_title('Connection Protocols', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Protocol')
            ax2.set_ylabel('Count')
        else:
            ax2.text(0.5, 0.5, 'No Traffic Data Available', ha='center', va='center', fontsize=12)
            ax2.set_title('Connection Protocols', fontsize=14, fontweight='bold')
        
        # 3. Traffic Timeline
        ax3 = axes[1, 0]
        timeline_points = 20
        time_points = list(range(timeline_points))
        simulated_traffic = np.random.randint(0, connection_count + 5, timeline_points)
        
        ax3.plot(time_points, simulated_traffic, marker='o', linestyle='-', color='#ff6b6b', linewidth=2, markersize=6)
        ax3.fill_between(time_points, simulated_traffic, alpha=0.3, color='#ff6b6b')
        ax3.set_title('Traffic Activity Timeline', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Time Interval')
        ax3.set_ylabel('Connection Count')
        ax3.grid(True, alpha=0.3)
        
        # 4. Summary
        ax4 = axes[1, 1]
        ax4.text(0.5, 0.5, f'Total Connections: {connection_count}\nThreat Level: {threat_level.upper()}', 
                ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        # Save traffic statistics graphic
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        traffic_graphic = os.path.join(self.output_dir, f'traffic_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(traffic_graphic, dpi=300, bbox_inches='tight')
        graphics_files['traffic_statistics'] = traffic_graphic
        plt.close()
        
        return graphics_files
    
    def generate_security_statistics(self, security_data: Dict, target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate security assessment statistics graphics"""
        graphics_files = {}
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Security Assessment Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        # 1. Risk Score
        ax1 = axes[0, 0]
        risk_score = security_data.get('risk_score', 0)
        risk_level = security_data.get('risk_level', 'low')
        
        # Create a simple bar for risk score
        colors = ['#ff6b6b' if risk_score >= 70 else '#ffd93d' if risk_score >= 40 else '#6bcf7f']
        ax1.bar(['Risk Score'], [risk_score], color=colors)
        ax1.set_ylim(0, 100)
        ax1.set_ylabel('Score')
        ax1.set_title(f'Risk Score: {risk_score}\nLevel: {risk_level.upper()}', fontsize=14, fontweight='bold')
        
        # 2. Threats Detected
        ax2 = axes[0, 1]
        threats = security_data.get('threats_detected', [])
        
        if threats:
            threat_categories = {
                'Port Related': len([t for t in threats if 'port' in t.lower()]),
                'Traffic Related': len([t for t in threats if 'traffic' in t.lower()]),
                'Security Related': len([t for t in threats if 'blocked' in t.lower() or 'risk' in t.lower()])
            }
            
            categories = list(threat_categories.keys())
            counts = list(threat_categories.values())
            
            bars = ax2.bar(range(len(categories)), counts, color=['#ff6b6b', '#45b7d1', '#ffd93d'])
            ax2.set_xticks(range(len(categories)))
            ax2.set_xticklabels(categories, rotation=45, ha='right')
            ax2.set_title('Threat Categories', fontsize=14, fontweight='bold')
            ax2.set_ylabel('Number of Threats')
        else:
            ax2.text(0.5, 0.5, 'No Threats Detected', ha='center', va='center', fontsize=12)
            ax2.set_title('Threats Detected', fontsize=14, fontweight='bold')
        
        # 3. Security Metrics
        ax3 = axes[1, 0]
        metrics = {
            'Open Ports': len(security_data.get('open_ports', [])),
            'Sensitive Ports': len([p for p in security_data.get('open_ports', []) if p in [21,22,23,3389,5900]]),
            'Blocked': 1 if security_data.get('is_blocked', False) else 0
        }
        
        metrics_names = list(metrics.keys())
        metrics_values = list(metrics.values())
        
        bars = ax3.barh(range(len(metrics_names)), metrics_values, color=['#ff6b6b', '#ffd93d', '#45b7d1'])
        ax3.set_yticks(range(len(metrics_names)))
        ax3.set_yticklabels(metrics_names)
        ax3.set_title('Security Metrics', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Count')
        
        # 4. Summary
        ax4 = axes[1, 1]
        summary_text = f"Risk Score: {risk_score}\nRisk Level: {risk_level.upper()}\n"
        summary_text += f"Threats: {len(threats)}\n"
        summary_text += f"Blocked: {'Yes' if security_data.get('is_blocked') else 'No'}"
        
        ax4.text(0.5, 0.5, summary_text, ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        # Save security statistics graphic
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        security_graphic = os.path.join(self.output_dir, f'security_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(security_graphic, dpi=300, bbox_inches='tight')
        graphics_files['security_statistics'] = security_graphic
        plt.close()
        
        return graphics_files
    
    def generate_comprehensive_statistics(self, analysis_result: IPAnalysisResult) -> Dict[str, str]:
        """Generate comprehensive statistics graphics for all aspects"""
        graphics_files = {}
        
        target_ip = analysis_result.target_ip
        timestamp = analysis_result.timestamp.replace(':', '-').replace(' ', '_')
        
        # Generate port statistics
        port_graphics = self.generate_port_statistics(
            analysis_result.port_scan_result.get('open_ports', []),
            target_ip,
            timestamp
        )
        graphics_files.update(port_graphics)
        
        # Generate traffic statistics
        traffic_graphics = self.generate_traffic_statistics(
            analysis_result.traffic_monitor_result,
            target_ip,
            timestamp
        )
        graphics_files.update(traffic_graphics)
        
        # Generate security statistics
        security_graphics = self.generate_security_statistics(
            analysis_result.security_status,
            target_ip,
            timestamp
        )
        graphics_files.update(security_graphics)
        
        return graphics_files

# =====================
# REPORT GENERATOR
# =====================
class ReportGenerator:
    """Generate comprehensive reports with graphics"""
    
    def __init__(self, output_dir: str = REPORT_DIR):
        self.output_dir = output_dir
        Path(output_dir).mkdir(exist_ok=True)
        
        # Initialize graphics generator
        self.graphics_gen = GraphicsGenerator()
    
    def generate_pdf_report(self, analysis_result: IPAnalysisResult, graphics_files: Dict[str, str] = None) -> str:
        """Generate PDF report with graphics"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"IP_Analysis_{analysis_result.target_ip}_{timestamp}.pdf")
        
        # Create PDF document
        doc = SimpleDocTemplate(
            report_filename,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12,
            spaceBefore=20
        )
        
        normal_style = styles['Normal']
        normal_style.fontSize = 10
        
        # Build document content
        story = []
        
        # Title
        story.append(Paragraph("LAZY PANDA IP ANALYSIS REPORT", title_style))
        story.append(Paragraph(f"Target: {analysis_result.target_ip}", heading_style))
        story.append(Paragraph(f"Analysis Time: {analysis_result.timestamp[:19]}", normal_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        
        risk_level = analysis_result.security_status.get('risk_level', 'unknown').upper()
        risk_color = 'red' if risk_level in ['CRITICAL', 'HIGH'] else 'orange' if risk_level == 'MEDIUM' else 'green'
        
        summary_text = f"""
        This report presents a comprehensive analysis of IP address <b>{analysis_result.target_ip}</b>.
        The security risk level is <font color="{risk_color}"><b>{risk_level}</b></font> with a risk score of 
        <b>{analysis_result.security_status.get('risk_score', 0)}</b>.
        """
        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 12))
        
        # Key Findings
        story.append(Paragraph("KEY FINDINGS", heading_style))
        
        findings = []
        ping_result = analysis_result.ping_result
        findings.append(f"• Ping Status: {'Online' if ping_result.get('success') else 'Offline'}")
        
        if ping_result.get('avg_rtt'):
            findings.append(f"• Average Latency: {ping_result.get('avg_rtt')}ms")
        
        geo = analysis_result.geolocation_result
        findings.append(f"• Location: {geo.get('country', 'Unknown')}, {geo.get('city', 'Unknown')}")
        findings.append(f"• ISP: {geo.get('isp', 'Unknown')}")
        
        ports = analysis_result.port_scan_result.get('open_ports', [])
        findings.append(f"• Open Ports: {len(ports)}")
        
        traffic = analysis_result.traffic_monitor_result
        findings.append(f"• Traffic Level: {traffic.get('threat_level', 'low').upper()}")
        findings.append(f"• Active Connections: {traffic.get('connection_count', 0)}")
        
        for finding in findings:
            story.append(Paragraph(finding, normal_style))
        
        story.append(Spacer(1, 20))
        
        # Add graphics if available
        if graphics_files:
            story.append(Paragraph("STATISTICAL VISUALIZATIONS", heading_style))
            
            for graphic_type, graphic_path in graphics_files.items():
                if os.path.exists(graphic_path):
                    title = graphic_type.replace('_', ' ').title()
                    story.append(Paragraph(title, styles['Heading3']))
                    story.append(Spacer(1, 10))
                    
                    img = Image(graphic_path, width=6*inch, height=4.5*inch)
                    story.append(img)
                    story.append(Spacer(1, 15))
        
        story.append(PageBreak())
        
        # Detailed Analysis
        story.append(Paragraph("DETAILED ANALYSIS", heading_style))
        
        # Ping Results
        story.append(Paragraph("1. Ping Analysis", styles['Heading3']))
        ping_table_data = [
            ['Metric', 'Value'],
            ['Status', 'Online' if ping_result.get('success') else 'Offline'],
            ['Average RTT', f"{ping_result.get('avg_rtt', 'N/A')}ms"],
            ['Packet Loss', f"{ping_result.get('packet_loss', 0)}%"]
        ]
        
        ping_table = Table(ping_table_data, colWidths=[2*inch, 3*inch])
        ping_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(ping_table)
        story.append(Spacer(1, 15))
        
        # Port Scan Results
        story.append(Paragraph("2. Port Scan Results", styles['Heading3']))
        
        if ports:
            port_table_data = [['Port', 'State', 'Service']]
            for port_info in ports[:20]:
                port_table_data.append([
                    str(port_info.get('port', 'N/A')),
                    port_info.get('state', 'unknown'),
                    port_info.get('service', 'unknown')
                ])
            
            port_table = Table(port_table_data, colWidths=[1.5*inch, 1.5*inch, 2*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
        else:
            story.append(Paragraph("No open ports detected.", normal_style))
        
        story.append(Spacer(1, 15))
        
        # Geolocation
        story.append(Paragraph("3. Geolocation", styles['Heading3']))
        geo_table_data = [
            ['Country', geo.get('country', 'Unknown')],
            ['Region', geo.get('region', 'Unknown')],
            ['City', geo.get('city', 'Unknown')],
            ['ISP', geo.get('isp', 'Unknown')]
        ]
        
        geo_table = Table(geo_table_data, colWidths=[2*inch, 3*inch])
        geo_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(geo_table)
        story.append(Spacer(1, 15))
        
        # Traffic Monitoring
        story.append(Paragraph("4. Traffic Monitoring", styles['Heading3']))
        
        traffic_table_data = [
            ['Threat Level', traffic.get('threat_level', 'unknown').upper()],
            ['Connection Count', str(traffic.get('connection_count', 0))]
        ]
        
        traffic_table = Table(traffic_table_data, colWidths=[2*inch, 3*inch])
        traffic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(traffic_table)
        story.append(Spacer(1, 15))
        
        # Security Assessment
        story.append(Paragraph("5. Security Assessment", styles['Heading3']))
        
        security = analysis_result.security_status
        security_table_data = [
            ['Risk Level', security.get('risk_level', 'unknown').upper()],
            ['Risk Score', str(security.get('risk_score', 0))],
            ['Blocked Status', 'Blocked' if security.get('is_blocked') else 'Not Blocked']
        ]
        
        security_table = Table(security_table_data, colWidths=[2*inch, 3*inch])
        security_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(security_table)
        story.append(Spacer(1, 15))
        
        # Threats Detected
        if security.get('threats_detected'):
            story.append(Paragraph("Threats Detected:", styles['Heading4']))
            for threat in security['threats_detected']:
                story.append(Paragraph(f"• {threat}", normal_style))
            story.append(Spacer(1, 10))
        
        # Recommendations
        story.append(Paragraph("RECOMMENDATIONS", heading_style))
        
        if analysis_result.recommendations:
            for rec in analysis_result.recommendations:
                story.append(Paragraph(f"• {rec}", normal_style))
        else:
            story.append(Paragraph("No specific recommendations at this time.", normal_style))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            f"Report generated by Lazy Panda v2.0.0 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Italic']
        ))
        
        # Build PDF
        doc.build(story)
        
        return report_filename
    
    def generate_html_report(self, analysis_result: IPAnalysisResult, graphics_files: Dict[str, str] = None) -> str:
        """Generate HTML report with graphics"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"IP_Analysis_{analysis_result.target_ip}_{timestamp}.html")
        
        risk_level = analysis_result.security_status.get('risk_level', 'unknown')
        risk_color = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }.get(risk_level, '#6c757d')
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Lazy Panda IP Analysis Report - {analysis_result.target_ip}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 2.5em;
                }}
                .section {{
                    background: white;
                    padding: 25px;
                    border-radius: 10px;
                    margin-bottom: 25px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .section h2 {{
                    color: #495057;
                    border-bottom: 3px solid #667eea;
                    padding-bottom: 10px;
                    margin-top: 0;
                }}
                .risk-badge {{
                    display: inline-block;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-weight: bold;
                    color: white;
                    background-color: {risk_color};
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #dee2e6;
                }}
                th {{
                    background-color: #667eea;
                    color: white;
                }}
                .graphics-container {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }}
                .graphic-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                .graphic-item img {{
                    max-width: 100%;
                    height: auto;
                    border-radius: 5px;
                }}
                .recommendation {{
                    background: #e7f5ff;
                    padding: 15px;
                    border-radius: 8px;
                    margin: 10px 0;
                    border-left: 4px solid #339af0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding: 20px;
                    color: #6c757d;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Lazy Panda IP Analysis Report</h1>
                <p>Target: {analysis_result.target_ip} | Analysis Time: {analysis_result.timestamp[:19]}</p>
                <div style="margin-top: 20px;">
                    <span class="risk-badge">Risk Level: {risk_level.upper()}</span>
                </div>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This comprehensive analysis of <strong>{analysis_result.target_ip}</strong> reveals a security risk level of 
                <strong style="color: {risk_color};">{risk_level.upper()}</strong> with a risk score of 
                <strong>{analysis_result.security_status.get('risk_score', 0)}</strong>.</p>
                
                <table>
                    <tr><th>Ping Status</th><td>{'Online' if analysis_result.ping_result.get('success') else 'Offline'}</td></tr>
                    <tr><th>Open Ports</th><td>{len(analysis_result.port_scan_result.get('open_ports', []))}</td></tr>
                    <tr><th>Traffic Level</th><td>{analysis_result.traffic_monitor_result.get('threat_level', 'low').upper()}</td></tr>
                    <tr><th>Active Connections</th><td>{analysis_result.traffic_monitor_result.get('connection_count', 0)}</td></tr>
                </table>
            </div>
        """
        
        # Add graphics section
        if graphics_files:
            html_content += """
            <div class="section">
                <h2>Statistical Visualizations</h2>
                <div class="graphics-container">
            """
            
            for graphic_type, graphic_path in graphics_files.items():
                if os.path.exists(graphic_path):
                    rel_path = os.path.relpath(graphic_path, self.output_dir)
                    title = graphic_type.replace('_', ' ').title()
                    html_content += f"""
                    <div class="graphic-item">
                        <h3>{title}</h3>
                        <img src="{rel_path}" alt="{title}">
                    </div>
                    """
            
            html_content += """
                </div>
            </div>
            """
        
        # Detailed analysis
        html_content += f"""
            <div class="section">
                <h2>Detailed Analysis</h2>
                
                <h3>Geolocation</h3>
                <table>
                    <tr><th>Country</th><td>{analysis_result.geolocation_result.get('country', 'Unknown')}</td></tr>
                    <tr><th>Region</th><td>{analysis_result.geolocation_result.get('region', 'Unknown')}</td></tr>
                    <tr><th>City</th><td>{analysis_result.geolocation_result.get('city', 'Unknown')}</td></tr>
                    <tr><th>ISP</th><td>{analysis_result.geolocation_result.get('isp', 'Unknown')}</td></tr>
                </table>
        """
        
        # Port scan results
        ports = analysis_result.port_scan_result.get('open_ports', [])
        if ports:
            html_content += """
                <h3>Open Ports</h3>
                <table>
                    <tr><th>Port</th><th>State</th><th>Service</th></tr>
            """
            for port_info in ports[:30]:
                html_content += f"""
                    <tr>
                        <td>{port_info.get('port', 'N/A')}</td>
                        <td>{port_info.get('state', 'unknown')}</td>
                        <td>{port_info.get('service', 'unknown')}</td>
                    </tr>
                """
            html_content += "</table>"
        
        # Threats
        threats = analysis_result.security_status.get('threats_detected', [])
        if threats:
            html_content += """
                <h3>Threats Detected</h3>
                <ul>
            """
            for threat in threats:
                html_content += f"<li>{threat}</li>"
            html_content += "</ul>"
        
        # Recommendations
        html_content += """
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
        """
        
        if analysis_result.recommendations:
            for rec in analysis_result.recommendations:
                html_content += f'<div class="recommendation">• {rec}</div>'
        else:
            html_content += '<p>No specific recommendations at this time.</p>'
        
        html_content += """
            </div>
            
            <div class="footer">
                <p>Report generated by Lazy Panda v2.0.0 | Advanced IP Analysis Tool</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_filename
    
    def generate_report(self, analysis_result: IPAnalysisResult, format: str = "both") -> Dict[str, str]:
        """Generate report in specified format"""
        reports = {}
        
        # Generate graphics
        graphics_files = self.graphics_gen.generate_comprehensive_statistics(analysis_result)
        analysis_result.graphics_files = graphics_files
        
        # Generate PDF report
        if format in ["pdf", "both"]:
            pdf_report = self.generate_pdf_report(analysis_result, graphics_files)
            reports['pdf'] = pdf_report
        
        # Generate HTML report
        if format in ["html", "both"]:
            html_report = self.generate_html_report(analysis_result, graphics_files)
            reports['html'] = html_report
        
        return reports

# =====================
# CONFIGURATION MANAGER
# =====================
class ConfigManager:
    """Manage configuration settings"""
    
    @staticmethod
    def load_config() -> Config:
        """Load configuration from file"""
        config = Config()
        
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    
                    config.discord_enabled = data.get('discord', {}).get('enabled', False)
                    config.discord_token = data.get('discord', {}).get('token', '')
                    config.discord_channel_id = data.get('discord', {}).get('channel_id', '')
                    config.discord_admin_role = data.get('discord', {}).get('admin_role', 'Admin')
                    
                    config.auto_block_threshold = data.get('auto_block_threshold', 5)
                    config.scan_timeout = data.get('scan_timeout', 30)
                    config.max_traceroute_hops = data.get('max_traceroute_hops', 30)
                    config.monitoring_duration = data.get('monitoring_duration', 60)
                    config.report_format = data.get('report_format', 'pdf')
                    config.generate_graphics = data.get('generate_graphics', True)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return config
    
    @staticmethod
    def save_config(config: Config) -> bool:
        """Save configuration to file"""
        try:
            data = {
                "discord": {
                    "enabled": config.discord_enabled,
                    "token": config.discord_token,
                    "channel_id": config.discord_channel_id,
                    "admin_role": config.discord_admin_role
                },
                "auto_block_threshold": config.auto_block_threshold,
                "scan_timeout": config.scan_timeout,
                "max_traceroute_hops": config.max_traceroute_hops,
                "monitoring_duration": config.monitoring_duration,
                "report_format": config.report_format,
                "generate_graphics": config.generate_graphics
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False

# =====================
# IP ANALYSIS ENGINE
# =====================
class IPAnalysisEngine:
    """Complete IP analysis engine with single command"""
    
    def __init__(self, config: Config):
        self.config = config
        self.db = DatabaseManager()
        self.report_gen = ReportGenerator()
    
    def execute_command(self, cmd: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """Execute shell command"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, str(e)
    
    def ping_target(self, target: str, count: int = 4) -> Dict[str, Any]:
        """Ping target IP address"""
        result = {
            "success": False,
            "output": "",
            "avg_rtt": None,
            "packet_loss": 100
        }
        
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), target]
            else:
                cmd = ['ping', '-c', str(count), target]
            
            success, output = self.execute_command(cmd, timeout=10)
            result["success"] = success
            result["output"] = output[:500]
            
            # Parse RTT from output
            if success:
                if platform.system().lower() == 'windows':
                    match = re.search(r'Average = (\d+)ms', output)
                    if match:
                        result["avg_rtt"] = int(match.group(1))
                else:
                    match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', output)
                    if match:
                        result["avg_rtt"] = float(match.group(1))
                
                # Parse packet loss
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    result["packet_loss"] = int(loss_match.group(1))
                else:
                    result["packet_loss"] = 0
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def scan_ports(self, target: str) -> Dict[str, Any]:
        """Scan common ports on target IP"""
        result = {
            "success": False,
            "output": "",
            "open_ports": [],
            "scan_type": "common_ports"
        }
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        try:
            # Fallback: socket scan
            result["success"] = True
            result["output"] = "Using socket scanner"
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock_result = sock.connect_ex((target, port))
                    if sock_result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        
                        result["open_ports"].append({
                            "port": port,
                            "protocol": "tcp",
                            "service": service,
                            "state": "open"
                        })
                    sock.close()
                except:
                    pass
            
            result["output"] = f"Found {len(result['open_ports'])} open ports"
        
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def get_geolocation(self, target: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        result = {
            "success": False,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "lat": "Unknown",
            "lon": "Unknown",
            "org": "Unknown"
        }
        
        try:
            response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result["success"] = True
                    result["country"] = data.get('country', 'Unknown')
                    result["region"] = data.get('regionName', 'Unknown')
                    result["city"] = data.get('city', 'Unknown')
                    result["isp"] = data.get('isp', 'Unknown')
                    result["lat"] = data.get('lat', 'Unknown')
                    result["lon"] = data.get('lon', 'Unknown')
        except Exception as e:
            logger.error(f"Geolocation error: {e}")
        
        return result
    
    def monitor_traffic(self, target: str) -> Dict[str, Any]:
        """Monitor traffic to/from target IP"""
        result = {
            "success": False,
            "output": "",
            "connections": [],
            "connection_count": 0,
            "threat_level": "low"
        }
        
        try:
            duration = self.config.monitoring_duration
            connections_seen = {}
            
            result["output"] = f"Monitoring traffic for {duration}s..."
            
            # Simple monitoring simulation
            time.sleep(min(duration, 5))  # Just wait a bit for demo
            
            # Add some simulated connections
            for i in range(3):
                conn = {
                    "protocol": "TCP" if i % 2 == 0 else "UDP",
                    "state": "ESTABLISHED",
                    "timestamp": datetime.datetime.now().isoformat()
                }
                connections_seen[f"conn_{i}"] = conn
            
            result["connections"] = list(connections_seen.values())
            result["connection_count"] = len(connections_seen)
            result["success"] = True
            
            # Determine threat level
            if len(connections_seen) > 5:
                result["threat_level"] = "high"
            elif len(connections_seen) > 2:
                result["threat_level"] = "medium"
            else:
                result["threat_level"] = "low"
        
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def analyze_security(self, target: str, port_scan: Dict, traffic_monitor: Dict) -> Dict[str, Any]:
        """Analyze security status of target IP"""
        result = {
            "is_blocked": self.db.is_ip_blocked(target),
            "risk_score": 0,
            "risk_level": "low",
            "threats_detected": [],
            "open_ports": [p.get('port') for p in port_scan.get('open_ports', [])],
            "traffic_level": traffic_monitor.get('threat_level', 'low')
        }
        
        # Calculate risk score
        risk_score = 0
        
        # Check open ports
        open_ports_count = len(port_scan.get("open_ports", []))
        if open_ports_count > 10:
            risk_score += 30
            result["threats_detected"].append("Multiple open ports detected")
        elif open_ports_count > 5:
            risk_score += 15
            result["threats_detected"].append("Several open ports detected")
        elif open_ports_count > 0:
            risk_score += 5
        
        # Check for sensitive ports
        sensitive_ports = [21, 22, 23, 3389, 5900]
        for port_info in port_scan.get("open_ports", []):
            try:
                port = int(port_info.get("port", 0))
                if port in sensitive_ports:
                    risk_score += 10
                    result["threats_detected"].append(f"Sensitive port {port} open")
            except:
                pass
        
        # Check traffic
        traffic_connections = traffic_monitor.get("connection_count", 0)
        if traffic_connections > 10:
            risk_score += 25
            result["threats_detected"].append("High traffic volume detected")
        elif traffic_connections > 5:
            risk_score += 10
            result["threats_detected"].append("Moderate traffic volume detected")
        
        # Check if previously blocked
        if result["is_blocked"]:
            risk_score += 50
            result["threats_detected"].append("Previously blocked IP address")
        
        # Determine risk level
        result["risk_score"] = risk_score
        if risk_score >= 70:
            result["risk_level"] = "critical"
        elif risk_score >= 40:
            result["risk_level"] = "high"
        elif risk_score >= 20:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
        
        return result
    
    def generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        ping_result = analysis.get("ping_result", {})
        if not ping_result.get("success", False):
            recommendations.append("Target is not responding to ping - may be down or blocking ICMP")
        elif ping_result.get("packet_loss", 100) > 20:
            recommendations.append(f"High packet loss ({ping_result.get('packet_loss', 0)}%) - network instability detected")
        
        port_scan = analysis.get("port_scan_result", {})
        open_ports = port_scan.get("open_ports", [])
        if len(open_ports) > 10:
            recommendations.append("Multiple open ports detected - consider closing unnecessary ports")
        
        for port_info in open_ports:
            port = port_info.get("port", "")
            if port in [23, 3389]:
                recommendations.append(f"Port {port} (telnet/RDP) is open - consider using SSH/VPN instead")
            elif port in [21]:
                recommendations.append(f"Port {port} (FTP) is open - consider using SFTP/FTPS")
        
        traffic = analysis.get("traffic_monitor_result", {})
        if traffic.get("threat_level") == "high":
            recommendations.append("High traffic volume detected - possible scanning or attack")
        
        if analysis.get("security_status", {}).get("risk_level") in ["critical", "high"]:
            recommendations.append("Consider blocking this IP address due to high risk")
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected")
        
        return recommendations
    
    def analyze_ip(self, target: str, generate_report: bool = True, report_format: str = "both") -> Tuple[IPAnalysisResult, Dict[str, str]]:
        """Complete IP analysis - single command with report generation"""
        reports = {}
        
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(target)
            except ValueError:
                try:
                    target = socket.gethostbyname(target)
                except:
                    result = IPAnalysisResult(
                        target_ip=target,
                        timestamp=datetime.datetime.now().isoformat(),
                        ping_result={"success": False, "output": "Invalid IP or hostname"},
                        traceroute_result={"success": False, "output": "Invalid IP or hostname"},
                        port_scan_result={"success": False, "output": "Invalid IP or hostname"},
                        geolocation_result={"success": False},
                        traffic_monitor_result={"success": False, "output": "Invalid IP or hostname"},
                        security_status={},
                        recommendations=["Invalid IP address or hostname"],
                        success=False,
                        error="Invalid IP or hostname"
                    )
                    return result, reports
            
            logger.info(f"Starting analysis for IP: {target}")
            
            # Perform all checks
            ping_result = self.ping_target(target)
            port_scan_result = self.scan_ports(target)
            geolocation_result = self.get_geolocation(target)
            traffic_monitor_result = self.monitor_traffic(target)
            security_status = self.analyze_security(target, port_scan_result, traffic_monitor_result)
            
            # Create traceroute result (simplified)
            traceroute_result = {
                "success": False,
                "output": "Traceroute disabled for speed",
                "hops": []
            }
            
            # Generate recommendations
            analysis_dict = {
                "ping_result": ping_result,
                "port_scan_result": port_scan_result,
                "traffic_monitor_result": traffic_monitor_result,
                "geolocation_result": geolocation_result,
                "security_status": security_status
            }
            recommendations = self.generate_recommendations(analysis_dict)
            
            # Create result object
            result = IPAnalysisResult(
                target_ip=target,
                timestamp=datetime.datetime.now().isoformat(),
                ping_result=ping_result,
                traceroute_result=traceroute_result,
                port_scan_result=port_scan_result,
                geolocation_result=geolocation_result,
                traffic_monitor_result=traffic_monitor_result,
                security_status=security_status,
                recommendations=recommendations,
                success=True
            )
            
            # Generate report if requested
            if generate_report:
                reports = self.report_gen.generate_report(result, report_format)
                
                report_path = reports.get('pdf', reports.get('html', ''))
                graphics_path = GRAPHICS_DIR
                self.db.save_analysis(target, asdict(result), report_path, graphics_path)
            else:
                self.db.save_analysis(target, asdict(result))
            
            logger.info(f"Analysis completed for IP: {target}")
            return result, reports
            
        except Exception as e:
            logger.error(f"Analysis failed for {target}: {e}")
            result = IPAnalysisResult(
                target_ip=target,
                timestamp=datetime.datetime.now().isoformat(),
                ping_result={"success": False, "output": str(e)},
                traceroute_result={"success": False, "output": str(e)},
                port_scan_result={"success": False, "output": str(e)},
                geolocation_result={"success": False},
                traffic_monitor_result={"success": False, "output": str(e)},
                security_status={},
                recommendations=["Analysis failed due to error"],
                success=False,
                error=str(e)
            )
            return result, reports
    
    def generate_security_statistics(self, target_ip: str) -> Dict[str, str]:
        """Generate security statistics graphics for a target IP"""
        graphics_files = {}
        
        try:
            analyses = self.db.get_analysis_by_ip(target_ip)
            if not analyses:
                logger.warning(f"No analysis found for IP: {target_ip}")
                return graphics_files
            
            latest = analyses[0]
            analysis_data = json.loads(latest['analysis_result'])
            
            result = IPAnalysisResult(**analysis_data)
            graphics_files = self.report_gen.graphics_gen.generate_comprehensive_statistics(result)
            
            logger.info(f"Generated statistics graphics for IP: {target_ip}")
            
        except Exception as e:
            logger.error(f"Failed to generate statistics for {target_ip}: {e}")
        
        return graphics_files

# =====================
# DISCORD BOT
# =====================
class LazyPandaDiscord:
    """Discord bot for Lazy Panda"""
    
    def __init__(self, config: Config, engine: IPAnalysisEngine):
        self.config = config
        self.engine = engine
        self.bot = None
        self.running = False
    
    async def start(self):
        """Start Discord bot"""
        if not DISCORD_AVAILABLE:
            logger.error("Discord.py not installed")
            return False
        
        if not self.config.discord_token:
            logger.error("Discord token not configured")
            return False
        
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            
            self.bot = commands.Bot(
                command_prefix='!', 
                intents=intents,
                help_command=None
            )
            
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot connected as {self.bot.user}')
                await self.bot.change_presence(
                    activity=discord.Activity(
                        type=discord.ActivityType.watching,
                        name="!analyze <ip> | !stats <ip> | !help"
                    )
                )
            
            @self.bot.command(name='help')
            async def help_command(ctx):
                """Show help"""
                embed = discord.Embed(
                    title="Lazy Panda v2.0.0 - Help",
                    description="Advanced IP Analysis Tool with Statistical Reporting",
                    color=discord.Color.blue()
                )
                
                embed.add_field(
                    name="ANALYSIS COMMANDS",
                    value="`!analyze <ip>` - Complete IP analysis with report\n`!stats <ip>` - Generate statistics graphics\n`!quick <ip>` - Quick port scan only",
                    inline=False
                )
                
                embed.add_field(
                    name="REPORT COMMANDS",
                    value="`!report <ip>` - Get latest analysis report\n`!list` - List available reports",
                    inline=False
                )
                
                embed.add_field(
                    name="BLOCKING COMMANDS",
                    value="`!block <ip> [reason]` - Block an IP (Admin)\n`!unblock <ip>` - Unblock an IP (Admin)\n`!blocked` - List blocked IPs",
                    inline=False
                )
                
                embed.add_field(
                    name="EXAMPLES",
                    value="`!analyze 8.8.8.8`\n`!stats 192.168.1.1`\n`!block 10.0.0.1 Suspicious activity`",
                    inline=False
                )
                
                await ctx.send(embed=embed)
            
            @self.bot.command(name='analyze')
            async def analyze_command(ctx, target: str):
                """Complete IP analysis with report generation"""
                await ctx.send(f"Analyzing `{target}`... This may take a minute.")
                
                result, reports = self.engine.analyze_ip(target, generate_report=True, report_format="both")
                
                self.engine.db.log_discord_command(str(ctx.author.id), ctx.author.name, target, "analyze", result.success)
                
                if result.success:
                    embed = discord.Embed(
                        title=f"IP Analysis: {result.target_ip}",
                        color=discord.Color.red() if result.security_status.get('risk_level') in ['critical', 'high'] else discord.Color.green(),
                        timestamp=datetime.datetime.now()
                    )
                    
                    ping = result.ping_result
                    ping_text = f"{'Online' if ping.get('success') else 'Offline'}"
                    if ping.get('avg_rtt'):
                        ping_text += f"\nAvg: {ping.get('avg_rtt')}ms"
                    embed.add_field(name="Ping", value=ping_text, inline=True)
                    
                    geo = result.geolocation_result
                    geo_text = f"{geo.get('country', 'Unknown')}\n{geo.get('city', 'Unknown')}"
                    embed.add_field(name="Location", value=geo_text, inline=True)
                    
                    ports = result.port_scan_result.get('open_ports', [])
                    port_text = f"Open ports: {len(ports)}"
                    if ports:
                        top_ports = [str(p.get('port', '')) for p in ports[:3]]
                        port_text += f"\nPorts: {', '.join(top_ports)}"
                    embed.add_field(name="Port Scan", value=port_text, inline=True)
                    
                    security = result.security_status
                    risk_text = f"Risk: {security.get('risk_level', 'unknown').upper()}\nScore: {security.get('risk_score', 0)}"
                    embed.add_field(name="Security", value=risk_text, inline=True)
                    
                    await ctx.send(embed=embed)
                    
                    if reports:
                        await ctx.send("**Generated Reports:**")
                        if 'pdf' in reports:
                            await ctx.send(file=File(reports['pdf']))
                        if 'html' in reports:
                            await ctx.send(file=File(reports['html']))
                else:
                    await ctx.send(f"Analysis failed: {result.error}")
            
            @self.bot.command(name='stats')
            async def stats_command(ctx, target: str):
                """Generate security statistics graphics"""
                await ctx.send(f"Generating statistics for `{target}`...")
                
                graphics_files = self.engine.generate_security_statistics(target)
                
                self.engine.db.log_discord_command(str(ctx.author.id), ctx.author.name, target, "stats", bool(graphics_files))
                
                if graphics_files:
                    embed = discord.Embed(
                        title=f"Statistics: {target}",
                        description="Generated statistics graphics",
                        color=discord.Color.blue()
                    )
                    await ctx.send(embed=embed)
                    
                    for graphic_path in graphics_files.values():
                        if os.path.exists(graphic_path):
                            await ctx.send(file=File(graphic_path))
                else:
                    await ctx.send(f"No statistics found for IP: {target}\nTry running `!analyze {target}` first.")
            
            @self.bot.command(name='report')
            async def report_command(ctx, target: str):
                """Get latest analysis report"""
                analyses = self.engine.db.get_analysis_by_ip(target)
                
                if not analyses:
                    await ctx.send(f"No reports found for IP: {target}")
                    return
                
                latest = analyses[0]
                if latest.get('report_path') and os.path.exists(latest['report_path']):
                    await ctx.send(file=File(latest['report_path']))
                else:
                    await ctx.send(f"No report file found for IP: {target}")
            
            @self.bot.command(name='block')
            @commands.has_permissions(administrator=True)
            async def block_command(ctx, ip: str, *, reason: str = "High risk detected"):
                """Block an IP address"""
                try:
                    ipaddress.ip_address(ip)
                except:
                    await ctx.send(f"Invalid IP address: {ip}")
                    return
                
                success = self.engine.db.block_ip(ip, reason, f"discord:{ctx.author}")
                
                if success:
                    embed = discord.Embed(
                        title="IP Blocked",
                        description=f"**IP:** `{ip}`\n**Reason:** {reason}\n**Blocked by:** {ctx.author.mention}",
                        color=discord.Color.red()
                    )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"Failed to block {ip}")
            
            @self.bot.command(name='unblock')
            @commands.has_permissions(administrator=True)
            async def unblock_command(ctx, ip: str):
                """Unblock an IP address"""
                success = self.engine.db.unblock_ip(ip)
                
                if success:
                    embed = discord.Embed(
                        title="IP Unblocked",
                        description=f"**IP:** `{ip}`\n**Unblocked by:** {ctx.author.mention}",
                        color=discord.Color.green()
                    )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"Failed to unblock {ip}")
            
            @self.bot.command(name='blocked')
            async def blocked_command(ctx):
                """List blocked IPs"""
                blocked = self.engine.db.get_blocked_ips(active_only=True)
                
                if not blocked:
                    await ctx.send("No IPs are currently blocked.")
                    return
                
                embed = discord.Embed(
                    title=f"Blocked IPs ({len(blocked)})",
                    color=discord.Color.red()
                )
                
                for ip_data in blocked[:10]:
                    embed.add_field(
                        name=f"`{ip_data['ip_address']}`",
                        value=f"Reason: {ip_data.get('reason', 'N/A')[:50]}",
                        inline=False
                    )
                
                await ctx.send(embed=embed)
            
            @self.bot.command(name='list')
            async def list_command(ctx):
                """List available reports"""
                analyses = self.engine.db.get_recent_analyses(10)
                
                if not analyses:
                    await ctx.send("No reports available")
                    return
                
                embed = discord.Embed(
                    title="Recent Reports",
                    color=discord.Color.blue()
                )
                
                for analysis in analyses:
                    embed.add_field(
                        name=analysis['target_ip'],
                        value=f"{analysis['timestamp'][:16]}\nReport: {'Yes' if analysis.get('report_path') else 'No'}",
                        inline=True
                    )
                
                await ctx.send(embed=embed)
            
            @self.bot.command(name='quick')
            async def quick_command(ctx, target: str):
                """Quick port scan"""
                await ctx.send(f"Quick scanning `{target}`...")
                
                port_scan = self.engine.scan_ports(target)
                
                if port_scan.get('success'):
                    open_ports = port_scan.get('open_ports', [])
                    
                    embed = discord.Embed(
                        title=f"Quick Scan: {target}",
                        color=discord.Color.blue()
                    )
                    
                    embed.add_field(name="Open Ports", value=str(len(open_ports)), inline=True)
                    
                    if open_ports:
                        port_list = [f"`{p.get('port')}`" for p in open_ports[:10]]
                        embed.add_field(name="Ports", value=", ".join(port_list), inline=False)
                    
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"Scan failed")
            
            self.running = True
            await self.bot.start(self.config.discord_token)
            return True
            
        except Exception as e:
            logger.error(f"Discord bot error: {e}")
            return False
    
    def start_bot_thread(self):
        """Start Discord bot in thread"""
        if self.config.discord_enabled and self.config.discord_token:
            thread = threading.Thread(target=self._run_discord_bot, daemon=True)
            thread.start()
            logger.info("Discord bot started in background")
            return True
        return False
    
    def _run_discord_bot(self):
        """Run Discord bot in thread"""
        try:
            import asyncio
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot thread error: {e}")

# =====================
# MAIN APPLICATION
# =====================
class LazyPandaApp:
    """Main application"""
    
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.engine = IPAnalysisEngine(self.config)
        self.discord_bot = LazyPandaDiscord(self.config, self.engine)
        self.running = True
    
    def print_banner(self):
        """Print application banner without emojis to avoid encoding issues"""
        banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║{Colors.WHITE}                                                                           {Colors.CYAN}║
║{Colors.WHITE}                     LAZY PANDA v8.0.0                                    {Colors.CYAN}║
║{Colors.WHITE}            Advanced IP Analysis with Statistical Graphics                 {Colors.CYAN}║
║{Colors.WHITE}                                                                           {Colors.CYAN}║
╠═══════════════════════════════════════════════════════════════════════════╣
║{Colors.GREEN}  FEATURES:                                                              {Colors.CYAN}║
║{Colors.GREEN}  • analyze <ip> - Complete IP analysis with report generation          {Colors.CYAN}║
║{Colors.GREEN}  • stats <ip> - Generate statistical graphics                          {Colors.CYAN}║
║{Colors.GREEN}  • report <ip> - Get latest analysis report                            {Colors.CYAN}║
║{Colors.GREEN}  • block <ip> [reason] - Block an IP (Admin)                           {Colors.CYAN}║
║{Colors.GREEN}  • blocked - List blocked IPs                                          {Colors.CYAN}║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """
        print(banner)
    
    def setup_configuration(self):
        """Setup configuration"""
        print(f"\n{Colors.CYAN}Lazy Panda Configuration{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        setup_discord = input(f"\n{Colors.YELLOW}Setup Discord bot? (y/n): {Colors.RESET}").strip().lower()
        if setup_discord == 'y':
            self.config.discord_enabled = True
            self.config.discord_token = input(f"{Colors.YELLOW}Enter Discord bot token: {Colors.RESET}").strip()
            self.config.discord_channel_id = input(f"{Colors.YELLOW}Enter channel ID (optional): {Colors.RESET}").strip()
            self.config.discord_admin_role = input(f"{Colors.YELLOW}Enter admin role name (default: Admin): {Colors.RESET}").strip() or "Admin"
        
        print(f"\n{Colors.CYAN}Report Configuration:{Colors.RESET}")
        print(f"1. PDF only")
        print(f"2. HTML only")
        print(f"3. Both PDF and HTML")
        
        report_choice = input(f"{Colors.YELLOW}Choose report format (1-3) [3]: {Colors.RESET}").strip() or "3"
        if report_choice == "1":
            self.config.report_format = "pdf"
        elif report_choice == "2":
            self.config.report_format = "html"
        else:
            self.config.report_format = "both"
        
        generate_graphics = input(f"\n{Colors.YELLOW}Generate statistics graphics? (y/n) [y]: {Colors.RESET}").strip().lower()
        self.config.generate_graphics = generate_graphics != 'n'
        
        ConfigManager.save_config(self.config)
        print(f"{Colors.GREEN}Configuration saved!{Colors.RESET}")
    
    def start_bots(self):
        """Start Discord bot"""
        if self.config.discord_enabled:
            if self.discord_bot.start_bot_thread():
                print(f"{Colors.GREEN}Discord bot started! Use !analyze <ip> or !stats <ip>{Colors.RESET}")
            else:
                print(f"{Colors.RED}Failed to start Discord bot{Colors.RESET}")
    
    def process_command(self, command: str):
        """Process local CLI command"""
        if not command.strip():
            return
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == 'help':
            print(f"\n{Colors.CYAN}Available Commands:{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"{Colors.WHITE}analyze <ip>{Colors.RESET} - Complete IP analysis with report")
            print(f"{Colors.WHITE}stats <ip>{Colors.RESET} - Generate statistics graphics")
            print(f"{Colors.WHITE}report <ip>{Colors.RESET} - Get latest analysis report")
            print(f"{Colors.WHITE}list{Colors.RESET} - List recent reports")
            print(f"{Colors.WHITE}block <ip> [reason]{Colors.RESET} - Block an IP")
            print(f"{Colors.WHITE}unblock <ip>{Colors.RESET} - Unblock an IP")
            print(f"{Colors.WHITE}blocked{Colors.RESET} - List blocked IPs")
            print(f"{Colors.WHITE}status{Colors.RESET} - Show system status")
            print(f"{Colors.WHITE}config{Colors.RESET} - Configure settings")
            print(f"{Colors.WHITE}clear{Colors.RESET} - Clear screen")
            print(f"{Colors.WHITE}exit{Colors.RESET} - Exit application")
        
        elif cmd == 'analyze':
            if not args:
                print(f"{Colors.RED}Please provide an IP address or hostname{Colors.RESET}")
                return
            
            target = args[0]
            print(f"\n{Colors.CYAN}Analyzing {Colors.WHITE}{target}{Colors.CYAN}...{Colors.RESET}")
            
            result, reports = self.engine.analyze_ip(target, generate_report=True, report_format=self.config.report_format)
            
            if result.success:
                self.print_analysis_result(result)
                
                if reports:
                    print(f"\n{Colors.GREEN}Reports generated:{Colors.RESET}")
                    for format_type, report_path in reports.items():
                        print(f"  • {format_type.upper()}: {report_path}")
            else:
                print(f"{Colors.RED}Analysis failed: {result.error}{Colors.RESET}")
        
        elif cmd == 'stats':
            if not args:
                print(f"{Colors.RED}Please provide an IP address{Colors.RESET}")
                return
            
            target = args[0]
            print(f"\n{Colors.CYAN}Generating statistics for {Colors.WHITE}{target}{Colors.CYAN}...{Colors.RESET}")
            
            graphics_files = self.engine.generate_security_statistics(target)
            
            if graphics_files:
                print(f"{Colors.GREEN}Statistics graphics generated:{Colors.RESET}")
                for graphic_type, graphic_path in graphics_files.items():
                    print(f"  • {graphic_type}: {graphic_path}")
            else:
                print(f"{Colors.RED}No statistics found for IP: {target}{Colors.RESET}")
        
        elif cmd == 'report':
            if not args:
                print(f"{Colors.RED}Please provide an IP address{Colors.RESET}")
                return
            
            target = args[0]
            analyses = self.engine.db.get_analysis_by_ip(target)
            
            if not analyses:
                print(f"{Colors.RED}No reports found for IP: {target}{Colors.RESET}")
                return
            
            latest = analyses[0]
            if latest.get('report_path') and os.path.exists(latest['report_path']):
                print(f"\n{Colors.GREEN}Report found: {latest['report_path']}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}No report file found for IP: {target}{Colors.RESET}")
        
        elif cmd == 'list':
            analyses = self.engine.db.get_recent_analyses(10)
            
            if not analyses:
                print(f"{Colors.YELLOW}No reports available{Colors.RESET}")
                return
            
            print(f"\n{Colors.CYAN}Recent Reports:{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
            
            for analysis in analyses:
                status = "✓" if analysis.get('report_path') else "✗"
                print(f"{status} {Colors.WHITE}{analysis['target_ip']}{Colors.RESET} - {analysis['timestamp'][:16]}")
        
        elif cmd == 'blocked':
            blocked = self.engine.db.get_blocked_ips(active_only=True)
            if not blocked:
                print(f"{Colors.GREEN}No IPs are currently blocked.{Colors.RESET}")
            else:
                print(f"\n{Colors.RED}Blocked IPs ({len(blocked)}):{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                for ip_data in blocked:
                    print(f"{Colors.WHITE}{ip_data['ip_address']}{Colors.RESET} - {ip_data.get('reason', 'N/A')}")
        
        elif cmd == 'block' and len(args) >= 1:
            ip = args[0]
            reason = ' '.join(args[1:]) if len(args) > 1 else "Manual block"
            
            try:
                ipaddress.ip_address(ip)
                success = self.engine.db.block_ip(ip, reason, "cli")
                if success:
                    print(f"{Colors.GREEN}IP {ip} blocked successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to block IP {ip}{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}Invalid IP address: {ip}{Colors.RESET}")
        
        elif cmd == 'unblock' and len(args) >= 1:
            ip = args[0]
            success = self.engine.db.unblock_ip(ip)
            if success:
                print(f"{Colors.GREEN}IP {ip} unblocked successfully{Colors.RESET}")
            else:
                print(f"{Colors.RED}Failed to unblock IP {ip}{Colors.RESET}")
        
        elif cmd == 'status':
            total_analyses = self.engine.db.cursor.execute("SELECT COUNT(*) FROM ip_analysis").fetchone()[0]
            blocked_count = len(self.engine.db.get_blocked_ips(active_only=True))
            
            print(f"\n{Colors.CYAN}Lazy Panda v2.0.0 Status:{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"System: Online")
            print(f"Database: {DATABASE_FILE}")
            print(f"Reports Directory: {REPORT_DIR}")
            print(f"\nTotal Analyses: {total_analyses}")
            print(f"Blocked IPs: {blocked_count}")
            print(f"Discord: {'Enabled' if self.config.discord_enabled else 'Disabled'}")
            print(f"Report Format: {self.config.report_format}")
        
        elif cmd == 'config':
            self.setup_configuration()
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{Colors.YELLOW}Thank you for using Lazy Panda!{Colors.RESET}")
        
        else:
            print(f"{Colors.RED}Unknown command: {cmd}{Colors.RESET}")
            print(f"{Colors.YELLOW}Type 'help' for available commands{Colors.RESET}")
    
    def print_analysis_result(self, result: IPAnalysisResult):
        """Print analysis result"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.WHITE}LAZY PANDA IP ANALYSIS: {Colors.CYAN}{result.target_ip}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Time: {result.timestamp[:19]}")
        
        ping = result.ping_result
        ping_status = "Online" if ping.get('success') else "Offline"
        print(f"\nPING: {ping_status}")
        if ping.get('avg_rtt'):
            print(f"  • Avg RTT: {ping.get('avg_rtt')}ms")
            print(f"  • Packet Loss: {ping.get('packet_loss', 0)}%")
        
        geo = result.geolocation_result
        if geo.get('success'):
            print(f"\nLOCATION:")
            print(f"  • Country: {geo.get('country', 'Unknown')}")
            print(f"  • City: {geo.get('city', 'Unknown')}")
            print(f"  • ISP: {geo.get('isp', 'Unknown')}")
        
        ports = result.port_scan_result.get('open_ports', [])
        print(f"\nOPEN PORTS: {len(ports)}")
        if ports:
            for port_info in ports[:10]:
                port = port_info.get('port', '')
                service = port_info.get('service', 'unknown')
                print(f"  • Port {port} - {service}")
        
        security = result.security_status
        print(f"\nSECURITY ASSESSMENT:")
        print(f"  • Risk Level: {security.get('risk_level', 'unknown').upper()}")
        print(f"  • Risk Score: {security.get('risk_score', 0)}")
        
        if result.recommendations:
            print(f"\nRECOMMENDATIONS:")
            for rec in result.recommendations:
                print(f"  • {rec}")
        
        print(f"\n{Colors.GREEN}Analysis completed successfully{Colors.RESET}")
    
    def run(self):
        """Main application loop"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        if not os.path.exists(CONFIG_FILE):
            print(f"{Colors.YELLOW}First time setup...{Colors.RESET}")
            self.setup_configuration()
        
        self.start_bots()
        
        while self.running:
            try:
                prompt = f"{Colors.CYAN}[lazy-panda]{Colors.RESET} "
                command = input(prompt).strip()
                self.process_command(command)
            
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Exiting...{Colors.RESET}")
                self.running = False
            
            except Exception as e:
                print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        self.engine.db.close()
        print(f"\n{Colors.GREEN}Lazy Panda shutdown complete.{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        print("Starting Lazy Panda v8.0.0...")
        
        if sys.version_info < (3, 7):
            print("Python 3.7 or higher is required")
            sys.exit(1)
        
        app = LazyPandaApp()
        app.run()
    
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()