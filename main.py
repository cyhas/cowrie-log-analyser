#!/usr/bin/env python3
"""
Cowrie Log Analyzer
A simple CLI-based tool to analyze Cowrie honeypot logs and generate comprehensive reports.
"""

import re
import sys
import argparse
import os
from collections import Counter, defaultdict
from datetime import datetime
import json

class CowrieLogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.connections = []
        self.login_attempts = []
        self.commands = []
        self.ip_addresses = Counter()
        self.usernames = Counter()
        self.passwords = Counter()
        self.successful_logins = Counter()
        self.failed_logins = Counter()
        self.commands_executed = Counter()
        self.session_data = defaultdict(list)
        self.geo_data = defaultdict(int)
        
    def parse_logs(self):
        """Parse the Cowrie log file and extract relevant information."""
        print(f"Parsing log file: {self.log_file}")
        
        try:
            # First, count total lines for percentage calculation
            print("Counting lines...", end='\r')
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for _ in f)
            
            print(f"Found {total_lines:,} lines. Parsing...")
            
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num % 1000 == 0 or line_num == total_lines:
                        percentage = (line_num / total_lines) * 100
                        print(f"Progress: {percentage:.1f}% ({line_num:,}/{total_lines:,})", end='\r')
                    
                    self._parse_line(line.strip())
                    
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading log file: {e}")
            sys.exit(1)
            
        print(f"\nFinished parsing {line_num:,} lines.")
    
    def _parse_line(self, line):
        """Parse individual log line and extract relevant data."""
        # Extract timestamp
        timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})', line)
        if not timestamp_match:
            return
            
        timestamp = timestamp_match.group(1)
        
        # Extract IP address from connection logs
        ip_match = re.search(r'New connection: ([\d\.]+):', line)
        if ip_match:
            ip = ip_match.group(1)
            self.ip_addresses[ip] += 1
            self.connections.append({
                'timestamp': timestamp,
                'ip': ip,
                'line': line
            })
        
        # Extract login attempts
        login_match = re.search(r'login attempt \[b\'([^\']+)\'/b\'([^\']+)\'\] (succeeded|failed)', line)
        if login_match:
            username = login_match.group(1)
            password = login_match.group(2)
            status = login_match.group(3)
            
            self.login_attempts.append({
                'timestamp': timestamp,
                'username': username,
                'password': password,
                'status': status,
                'line': line
            })
            
            self.usernames[username] += 1
            self.passwords[password] += 1
            
            if status == 'succeeded':
                self.successful_logins[username] += 1
            else:
                self.failed_logins[username] += 1
        
        # Extract commands executed
        cmd_match = re.search(r'CMD: (.+)', line)
        if cmd_match:
            command = cmd_match.group(1)
            self.commands_executed[command] += 1
            self.commands.append({
                'timestamp': timestamp,
                'command': command,
                'line': line
            })
        
        # Extract file downloads
        download_match = re.search(r'File download: (.+)', line)
        if download_match:
            filename = download_match.group(1)
            # Could add download tracking here
    
    def generate_report(self, output_file):
        """Generate comprehensive analysis report."""
        print(f"Generating report: {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("COWRIE HONEYPOT LOG ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Log file: {self.log_file}\n\n")
            
            # Summary Statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total connections: {len(self.connections):,}\n")
            f.write(f"Total login attempts: {len(self.login_attempts):,}\n")
            f.write(f"Successful logins: {sum(self.successful_logins.values()):,}\n")
            f.write(f"Failed logins: {sum(self.failed_logins.values()):,}\n")
            f.write(f"Commands executed: {len(self.commands):,}\n")
            f.write(f"Unique IP addresses: {len(self.ip_addresses):,}\n")
            f.write(f"Unique usernames: {len(self.usernames):,}\n")
            f.write(f"Unique passwords: {len(self.passwords):,}\n\n")
            
            # Top IP Addresses
            f.write("TOP 15 IP ADDRESSES\n")
            f.write("-" * 40 + "\n")
            for i, (ip, count) in enumerate(self.ip_addresses.most_common(15), 1):
                f.write(f"{i:2d}. {ip:<15} - {count:,} connections\n")
            f.write("\n")
            
            # Top Usernames
            f.write("TOP 15 USERNAMES\n")
            f.write("-" * 40 + "\n")
            for i, (username, count) in enumerate(self.usernames.most_common(15), 1):
                successful = self.successful_logins.get(username, 0)
                failed = self.failed_logins.get(username, 0)
                f.write(f"{i:2d}. {username:<15} - {count:,} attempts ({successful} successful, {failed} failed)\n")
            f.write("\n")
            
            # Top Passwords
            f.write("TOP 15 PASSWORDS\n")
            f.write("-" * 40 + "\n")
            for i, (password, count) in enumerate(self.passwords.most_common(15), 1):
                f.write(f"{i:2d}. {password:<15} - {count:,} attempts\n")
            f.write("\n")
            
            # Top Commands
            f.write("TOP 15 COMMANDS EXECUTED\n")
            f.write("-" * 40 + "\n")
            for i, (command, count) in enumerate(self.commands_executed.most_common(15), 1):
                # Truncate long commands
                display_cmd = command[:60] + "..." if len(command) > 60 else command
                f.write(f"{i:2d}. {display_cmd:<63} - {count:,} times\n")
            f.write("\n")
            
            
            # Time-based Analysis
            f.write("TIME-BASED ANALYSIS\n")
            f.write("-" * 40 + "\n")
            if self.connections:
                first_connection = min(self.connections, key=lambda x: x['timestamp'])
                last_connection = max(self.connections, key=lambda x: x['timestamp'])
                f.write(f"First connection: {first_connection['timestamp']}\n")
                f.write(f"Last connection:  {last_connection['timestamp']}\n")
                
                # Calculate duration
                try:
                    start_time = datetime.fromisoformat(first_connection['timestamp'].replace('+0000', '+00:00'))
                    end_time = datetime.fromisoformat(last_connection['timestamp'].replace('+0000', '+00:00'))
                    duration = end_time - start_time
                    f.write(f"Duration: {duration.days} days, {duration.seconds // 3600} hours\n")
                except:
                    f.write("Duration: Unable to calculate\n")
            f.write("\n")
            
            # Security Insights
            f.write("SECURITY INSIGHTS\n")
            f.write("-" * 40 + "\n")
            total_attempts = len(self.login_attempts)
            successful_attempts = sum(self.successful_logins.values())
            if total_attempts > 0:
                success_rate = (successful_attempts / total_attempts) * 100
                f.write(f"Overall login success rate: {success_rate:.2f}%\n")
            
            # Most targeted usernames
            if self.usernames:
                most_targeted = self.usernames.most_common(1)[0]
                f.write(f"Most targeted username: {most_targeted[0]} ({most_targeted[1]:,} attempts)\n")
            
            # Most common passwords
            if self.passwords:
                most_common_pwd = self.passwords.most_common(1)[0]
                f.write(f"Most common password: {most_common_pwd[0]} ({most_common_pwd[1]:,} attempts)\n")
            
            # Most active IP
            if self.ip_addresses:
                most_active_ip = self.ip_addresses.most_common(1)[0]
                f.write(f"Most active IP: {most_active_ip[0]} ({most_active_ip[1]:,} connections)\n")
            
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        print(f"Report saved to: {output_file}")

def find_log_file(log_file_arg):
    """Find the log file, checking logs directory if not specified."""
    if log_file_arg:
        if os.path.exists(log_file_arg):
            return log_file_arg
        else:
            print(f"Error: Specified log file '{log_file_arg}' not found.")
            sys.exit(1)
    
    # Auto-detect log file in logs directory
    logs_dir = "logs"
    default_log_file = os.path.join(logs_dir, "logs.txt")
    
    if os.path.exists(default_log_file):
        return default_log_file
    
    # Look for any .txt files in logs directory
    if os.path.exists(logs_dir):
        txt_files = [f for f in os.listdir(logs_dir) if f.endswith('.txt')]
        if txt_files:
            return os.path.join(logs_dir, txt_files[0])
    
    print("Error: No log file found.")
    print("Usage:")
    print("  python3 main.py [log_file] [-o output_file] [-v]")
    print("  python3 main.py logs/logs.txt")
    print("  python3 main.py -o my_report.txt")
    print("\nIf no log file is specified, the analyzer will look for 'logs.txt' in the 'logs' directory.")
    sys.exit(1)

def generate_output_filename(output_arg):
    """Generate output filename with timestamp if not specified."""
    if output_arg:
        return output_arg
    
    # Create output directory if it doesn't exist
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(output_dir, f"cowrie_analysis_report_{timestamp}.txt")

def main():
    parser = argparse.ArgumentParser(
        description='Analyze Cowrie honeypot logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py                           # Auto-detect logs.txt in logs/ directory
  python3 main.py logs/logs.txt             # Specify log file
  python3 main.py -o my_report.txt          # Custom output file
  python3 main.py logs/logs.txt -o output/  # Custom output with auto-timestamp
  python3 main.py -v                        # Verbose output

If no log file is specified, the analyzer will automatically look for 'logs.txt' 
in the 'logs' directory. If no output file is specified, a timestamped file will 
be created in the 'output' directory.
        """
    )
    parser.add_argument('log_file', nargs='?', help='Path to the Cowrie log file (optional)')
    parser.add_argument('-o', '--output', help='Output file for the analysis report (optional)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    print("Cowrie Log Analyzer")
    print("=" * 50)
    
    # Find log file
    log_file = find_log_file(args.log_file)
    print(f"Using log file: {log_file}")
    
    # Generate output filename
    output_file = generate_output_filename(args.output)
    print(f"Output file: {output_file}")
    
    # Create analyzer instance
    analyzer = CowrieLogAnalyzer(log_file)
    
    # Parse logs
    analyzer.parse_logs()
    
    # Generate report
    analyzer.generate_report(output_file)
    
    print(f"\nAnalysis complete! Report saved to: {output_file}")
    print(f"Summary:")
    print(f"  - {len(analyzer.connections):,} total connections")
    print(f"  - {len(analyzer.login_attempts):,} login attempts")
    print(f"  - {len(analyzer.ip_addresses):,} unique IP addresses")
    print(f"  - {len(analyzer.usernames):,} unique usernames")

if __name__ == "__main__":
    main()
