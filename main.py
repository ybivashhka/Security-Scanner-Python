import socket
import ipaddress
import concurrent.futures
import argparse
from datetime import datetime
from typing import List, Dict, Tuple
import sys
import re
import json
from colorama import init, Fore, Style
import logging
from tqdm import tqdm

# Инициализация colorama и логирования
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Остальной код остается без изменений (функции load_vulnerabilities, parse_ip_range и т.д.)
def load_vulnerabilities(file_path: str) -> Dict[int, str]:
    """Загружает базу уязвимостей из JSON-файла с проверкой существования."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        vulnerabilities = {}
        for k, v in data.items():
            if not k.isdigit() or not (1 <= int(k) <= 65535):
                logger.warning(f"Invalid port in {file_path}: {k}")
                continue
            vulnerabilities[int(k)] = v
        if not vulnerabilities:
            logger.warning(f"No valid vulnerabilities found in {file_path}")
        return vulnerabilities
    except FileNotFoundError:
        logger.error(f"Vulnerability file not found: {file_path}. Please create it with valid JSON data.")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format in {file_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load vulnerabilities: {e}")
        sys.exit(1)

def parse_ip_range(ip_range: str) -> List[str]:
    """Парсит диапазон IP-адресов или одиночный IP."""
    try:
        if '-' in ip_range:
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_range):
                raise ValueError("Invalid IP range format. Use: x.x.x.x-y.y.y.y")
            start_ip, end_ip = ip_range.split('-')
            start = int(ipaddress.IPv4Address(start_ip))
            end = int(ipaddress.IPv4Address(end_ip))
            if start > end:
                raise ValueError("Start IP must be less than or equal to end IP")
            return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
        else:
            ip = str(ipaddress.IPv4Address(ip_range))
            return [ip]
    except ValueError as e:
        logger.error(f"Invalid IP format: {e}")
        sys.exit(1)

def scan_port(ip: str, port: int, timeout: float, vulns: Dict[int, str]) -> Tuple[int, bool, str]:
    """Сканирует один порт на указанном IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            is_open = result == 0
            vuln = vulns.get(port, "No known vulnerabilities")
            return port, is_open, vuln
    except socket.error:
        return port, False, "Connection error"

def scan_ip(ip: str, ports: range, vulns: Dict[int, str], timeout: float) -> List[Tuple[int, bool, str]]:
    """Сканирует указанный IP на открытые порты с прогресс-баром."""
    results = []
    logger.info(f"Scanning {ip}")
    total_ports = len(ports)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port, timeout, vulns) for port in ports]
        with tqdm(total=total_ports, desc=f"Scanning {ip}", unit="port") as pbar:
            for future in concurrent.futures.as_completed(futures):
                port, is_open, vuln = future.result()
                if is_open:
                    results.append((port, is_open, vuln))
                pbar.update(1)
    
    logger.info(f"Completed scanning {ip}: {len(results)} open ports found")
    return results

def generate_report(results: Dict[str, List[Tuple[int, bool, str]]], out_file: str, scan_duration: float):
    """Генерирует отчёт и сохраняет его в файл."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"Port Scan Report - {timestamp}",
        f"Scanned IPs: {len(results)}",
        f"Scan Duration: {scan_duration:.2f} seconds",
        "=" * 50,
        ""
    ]
    
    for ip, ports in results.items():
        lines.append(f"IP: {ip}")
        if ports:
            lines.append(f"  Open ports ({len(ports)}):")
            for port, _, vuln in sorted(ports, key=lambda x: x[0]):  # Сортировка по портам
                lines.append(f"    Port {port}: {vuln}")
        else:
            lines.append("  No open ports found.")
        lines.append("-" * 50)
    
    report = "\n".join(lines)
    print(report)
    
    try:
        with open(out_file, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {out_file}")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")

def main():
    """Основная функция приложения."""
    parser = argparse.ArgumentParser(description="Multi-IP Port Vulnerability Scanner")
    parser.add_argument("--ip", type=str, required=True, help="IP or IP range (e.g., 192.168.1.1-192.168.1.10)")
    parser.add_argument("--ports", type=str, default="1-1024", help="Port range (e.g., 1-65535)")
    parser.add_argument("--vulns", type=str, default="vulns.json", help="Path to vulnerability database")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout for port scanning (seconds)")
    parser.add_argument("--output", type=str, default="report.txt", help="Output report file")
    args = parser.parse_args()

    if args.timeout <= 0:
        logger.error("Timeout must be positive")
        sys.exit(1)
    
    start_time = datetime.now()
    ip_list = parse_ip_range(args.ip)
    
    try:
        start_port, end_port = map(int, args.ports.split('-'))
        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError("Ports must be between 1 and 65535")
        ports = range(start_port, end_port + 1)
    except ValueError as e:
        logger.error(f"Invalid port range: {e}")
        sys.exit(1)
    
    vulnerabilities = load_vulnerabilities(args.vulns)
    
    all_results = {}
    for ip in ip_list:
        results = scan_ip(ip, ports, vulnerabilities, args.timeout)
        all_results[ip] = results
    
    scan_duration = (datetime.now() - start_time).total_seconds()
    generate_report(all_results, args.output, scan_duration)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
