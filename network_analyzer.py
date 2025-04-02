from scapy.all import *
from scapy.layers.http import *
from scapy.layers.dns import DNS
import asyncio
from typing import Dict, List, Optional
import socket
from urllib.parse import urlparse
import logging

class NetworkAnalyzer:
    def __init__(self):
        self.findings = []
        self.logger = logging.getLogger(__name__)
        self.captured_packets = []
        self.target_domain = None
        self.target_ip = None

    async def setup(self, target_url: str):
        """Configuración inicial para el análisis de red"""
        try:
            parsed_url = urlparse(target_url)
            self.target_domain = parsed_url.netloc
            self.target_ip = socket.gethostbyname(self.target_domain)
            print(f"[+] Objetivo configurado: {self.target_domain} ({self.target_ip})")
        except Exception as e:
            self.logger.error(f"Error en setup: {e}")
            raise

    def start_capture(self, interface: str = None, timeout: int = 30):
        """Inicia la captura de paquetes"""
        try:
            # Si no se especifica interfaz, usar la predeterminada
            if not interface:
                interface = conf.iface

            print(f"[+] Iniciando captura en interfaz {interface}")
            
            # Filtro para capturar solo tráfico relacionado con el objetivo
            filter_str = f"host {self.target_ip}"
            
            # Iniciar captura
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self.packet_callback,
                timeout=timeout
            )
            
            print(f"[+] Captura finalizada. Paquetes capturados: {len(self.captured_packets)}")
            
        except Exception as e:
            self.logger.error(f"Error en captura: {e}")
            raise

    def packet_callback(self, packet):
        """Callback para procesar cada paquete capturado"""
        try:
            self.captured_packets.append(packet)
            
            # Analizar paquetes HTTP
            if packet.haslayer(HTTP):
                self.analyze_http_packet(packet)
            
            # Analizar paquetes TCP
            elif packet.haslayer(TCP):
                self.analyze_tcp_packet(packet)
                
            # Analizar paquetes DNS
            elif packet.haslayer(DNS):
                self.analyze_dns_packet(packet)
                
        except Exception as e:
            self.logger.error(f"Error procesando paquete: {e}")

    def analyze_http_packet(self, packet):
        """Analiza paquetes HTTP en busca de información sensible"""
        try:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                
                # Registrar la petición
                finding = {
                    "type": "http_request",
                    "method": http_layer.Method.decode(),
                    "path": http_layer.Path.decode(),
                    "headers": {},
                    "timestamp": packet.time
                }
                
                # Analizar headers
                for field in http_layer.fields:
                    if field != "Method" and field != "Path":
                        finding["headers"][field] = http_layer.fields[field]
                
                # Buscar información sensible en parámetros
                if b"?" in http_layer.Path:
                    finding["params"] = self.analyze_params(http_layer.Path.decode())
                
                self.findings.append(finding)
                
            elif packet.haslayer(HTTPResponse):
                http_layer = packet[HTTPResponse]
                
                # Registrar la respuesta
                finding = {
                    "type": "http_response",
                    "status_code": http_layer.Status_Code,
                    "headers": {},
                    "timestamp": packet.time
                }
                
                # Analizar headers de respuesta
                for field in http_layer.fields:
                    if field != "Status_Code":
                        finding["headers"][field] = http_layer.fields[field]
                
                self.findings.append(finding)
                
        except Exception as e:
            self.logger.error(f"Error analizando paquete HTTP: {e}")

    def analyze_tcp_packet(self, packet):
        """Analiza paquetes TCP buscando patrones sospechosos"""
        try:
            tcp = packet[TCP]
            
            # Registrar conexiones a puertos sensibles
            sensitive_ports = {80, 443, 21, 22, 23, 3306, 5432}
            if tcp.dport in sensitive_ports or tcp.sport in sensitive_ports:
                self.findings.append({
                    "type": "sensitive_port_connection",
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "timestamp": packet.time,
                    "flags": tcp.flags
                })
                
        except Exception as e:
            self.logger.error(f"Error analizando paquete TCP: {e}")

    def analyze_dns_packet(self, packet):
        """Analiza paquetes DNS para detectar subdominios"""
        try:
            dns = packet[DNS]
            
            if dns.qr == 0:  # Es una consulta DNS
                for i in range(dns.qdcount):
                    query = dns.qd[i]
                    if self.target_domain in query.qname.decode():
                        self.findings.append({
                            "type": "dns_query",
                            "domain": query.qname.decode(),
                            "query_type": query.qtype,
                            "timestamp": packet.time
                        })
                        
        except Exception as e:
            self.logger.error(f"Error analizando paquete DNS: {e}")

    def analyze_params(self, path: str) -> Dict:
        """Analiza parámetros en busca de patrones sensibles"""
        sensitive_patterns = {
            "auth": r"(api[_-]?key|auth[_-]?token|access[_-]?token)",
            "personal": r"(password|passwd|secret|ssn|email)",
            "technical": r"(select|union|drop|exec|eval)"
        }
        
        findings = {}
        try:
            params = path.split("?")[1].split("&")
            for param in params:
                name, value = param.split("=")
                for category, pattern in sensitive_patterns.items():
                    if re.search(pattern, name, re.I):
                        findings[name] = {
                            "category": category,
                            "value": value
                        }
        except Exception as e:
            self.logger.error(f"Error analizando parámetros: {e}")
            
        return findings

    def get_findings(self) -> List[Dict]:
        """Retorna todos los hallazgos encontrados"""
        return self.findings

    def generate_network_report(self) -> Dict:
        """Genera un reporte del análisis de red"""
        return {
            "target": {
                "domain": self.target_domain,
                "ip": self.target_ip
            },
            "statistics": {
                "total_packets": len(self.captured_packets),
                "http_requests": len([f for f in self.findings if f["type"] == "http_request"]),
                "sensitive_connections": len([f for f in self.findings if f["type"] == "sensitive_port_connection"]),
                "dns_queries": len([f for f in self.findings if f["type"] == "dns_query"])
            },
            "findings": self.findings
        } 