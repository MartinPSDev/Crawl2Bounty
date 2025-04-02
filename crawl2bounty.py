import argparse
from rich.console import Console
from site_crawler import SmartCrawler
from console_manager import ConsoleManager
from report_generator import ReportGenerator
import asyncio
import time
import logging
import os
import sys
import playwright.async_api as pw
import httpx
import signal
from typing import Optional
from urllib.parse import urlparse

# Constantes de configuración
MAX_DEPTH = 10  # Profundidad máxima recomendada
MIN_DEPTH = 1   # Profundidad mínima

def setup_logging(verbose: bool = False):
    """Configura el sistema de logging."""
    # Configurar nivel de logging basado en el modo verbose
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Crear directorio de logs si no existe
    os.makedirs('logs', exist_ok=True)
    
    # Configurar formato del log
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Configurar handlers
    handlers = [
        logging.FileHandler('logs/crawl2bounty.log'),
        logging.StreamHandler()
    ]
    
    # Configurar logging básico
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt=date_format,
        handlers=handlers
    )
    
    # Configurar logging para bibliotecas externas
    logging.getLogger('playwright').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    
    # Configurar logger para este módulo
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    
    return logger

# Configurar logger para este módulo
logger = logging.getLogger(__name__)

def display_banner(console):
    """Muestra el banner de la aplicación."""
    banner = r"""
██████╗  ██████╗ ██████╗  ██████╗ ████████╗   ██╗   ██╗██╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝   ██║   ██║██║   ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██████╔╝██║   ██║   ██║      ██║   ██║██║   ██║   ██║   ███████╗██████╔╝
██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║      ██║   ██║██║   ██║   ██║   ╚════██║██╔══██╗
██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║      ╚██████╔╝╚██████╔╝   ██║   ███████║██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝       ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝
                                Versión 1.1.0 - Reconocimiento Web Avanzado
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]\n", highlight=False)

def setup_signal_handlers(console_manager: Optional[ConsoleManager] = None):
    """Configura los manejadores de señales para interrupción elegante."""
    def signal_handler(signum, frame):
        if console_manager:
            console_manager.print_warning("\nSeñal de interrupción recibida. Finalizando escaneo...")
        else:
            print("\nSeñal de interrupción recibida. Finalizando escaneo...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def validate_target_url(url: str) -> bool:
    """Valida que la URL objetivo sea válida y accesible."""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False

def validate_depth(depth: int) -> bool:
    """Valida que la profundidad de rastreo esté dentro de los límites permitidos."""
    return MIN_DEPTH <= depth <= MAX_DEPTH

def main():
    """Main function to run the crawl2bounty."""
    parser = argparse.ArgumentParser(description='Crawl2Bounty - Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('-o', '--output', help='Output file prefix (default: robot_hunter)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--rate-limit', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--proxy', help='Proxy server URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    parser.add_argument('--max-requests', type=int, help='Maximum number of requests to make')
    parser.add_argument('--save-screenshots', action='store_true', help='Save screenshots of pages')
    parser.add_argument('--save-responses', action='store_true', help='Save response bodies')
    parser.add_argument('--threads', type=int, default=4, help='Number of concurrent threads (default: 4)')
    
    args = parser.parse_args()
    
    # Validate target URL
    if not validate_target_url(args.url):
        print("Error: URL inválida. Por favor, proporcione una URL válida.")
        sys.exit(1)
    
    # Validate depth
    if not validate_depth(args.depth):
        print(f"Error: La profundidad debe estar entre {MIN_DEPTH} y {MAX_DEPTH}.")
        sys.exit(1)
    
    # Setup logging
    logger = setup_logging(args.verbose)
    logger.info("Iniciando Crawl2Bounty")
    
    # Initialize console manager with verbose enabled
    console_manager = ConsoleManager(verbose=True)
    
    # Setup signal handlers with console manager
    setup_signal_handlers(console_manager)
    
    try:
        # Initialize crawler
        crawler = SmartCrawler(
            base_url=args.url,
            max_depth=args.depth,
            timeout=30,
            rate_limit=args.rate_limit,
            excluded_patterns=None,
            included_patterns=None,
            interactsh_url=None
        )
        
        # Initialize report generator
        report_generator = ReportGenerator(
            output_prefix=args.output or "crawl2bounty",
            save_screenshots=args.save_screenshots,
            save_responses=args.save_responses
        )
        
        # Display configuration
        console_manager.print_info("Configuración del escaneo:")
        console_manager.print_info(f"URL objetivo: {args.url}")
        console_manager.print_info(f"Profundidad máxima: {args.depth}")
        console_manager.print_info(f"Límite de tasa: {args.rate_limit} segundos")
        if args.proxy:
            console_manager.print_info(f"Proxy: {args.proxy}")
        if args.user_agent:
            console_manager.print_info(f"User-Agent: {args.user_agent}")
        if args.max_requests:
            console_manager.print_info(f"Máximo de solicitudes: {args.max_requests}")
        if args.save_screenshots:
            console_manager.print_info("Guardando capturas de pantalla")
        if args.save_responses:
            console_manager.print_info("Guardando cuerpos de respuesta")
        console_manager.print_info(f"Hilos concurrentes: {args.threads}")
        
        # Start crawling
        asyncio.run(crawler.start_crawl(args.url, args.depth))
        
        # Generate report
        report_generator.generate_report()
        
        console_manager.print_success("Escaneo completado exitosamente")
        
    except KeyboardInterrupt:
        console_manager.print_warning("\nEscaneo interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        console_manager.print_error(f"Error durante el escaneo: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("Crawl2Bounty requiere Python 3.7 o superior.", file=sys.stderr)
        sys.exit(1)
    main()