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
from smart_detector import SmartDetector
from attack_engine import AttackEngine

# Constantes de configuración
MAX_DEPTH = 10  # Profundidad máxima recomendada
MIN_DEPTH = 1   # Profundidad mínima

def create_domain_directory(url: str) -> str:
    """Crea un directorio para el dominio y retorna su ruta."""
    try:
        # Obtener el dominio de la URL
        domain = urlparse(url).netloc.lower()
        
        # Crear directorio para el dominio
        domain_dir = os.path.join('reports', domain)
        os.makedirs(domain_dir, exist_ok=True)
        
        # Crear subdirectorios
        os.makedirs(os.path.join(domain_dir, 'logs'), exist_ok=True)
        os.makedirs(os.path.join(domain_dir, 'screenshots'), exist_ok=True)
        os.makedirs(os.path.join(domain_dir, 'responses'), exist_ok=True)
        
        return domain_dir
    except Exception as e:
        logging.error(f"Error creando directorio para el dominio: {e}")
        return 'reports'

def setup_logging(domain_dir: str, verbose: bool = False):
    """Configura el sistema de logging."""
    # Configurar nivel de logging basado en el modo verbose
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Configurar formato del log
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Configurar handlers
    handlers = [
        logging.FileHandler(os.path.join(domain_dir, 'logs', 'crawl2bounty.log')),
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

async def run_scan(crawler: SmartCrawler, detector: SmartDetector, attack_engine: AttackEngine, report_generator: ReportGenerator, save_screenshots: bool = False, save_responses: bool = False):
    """Ejecuta el escaneo completo."""
    try:
        # Iniciar el crawling
        await crawler.start_crawl(crawler.base_url)
        
        # Analizar URLs descubiertas
        for url in crawler.visited_urls:
            try:
                # Analizar JavaScript
                js_findings = await detector.analyze_js(url)
                if js_findings:
                    report_generator.add_findings("javascript_analysis", js_findings)
                
                # Analizar contenido dinámico
                dynamic_findings = await detector.analyze_dynamic_content(url)
                if dynamic_findings:
                    report_generator.add_findings("dynamic_analysis", dynamic_findings)
                
                # Probar vulnerabilidades
                if attack_engine.interactsh_url:
                    vuln_findings = await attack_engine.test_vulnerabilities(url)
                    if vuln_findings:
                        report_generator.add_findings("vulnerability_scan", vuln_findings)
                
                # Guardar capturas de pantalla si está habilitado
                if save_screenshots:
                    await crawler.save_screenshot(url)
                
                # Guardar respuestas si está habilitado
                if save_responses:
                    await crawler.save_response(url)
                    
            except asyncio.CancelledError:
                logging.info("Escaneo interrumpido por el usuario")
                raise
            except Exception as e:
                logging.error(f"Error procesando URL {url}: {e}")
                continue
        
        # Generar reporte final
        await report_generator.generate_report("reporte_final")
        
    except asyncio.CancelledError:
        logging.info("Escaneo interrumpido por el usuario")
        # Asegurar que se genere un reporte parcial
        await report_generator.generate_report("reporte_parcial")
    except Exception as e:
        logging.error(f"Error durante el escaneo: {e}")
        # Asegurar que se genere un reporte parcial
        await report_generator.generate_report("reporte_error")
        raise

def main():
    """Main function to run the web vulnerability scanner."""
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner with Advanced Features')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--rate-limit', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--exclude', nargs='+', help='Patterns to exclude from crawling')
    parser.add_argument('--include', nargs='+', help='Patterns to include in crawling')
    parser.add_argument('--screenshots', action='store_true', help='Save screenshots of pages')
    parser.add_argument('--responses', action='store_true', help='Save page responses')
    parser.add_argument('--interactsh-url', help='Interactsh URL for OOB testing')
    parser.add_argument('--force', '-f', action='store_true', help='Forzar el análisis de dominios normalmente excluidos (redes sociales, etc.)')
    parser.add_argument('-o', '--output', help='Nombre del archivo de salida para el reporte')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose para mostrar más información')
    
    args = parser.parse_args()
    
    # Crear directorio para el dominio
    domain_dir = create_domain_directory(args.url)
    
    # Configurar logging
    logger = setup_logging(domain_dir, args.verbose)
    
    try:
        # Inicializar componentes
        console = ConsoleManager(verbose=args.verbose)
        report_generator = ReportGenerator(console_manager=console, output_file=args.output, domain_dir=domain_dir)
        crawler = SmartCrawler(
            base_url=args.url,
            max_depth=args.depth,
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            excluded_patterns=args.exclude,
            included_patterns=args.include,
            interactsh_url=args.interactsh_url,
            report_generator=report_generator,
            force=args.force,
            domain_dir=domain_dir
        )
        detector = SmartDetector(console_manager=console)
        attack_engine = AttackEngine(console_manager=console, smart_detector=detector, interactsh_url=args.interactsh_url)
        
        # Configurar manejador de señales
        def signal_handler(signum, frame):
            console.print_warning("\nSeñal de interrupción recibida. Finalizando escaneo...")
            # Cancelar todas las tareas asíncronas
            for task in asyncio.all_tasks():
                task.cancel()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Ejecutar el escaneo
        asyncio.run(run_scan(
            crawler=crawler,
            detector=detector,
            attack_engine=attack_engine,
            report_generator=report_generator,
            save_screenshots=args.screenshots,
            save_responses=args.responses
        ))
        
    except KeyboardInterrupt:
        console.print_warning("\nEscaneo interrumpido por el usuario")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("Crawl2Bounty requiere Python 3.7 o superior.", file=sys.stderr)
        sys.exit(1)
    main()