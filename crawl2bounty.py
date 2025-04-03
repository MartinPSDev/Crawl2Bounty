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
import subprocess
import requests
from packaging import version
import json

# Constantes de configuración
MAX_DEPTH = 10  # Profundidad máxima recomendada
MIN_DEPTH = 1   # Profundidad mínima
GITHUB_REPO = "M4rt1n_0x1337/crawl2Bounty"  

def get_repo_info():
    """Obtiene la información del repositorio desde el archivo de configuración."""
    try:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config['repository']
    except Exception as e:
        logging.error(f"Error leyendo configuración: {e}")
    return None

def get_git_info():
    """Obtiene información del repositorio git si existe."""
    try:
        # Verificar si estamos en un repositorio git
        if os.path.exists('.git'):
            # Obtener URL remota
            result = subprocess.run(['git', 'remote', '-v'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'origin' in line and '(fetch)' in line:
                        url = line.split()[1]
                        # Extraer owner y repo de la URL
                        if 'github.com' in url:
                            parts = url.replace('.git', '').split('/')
                            owner = parts[-2]
                            repo = parts[-1]
                            return {
                                'owner': owner,
                                'name': repo,
                                'is_git': True
                            }
    except Exception as e:
        logging.error(f"Error obteniendo información git: {e}")
    return None

def check_for_updates():
    """Verifica si hay actualizaciones disponibles en GitHub."""
    try:
        # Primero intentar obtener info de git
        git_info = get_git_info()
        if git_info and git_info['is_git']:
            repo_owner = git_info['owner']
            repo_name = git_info['name']
        else:
            # Si no es git, usar la configuración
            repo_info = get_repo_info()
            if not repo_info:
                return False, None
            repo_owner = repo_info['owner']
            repo_name = repo_info['name']
        
        # Obtener la versión actual
        current_version = get_current_version()
        
        # Obtener la última versión de GitHub
        response = requests.get(f"https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest")
        if response.status_code == 200:
            latest_version = response.json()["tag_name"]
            if version.parse(latest_version) > version.parse(current_version):
                return True, latest_version
    except Exception as e:
        logging.error(f"Error checking for updates: {e}")
    return False, None

def get_current_version():
    """Obtiene la versión actual de la herramienta."""
    try:
        # Primero intentar desde git
        if os.path.exists('.git'):
            result = subprocess.run(['git', 'describe', '--tags'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        
        # Si no es git, usar la configuración
        repo_info = get_repo_info()
        if repo_info:
            return repo_info['version']
    except Exception as e:
        logging.error(f"Error obteniendo versión actual: {e}")
    return "1.0.0"  # Versión por defecto

def update_tool():
    """Actualiza el tool desde GitHub."""
    try:
        console = ConsoleManager(verbose=True)
        console.print_info("Iniciando actualización...")
        
        # Obtener información del repositorio
        git_info = get_git_info()
        if git_info and git_info['is_git']:
            # Si es un repositorio git, actualizar
            console.print_info("Actualizando desde repositorio git...")
            subprocess.run(["git", "pull"], check=True)
        else:
            # Si no es git, usar la configuración
            repo_info = get_repo_info()
            if not repo_info:
                console.print_error("No se pudo determinar el repositorio para actualizar")
                return False
            
            console.print_info(f"Clonando repositorio {repo_info['owner']}/{repo_info['name']}...")
            subprocess.run([
                "git", "clone", 
                f"https://github.com/{repo_info['owner']}/{repo_info['name']}.git",
                "temp_update"
            ], check=True)
            
            # Copiar archivos actualizados
            for file in os.listdir("temp_update"):
                if file != ".git":
                    src = os.path.join("temp_update", file)
                    dst = os.path.join(".", file)
                    if os.path.isdir(src):
                        if os.path.exists(dst):
                            subprocess.run(["rm", "-rf", dst])
                        subprocess.run(["cp", "-r", src, "."])
                    else:
                        subprocess.run(["cp", src, dst])
            
            # Limpiar directorio temporal
            subprocess.run(["rm", "-rf", "temp_update"])
        
        # Instalar dependencias actualizadas
        console.print_info("Instalando dependencias actualizadas...")
        subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)
        
        console.print_success("Actualización completada exitosamente!")
        return True
    except Exception as e:
        console.print_error(f"Error durante la actualización: {e}")
        return False

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
    parser.add_argument('url', nargs='?', help='Target URL to scan')
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
    parser.add_argument('-u', '--update', action='store_true', help='Actualizar la herramienta desde GitHub')
    
    args = parser.parse_args()
    
    # Verificar si se solicitó actualización
    if args.update:
        if update_tool():
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Verificar si se proporcionó URL
    if not args.url:
        parser.print_help()
        sys.exit(1)
    
    # Verificar actualizaciones disponibles
    has_update, latest_version = check_for_updates()
    if has_update:
        console = ConsoleManager(verbose=True)
        console.print_warning(f"Hay una nueva versión disponible: {latest_version}")
        console.print_info("Ejecuta con el flag -u o --update para actualizar")
    
    # Crear directorio para el dominio
    domain_dir = create_domain_directory(args.url)
    
    # Configurar logging
    logger = setup_logging(domain_dir, args.verbose)
    
    try:
        # Inicializar componentes
        console = ConsoleManager(verbose=args.verbose)
        report_generator = ReportGenerator(
            console_manager=console, 
            output_file=args.output,
            domain_dir=domain_dir
        )
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