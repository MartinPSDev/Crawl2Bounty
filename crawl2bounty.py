import argparse
import asyncio
import logging
import os
import sys
import signal
import subprocess
import json
import shutil
import requests
from typing import Optional
from urllib.parse import urlparse
from packaging import version
from site_crawler import SmartCrawler
from console_manager import ConsoleManager
from report_generator import ReportGenerator
from smart_detector import SmartDetector
from attack_engine import AttackEngine

# Constantes de configuración
MAX_DEPTH = 10
MIN_DEPTH = 1
GITHUB_REPO = "M4rt1n_0x1337/crawl2Bounty"

# Configurar logger global
logger = logging.getLogger(__name__)

def get_repo_info():
    """Obtiene la información del repositorio desde el archivo de configuración."""
    try:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f).get('repository')
    except Exception as e:
        logger.error(f"Error leyendo configuración: {e}")
    return None

def get_git_info():
    """Obtiene información del repositorio git si existe."""
    try:
        if os.path.exists('.git'):
            result = subprocess.run(['git', 'remote', '-v'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'origin' in line and '(fetch)' in line:
                        url = line.split()[1]
                        if 'github.com' in url:
                            parts = url.replace('.git', '').split('/')
                            return {'owner': parts[-2], 'name': parts[-1], 'is_git': True}
    except Exception as e:
        logger.error(f"Error obteniendo información git: {e}")
    return None

def get_current_version():
    """Obtiene la versión actual de la herramienta."""
    try:
        if os.path.exists('.git'):
            result = subprocess.run(['git', 'describe', '--tags'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        repo_info = get_repo_info()
        if repo_info:
            return repo_info.get('version', '1.0.0')
    except Exception as e:
        logger.error(f"Error obteniendo versión actual: {e}")
    return "1.0.0"

def check_for_updates():
    """Verifica si hay actualizaciones disponibles en GitHub."""
    try:
        git_info = get_git_info()
        repo_owner, repo_name = (git_info['owner'], git_info['name']) if git_info and git_info['is_git'] else (get_repo_info()['owner'], get_repo_info()['name']) if get_repo_info() else (None, None)
        if not repo_owner or not repo_name:
            return False, None
        current_version = get_current_version()
        response = requests.get(f"https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest", timeout=5)
        if response.status_code == 200:
            latest_version = response.json()["tag_name"]
            if version.parse(latest_version) > version.parse(current_version):
                return True, latest_version
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
    return False, None

def update_tool():
    """Actualiza la herramienta desde GitHub."""
    console = ConsoleManager(verbose=True)
    try:
        console.print_info("Iniciando actualización...")
        git_info = get_git_info()
        if git_info and git_info['is_git']:
            console.print_info("Actualizando desde repositorio git...")
            subprocess.run(['git', 'fetch', 'origin'], check=True)
            subprocess.run(['git', 'reset', '--hard', 'origin/main'], check=True)
        else:
            repo_info = get_repo_info()
            if not repo_info:
                console.print_error("No se pudo determinar el repositorio para actualizar")
                return False
            console.print_info(f"Clonando repositorio {repo_info['owner']}/{repo_info['name']}...")
            subprocess.run(["git", "clone", f"https://github.com/{repo_info['owner']}/{repo_info['name']}.git", "temp_update"], check=True)
            items_to_preserve = {'reports', 'temp_update', 'config.json', '.env'}
            for item in os.listdir("."):
                if item not in items_to_preserve:
                    item_path = os.path.join(".", item)
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
            for file in os.listdir("temp_update"):
                if file not in items_to_preserve:
                    shutil.move(os.path.join("temp_update", file), os.path.join(".", file))
            shutil.rmtree("temp_update")

        console.print_info("Instalando dependencias actualizadas...")
        if os.path.exists('/etc/kali-release') and ('VIRTUAL_ENV' in os.environ or sys.base_prefix != sys.prefix):
            subprocess.run(['python3', '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
            subprocess.run(['python3', '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)
        else:
            subprocess.run(['pip', 'install', '-r', 'requirements.txt'], check=True)
        console.print_success("Actualización completada exitosamente!")
        return True
    except Exception as e:
        console.print_error(f"Error durante la actualización: {e}")
        return False

def create_domain_directory(url: str) -> str:
    """Crea un directorio para el dominio y retorna su ruta."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower() if parsed.netloc else url.split('/')[0].lower()
        domain_dir = os.path.join('reports', domain)
        os.makedirs(os.path.join(domain_dir, 'logs'), exist_ok=True)
        os.makedirs(os.path.join(domain_dir, 'screenshots'), exist_ok=True)
        os.makedirs(os.path.join(domain_dir, 'responses'), exist_ok=True)
        logger.debug(f"Directorio creado: {domain_dir}")
        return domain_dir
    except Exception as e:
        logger.error(f"Error creando directorio para el dominio: {e}")
        return 'reports'

def setup_logging(domain_dir: str, verbose: bool = False):
    """Configura el sistema de logging."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[logging.FileHandler(os.path.join(domain_dir, 'logs', 'crawl2bounty.log')), logging.StreamHandler()]
    )
    logging.getLogger('playwright').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logger.setLevel(log_level)
    logger.debug("Logging configurado")

def display_banner(console: ConsoleManager):
    """Muestra el banner de la aplicación."""
    banner = r"""
   ____  ____   ____  
  / ___|___  | | __ ) 
 | |      / /  |  _ \ 
 | |___  / /_  | |_) |
  \____|/____| |____/ 
    Crawl2Bounty
    by @M4rt1n_0x1337
    Version 1.1.0 - Advanced Web Recognition
    """
    console.print_info(f"[bold cyan]{banner}[/bold cyan]")

def validate_target_url(url: str) -> str:
    """Valida y normaliza la URL objetivo, añadiendo esquema si falta."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            normalized_url = f"https://{url}"
            logger.debug(f"Esquema añadido: {normalized_url}")
        else:
            normalized_url = url
        parsed = urlparse(normalized_url)
        if not parsed.netloc:
            logger.error(f"URL inválida: {url} - No se detectó dominio válido")
            return ""
        logger.debug(f"URL validada: {normalized_url}")
        return normalized_url
    except Exception as e:
        logger.error(f"Error validando URL {url}: {e}")
        return ""

def validate_depth(depth: int) -> bool:
    """Valida que la profundidad de rastreo esté dentro de los límites permitidos."""
    if MIN_DEPTH <= depth <= MAX_DEPTH:
        logger.debug(f"Profundidad validada: {depth}")
        return True
    logger.error(f"Profundidad {depth} fuera de límites ({MIN_DEPTH}-{MAX_DEPTH})")
    return False

async def run_scan(crawler: SmartCrawler, detector: SmartDetector, attack_engine: AttackEngine, report_generator: ReportGenerator, save_screenshots: bool = False, save_responses: bool = False, output_format: str = 'txt'):
    """Ejecuta el escaneo completo."""
    try:
        logger.info(f"Iniciando escaneo en {crawler.base_url}")
        await crawler.start_crawl(crawler.base_url)
        logger.debug(f"URLs visitadas: {len(crawler.visited_urls)}")
        
        # Usar la página de SmartCrawler para análisis dinámico
        if crawler.page:
            for url in crawler.visited_urls:
                try:
                    async with asyncio.timeout(60):
                        logger.debug(f"Procesando URL: {url}")
                        # Navegar a la URL para análisis dinámico
                        await crawler.page.goto(url, wait_until="domcontentloaded", timeout=30000)
                        js_findings = await detector.analyze_js(await crawler.page.content())
                        if js_findings:
                            report_generator.add_findings("javascript_analysis", js_findings)
                        dynamic_findings = await detector.analyze_dynamic_content(crawler.page)
                        if dynamic_findings:
                            report_generator.add_findings("dynamic_analysis", dynamic_findings)
                        if attack_engine.interactsh_url:
                            vuln_findings = await attack_engine.test_vulnerability(url)
                            if vuln_findings:
                                report_generator.add_findings("vulnerability_scan", vuln_findings)
                        if save_screenshots:
                            await crawler.save_screenshot(url)
                        if save_responses:
                            await crawler.save_response(url)
                except asyncio.TimeoutError:
                    logger.error(f"Timeout procesando URL {url}")
                except Exception as e:
                    logger.error(f"Error procesando URL {url}: {e}")
        else:
            logger.warning("No se pudo acceder a la página de SmartCrawler para análisis dinámico")

        filename = f"report_final_{urlparse(crawler.base_url).netloc}"
        logger.debug(f"Generando reporte: {filename}")
        await report_generator.generate_report(filename)
    except asyncio.CancelledError:
        logger.info("Escaneo interrumpido por el usuario")
        await report_generator.generate_report(f"report_partial_{urlparse(crawler.base_url).netloc}")
    except Exception as e:
        logger.error(f"Error durante el escaneo: {e}")
        await report_generator.generate_report(f"report_error_{urlparse(crawler.base_url).netloc}")
        raise

async def shutdown(signal: signal.Signals, loop: asyncio.AbstractEventLoop, console: ConsoleManager, attack_engine: AttackEngine):
    """Cierra todas las tareas y recursos al recibir una señal."""
    console.print_warning(f"Recibida señal {signal.name}. Cerrando...")
    logger.info(f"Cerrando por señal: {signal.name}")
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await attack_engine.close_client()
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()

def main():
    """Función principal para ejecutar el escáner de vulnerabilidades web."""
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
    parser.add_argument('--force', '-f', action='store_true', help='Force analysis of excluded domains')
    parser.add_argument('-o', '--output', choices=['txt', 'json', 'md'], default='txt', help='Output format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('-u', '--update', action='store_true', help='Update from GitHub')

    args = parser.parse_args()
    logger.debug(f"Argumentos recibidos: {vars(args)}")

    if args.update:
        sys.exit(0 if update_tool() else 1)

    if not args.url:
        logger.error("No se proporcionó URL")
        parser.print_help()
        sys.exit(1)

    normalized_url = validate_target_url(args.url)
    if not normalized_url:
        logger.error(f"URL inválida: {args.url}")
        parser.print_help()
        sys.exit(1)

    if not validate_depth(args.depth):
        logger.error(f"Profundidad inválida: {args.depth}")
        parser.print_help()
        sys.exit(1)

    console = ConsoleManager(verbose=args.verbose)
    display_banner(console)
    domain_dir = create_domain_directory(normalized_url)
    setup_logging(domain_dir, args.verbose)

    try:
        logger.debug("Instanciando componentes...")
        report_generator = ReportGenerator(console, domain_dir=domain_dir, report_format=args.output)
        crawler = SmartCrawler(
            base_url=normalized_url,
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
        detector = SmartDetector(console)
        attack_engine = AttackEngine(console, detector, args.interactsh_url)
    except Exception as e:
        logger.error(f"Error al instanciar componentes: {e}")
        console.print_error(f"Fatal error al inicializar: {e}", fatal=True)
        sys.exit(1)

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(s, loop, console, attack_engine)))

    try:
        logger.debug("Ejecutando escaneo...")
        loop.run_until_complete(run_scan(crawler, detector, attack_engine, report_generator, args.screenshots, args.responses, args.output))
    except KeyboardInterrupt:
        logger.debug("Interrupción por usuario")
    except Exception as e:
        logger.error(f"Error en ejecución del escaneo: {e}")
        console.print_error(f"Fatal error durante el escaneo: {e}", fatal=True)
        sys.exit(1)
    finally:
        logger.debug("Cerrando recursos...")
        loop.run_until_complete(attack_engine.close_client())
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        logger.info("Programa finalizado")

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("Crawl2Bounty requires Python 3.7 or higher.", file=sys.stderr)
        sys.exit(1)
    main()

