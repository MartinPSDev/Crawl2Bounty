import logging
from console_manager import ConsoleManager
from smart_detector import SmartDetector
from attack_engine import AttackEngine
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import json
from datetime import datetime
import os
import time
from collections import defaultdict
import threading
import subprocess
import asyncio
import signal
import sys
import aiofiles

# Configurar logger global
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Configurar un handler para el logger
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Asegúrate de que `console` esté definido
console = ConsoleManager(verbose=True)

class ReportGenerator:
    def __init__(self, console_manager: ConsoleManager, output_file: str = None, domain_dir: str = None, report_format: str = "txt"):
        self.console = console_manager
        self.findings = defaultdict(list)
        self.metadata = {
            "scan_start": datetime.now().isoformat(),
            "scan_start_time": time.time(),
            "scan_end": None,
            "scan_end_time": None,
            "scan_duration_seconds": None,
            "total_urls": 0,
            "total_findings": 0,
            "vulnerability_types": set(),
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        self.domain_dir = domain_dir or 'reports'
        self.report_format = report_format  # Formato del reporte
        os.makedirs(self.domain_dir, exist_ok=True)

    def log_realtime_event(self, message: str, *args):
        """Registra un evento en tiempo real."""
        formatted_message = message.format(*args)
        self.console.print_info(formatted_message)
        logger.info(formatted_message)

    def _generate_summary(self):
        """Genera un resumen del escaneo."""
        return {
            "total_urls": self.metadata["total_urls"],
            "total_findings": self.metadata["total_findings"],
            "vulnerability_types": list(self.metadata["vulnerability_types"]),  # Convertir set a lista
            "severity_counts": self.metadata["severity_counts"]
        }

    async def generate_report(self, filename_prefix: str):
        """Genera el reporte en el formato especificado."""
        try:
            report_path = os.path.join(self.domain_dir, f"{filename_prefix}.{self.report_format}")
            
            if self.report_format == "json":
                await self._generate_json_report(report_path)
            elif self.report_format == "txt":
                await self._generate_txt_report(report_path)
            elif self.report_format == "md":
                await self._generate_markdown_report(report_path)
            else:
                raise ValueError(f"Formato no soportado: {self.report_format}")
            
            self.console.print_success(f"Reporte guardado en: {report_path}")
        except Exception as e:
            self.console.print_error(f"Error al generar el reporte: {e}")
            logger.error(f"Error al generar el reporte: {e}", exc_info=True)

    async def _generate_json_report(self, report_path: str):
        """Genera el reporte en formato JSON."""
        async with aiofiles.open(report_path, 'w') as report_file:
            await report_file.write(json.dumps({
                "metadata": {
                    **self.metadata,
                    "vulnerability_types": list(self.metadata["vulnerability_types"])  # Convertir set a lista
                },
                "summary": self._generate_summary(),
                "findings": self.findings
            }, indent=4))

    async def _generate_txt_report(self, report_path: str):
        """Genera el reporte en formato TXT."""
        async with aiofiles.open(report_path, 'w') as report_file:
            await report_file.write("=== Resumen del Escaneo ===\n")
            await report_file.write(f"Inicio del escaneo: {self.metadata['scan_start']}\n")
            await report_file.write(f"Fin del escaneo: {self.metadata['scan_end']}\n")
            await report_file.write(f"Duración: {self.metadata['scan_duration_seconds']} segundos\n")
            await report_file.write(f"Total de URLs escaneadas: {self.metadata['total_urls']}\n")
            await report_file.write(f"Total de hallazgos: {self.metadata['total_findings']}\n")
            await report_file.write("\n=== Hallazgos ===\n")
            for category, findings in self.findings.items():
                await report_file.write(f"\n{category}:\n")
                for finding in findings:
                    await report_file.write(f"- {finding}\n")

    async def _generate_markdown_report(self, report_path: str):
        """Genera el reporte en formato Markdown."""
        async with aiofiles.open(report_path, 'w') as report_file:
            await report_file.write("# Resumen del Escaneo\n")
            await report_file.write(f"- **Inicio del escaneo:** {self.metadata['scan_start']}\n")
            await report_file.write(f"- **Fin del escaneo:** {self.metadata['scan_end']}\n")
            await report_file.write(f"- **Duración:** {self.metadata['scan_duration_seconds']} segundos\n")
            await report_file.write(f"- **Total de URLs escaneadas:** {self.metadata['total_urls']}\n")
            await report_file.write(f"- **Total de hallazgos:** {self.metadata['total_findings']}\n")
            await report_file.write("\n## Hallazgos\n")
            for category, findings in self.findings.items():
                await report_file.write(f"\n### {category}\n")
                for finding in findings:
                    await report_file.write(f"- {finding}\n")

async def run_scan(crawler, detector, attack_engine, report_generator, save_screenshots=False, save_responses=False):
    from site_crawler import SmartCrawler  # Importación dentro de la función
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

async def shutdown(sig, loop, console):
    """Maneja el cierre del programa de forma elegante."""
    console.print_warning(f"\nReceived exit signal {sig.name}...")
    console.print_info("Attempting graceful shutdown, cancelling tasks...")

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if not tasks:
        console.print_info("No pending tasks to cancel.")
        return

    # Cancel all tasks
    for task in tasks:
        task.cancel()

    try:
        # Wait for tasks to finish cancelling with a timeout
        await asyncio.wait(tasks, timeout=5)
    except asyncio.CancelledError:
        console.print_warning("Some tasks did not finish in time.")

    # Forcefully close the loop if tasks are still pending
    pending_tasks = [t for t in asyncio.all_tasks() if not t.done()]
    if pending_tasks:
        console.print_warning(f"Forcing shutdown. {len(pending_tasks)} tasks are still pending.")
        for task in pending_tasks:
            task.cancel()
        loop.stop()

    console.print_info("Shutdown complete.")

async def async_main(output_file: str, domain_dir: str, verbose: bool):
    # Inicializa `console`
    console = ConsoleManager(verbose=verbose)

    # Inicializa `ReportGenerator`
    report_generator = ReportGenerator(
        console_manager=console,
        output_file=output_file,
        domain_dir=domain_dir
    )

    # Aquí puedes continuar con la lógica de escaneo
    console.print_info("Iniciando el escaneo...")
    report_generator.log_realtime_event("Evento registrado correctamente")

def some_function_that_returns_an_object():
    """Devuelve un objeto simulado con un atributo 'content'."""
    class MockObject:
        content = "Este es el contenido del objeto"
    return MockObject()

# Uso del objeto
obj = some_function_that_returns_an_object()

# Verifica que el objeto tenga el atributo `content` antes de acceder a él
if hasattr(obj, 'content'):
    content = obj.content
else:
    logger.error("El objeto no tiene el atributo 'content'")

try:
    # Define valores predeterminados para los argumentos
    output_file = "default_report"
    domain_dir = "reports"
    verbose = True

    # Pasa los argumentos a async_main
    asyncio.run(async_main(output_file=output_file, domain_dir=domain_dir, verbose=verbose))
except KeyboardInterrupt:
    console.print_warning("\nKeyboardInterrupt caught (might be during setup/shutdown).")
except Exception as e:
    logger.error(f"Unhandled error in main execution: {e}", exc_info=True)
    console.print_error(f"Fatal error: {e}")
    sys.exit(1)
