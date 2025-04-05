from site_crawler import SmartCrawler
from smart_detector import SmartDetector
from attack_engine import AttackEngine
from report_generator import ReportGenerator
import asyncio
import logging
from urllib.parse import urlparse

async def run_scan(crawler: SmartCrawler, detector: SmartDetector, attack_engine: AttackEngine, report_generator: ReportGenerator, save_screenshots: bool = False, save_responses: bool = False, output_format: str = 'txt'):
    """Ejecuta el escaneo completo."""
    try:
        logger.info(f"Iniciando escaneo en {crawler.base_url}")
        await crawler.start_crawl(crawler.base_url)
        logger.debug(f"URLs visitadas: {len(crawler.visited_urls)}")
        
        # Forzar el uso de AttackEngine
        logger.info("Iniciando pruebas de vulnerabilidades con AttackEngine")
        for url in crawler.visited_urls:
            logger.debug(f"Probando vulnerabilidades en {url}")
            await attack_engine.test_vulnerability(url, method="GET")  # Prueba básica en la URL
            # Si SmartCrawler recolecta parámetros o formularios, agrégalos aquí
            if hasattr(crawler, 'forms') and crawler.forms.get(url):
                for form in crawler.forms[url]:
                    await attack_engine.test_vulnerability(url, method=form.get('method', 'GET'), data=form.get('data', {}))
        
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
        await report_generator.generate_report(f"report_{urlparse(crawler.base_url).netloc}")
        
    except asyncio.CancelledError:
        logging.info("Escaneo interrumpido por el usuario")
        # Asegurar que se genere un reporte parcial
        await report_generator.generate_report("reporte_parcial")
    except Exception as e:
        logging.error(f"Error durante el escaneo: {e}")
        # Asegurar que se genere un reporte parcial
        await report_generator.generate_report("reporte_error")
        raise

