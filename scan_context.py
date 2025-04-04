from typing import Dict, List, Any, Optional, Set

class ScanContext:
    def __init__(self, target: str):
        self.target = target
        self.urls_with_params: Dict[str, Dict[str, List[str]]] = {}  # URL -> {method: [params]}
        self.forms: List[Dict] = []  # Lista de formularios encontrados
        self.js_findings: List[Dict] = []  # Hallazgos de JS (credenciales, sinks, etc.)
        self.endpoints: Set[str] = set()  # Endpoints descubiertos
        self.sensitive_params: Set[str] = set()  # Parámetros potencialmente sensibles

    def add_url_params(self, url: str, method: str, params: Dict[str, str]):
        if url not in self.urls_with_params:
            self.urls_with_params[url] = {}
        if method not in self.urls_with_params[url]:
            self.urls_with_params[url][method] = []
        self.urls_with_params[url][method].extend(params.keys())
        self.sensitive_params.update(params.keys())
        self.endpoints.add(url)

    def add_form(self, form_data: Dict):
        self.forms.append(form_data)

    def add_js_finding(self, finding: Dict):
        self.js_findings.append(finding)
        if "parameter" in finding:
            self.sensitive_params.add(finding["parameter"])

    def get_sensitive_params(self) -> Set[str]:
        return self.sensitive_params
