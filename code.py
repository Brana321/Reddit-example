#!/usr/bin/env python3
import argparse
import configparser
import logging
from pathlib import Path
import sys
import json

ROOT = Path(__file__).parent.resolve()
SHARE_FOLDER = ROOT / "inventario_share"
RESULTS_FOLDER = SHARE_FOLDER / "resultados"
PS_TEMPLATE = ROOT / "recopilar.template.ps1"
CONFIG_TEMPLATE = ROOT / "inventario_config.template.ini"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def load_config(path: Path):
    cfg = configparser.ConfigParser()
    if not path.exists():
        logging.warning("No existe fichero de configuración. Usa la plantilla inventario_config.template.ini como guía.")
        return None
    cfg.read(path, encoding="utf-8")
    return cfg

def ensure_folders():
    SHARE_FOLDER.mkdir(parents=True, exist_ok=True)
    RESULTS_FOLDER.mkdir(parents=True, exist_ok=True)

def read_ps_template():
    if not PS_TEMPLATE.exists():
        logging.warning(f"No se encontró {PS_TEMPLATE.name}. Crea tu script de recolección localmente y mantenlo fuera del repo.")
        return None
    return PS_TEMPLATE.read_text(encoding="utf-8")

def sanitize_output(record: dict):
    sanitized = dict(record)
    for key in list(sanitized.keys()):
        if "password" in key.lower() or "pwd" in key.lower() or "secret" in key.lower() or "token" in key.lower():
            sanitized.pop(key, None)
    return sanitized

def save_result(host_identifier: str, data: dict):
    sanitized = sanitize_output(data)
    out_file = RESULTS_FOLDER / f"{host_identifier}_summary.json"
    out_file.write_text(json.dumps(sanitized, indent=2, ensure_ascii=False), encoding="utf-8")
    logging.info(f"Resultado (sanitizado) guardado en: {out_file}")

def execute_remote_collection_stub(target_ip: str, cfg, dry_run=True):
    logging.info("=== EJECUTANDO STUB DE RECOLECCIÓN REMOTA ===")
    logging.info(f"Target: {target_ip}")
    logging.info(f"Modo dry_run: {dry_run}")
    if dry_run:
        logging.info("Dry-run activo: no se realizará ninguna conexión remota.")
        fake = {
            "host": target_ip,
            "os": "Windows (simulado)",
            "collected_at": "2025-10-22T00:00:00Z",
            "notes": "Resultado simulado (dry-run)"
        }
        save_result(target_ip.replace(":", "_"), fake)
        return fake
    else:
        raise NotImplementedError("Implementa la ejecución remota en tu entorno privado con medidas de seguridad.")

def main():
    parser = argparse.ArgumentParser(description="Inventory Orchestrator (safe, public-friendly version)")
    parser.add_argument("--config", type=str, default=str(CONFIG_TEMPLATE), help="Ruta al fichero de config (no subirlo público)")
    parser.add_argument("--target", type=str, help="IP o hostname del objetivo a simular/recoger")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Por defecto activo: no realizará acciones remotas.")
    parser.add_argument("--no-dry-run", dest="dry_run", action="store_false", help="Permite ejecutar (solo si sabes lo que haces).")
    args = parser.parse_args()

    ensure_folders()

    cfg = load_config(Path(args.config))
    ps_template = read_ps_template()
    if ps_template:
        logging.info(f"Plantilla PowerShell encontrada ({PS_TEMPLATE.name}). Asegúrate de mantenerla fuera del repo si contiene datos sensibles.")

    if not args.target:
        logging.error("No has indicado ningún objetivo. Usa --target <IP> para simular una recolección.")
        parser.print_help()
        sys.exit(1)

    result = execute_remote_collection_stub(args.target, cfg, dry_run=args.dry_run)

    logging.info("Operación completada (modo seguro). Revisa el directorio 'inventario_share/resultados' para los resúmenes.")


if __name__ == "__main__":
    main()