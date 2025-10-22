#!/usr/bin/env python3
"""
inventario_red_compartido.py - VERSION CON CARPETA COMPARTIDA

Script que crea carpeta compartida en red, distribuye script PowerShell,
y recopila resultados de todos los equipos.

Compilar:
  pyinstaller --onefile --noconsole --name InventarioRed inventario_red_compartido.py

Uso:
  InventarioRed.exe
"""

import ipaddress
import socket
import json
import csv
import sys
import os
import threading
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import configparser
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import shutil

# ---------- Configuración ----------
VERSION = "4.0.0-SHARED"
CONFIG_FILE = "inventario_config.ini"
CONCURRENCY = 20
TCP_TIMEOUT = 2.0
SCAN_TIMEOUT = 1.0

# Carpeta compartida
SHARE_NAME = "InventarioRed"
SHARE_FOLDER = Path("inventario_share")
RESULTS_FOLDER = SHARE_FOLDER / "resultados"
SCRIPT_FILE = SHARE_FOLDER / "recopilar.ps1"
# -----------------------------------

# (Reemplaza la variable PS_SCRIPT_CONTENT por este contenido)
PS_SCRIPT_CONTENT = r'''
param(
    [string]$SharePath = "",
    [string]$MyIP = ""
)

function SafeWriteJson {
    param($obj, $filename)
    try {
        $json = $obj | ConvertTo-Json -Depth 6 -Compress
        if ($SharePath) {
            try {
                $shareOut = Join-Path $SharePath "resultados\$filename"
                $json | Out-File -FilePath $shareOut -Encoding UTF8 -Force
                Write-Host "WROTE_SHARE:$shareOut"
            } catch {
                Write-Host "WARN: No se pudo escribir en share: $($_.Exception.Message)"
            }
        }
        
        try {
            $localOut = Join-Path $env:TEMP $filename
            $json | Out-File -FilePath $localOut -Encoding UTF8 -Force
            Write-Host "WROTE_LOCAL:$localOut"
        } catch {
            Write-Host "ERROR: No se pudo escribir local: $($_.Exception.Message)"
        }
        return $true
    } catch {
        return $false
    }
}

try {
 
    $result = @{
        Success = $true
        Computer = $env:COMPUTERNAME
        Timestamp = (Get-Date).ToString('o')
        CollectionMethod = 'Local'
        
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $hostname = $env:COMPUTERNAME
    $filename = "${hostname}_${timestamp}.json"

    SafeWriteJson -obj $result -filename $filename

} catch {
    $errorResult = @{
        Success = $false
        Computer = $env:COMPUTERNAME
        Error = $_.Exception.Message
        Timestamp = (Get-Date).ToString('o')
    }
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $filename = "${env:COMPUTERNAME}_ERROR_${timestamp}.json"
   
    SafeWriteJson -obj $errorResult -filename $filename
}
'''

class ConfigManager:
    
    def __init__(self, config_file=CONFIG_FILE):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load()
    
    def load(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file, encoding='utf-8')
        else:
            self.create_default()
    
    def create_default(self):
        self.config['Network'] = {
            'default_range': '192.168.1.0/24',
            'concurrency': '20',
            'timeout': '2.0'
        }
        self.config['Credentials'] = {
            'username': 'x',
            'password': ''
        }
        self.config['Share'] = {
            'auto_create': 'yes',
            'share_name': SHARE_NAME
        }
        self.config['Output'] = {
            'directory': '.',
            'generate_html': 'yes',
            'generate_csv': 'yes',
            'generate_json': 'yes'
        }
        self.save()
    
    def save(self):
        with open(self.config_file, 'w', encoding='utf-8') as f:
            self.config.write(f)
    
    def get(self, section, key, fallback=''):
        return self.config.get(section, key, fallback=fallback)
    
    def set(self, section, key, value):
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = str(value)


def get_local_ip():
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"


def setup_shared_folder():
    """Crea carpeta compartida en Windows"""
    try:
        # Crear carpetas
        SHARE_FOLDER.mkdir(exist_ok=True)
        RESULTS_FOLDER.mkdir(exist_ok=True)
        
        # Crear script PowerShell
        with open(SCRIPT_FILE, 'w', encoding='utf-8') as f:
            f.write(PS_SCRIPT_CONTENT)
        
        # Compartir carpeta en red (Windows)
        if sys.platform == 'win32':
            # Eliminar share existente si existe
            subprocess.run(
                ['net', 'share', SHARE_NAME, '/delete'],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Crear nuevo share con permisos completos
            grant_user = 'Everyone'
            if os.system('net localgroup "Todos" >nul 2>&1') == 0:
                grant_user = 'Todos'
            result = subprocess.run(
               ['net', 'share', SHARE_NAME + '=' + str(SHARE_FOLDER.absolute()), '/GRANT:Usuarios,FULL'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                return True, f"Carpeta compartida creada: \\\\{get_local_ip()}\\{SHARE_NAME}"
            else:
                return False, f"Error al compartir: {result.stderr}"
        else:
            return False, "Sistema no Windows, compartir manualmente"
    
    except Exception as e:
        return False, f"Error: {str(e)}"


def cleanup_shared_folder():
    """Elimina carpeta compartida"""
    try:
        if sys.platform == 'win32':
            subprocess.run(
                ['net', 'share', SHARE_NAME, '/delete'],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
    except:
        pass


def parse_cidr_range(cidr_input: str):
    """Parsea rango CIDR"""
    try:
        cidr_input = cidr_input.strip()
        if '/' in cidr_input:
            network = ipaddress.ip_network(cidr_input, strict=False)
            return [str(ip) for ip in network.hosts()]
        elif ' ' in cidr_input:
            addr, mask = cidr_input.split(None, 1)
            network = ipaddress.ip_network(f'{addr}/{mask}', strict=False)
            return [str(ip) for ip in network.hosts()]
        else:
            return [cidr_input.strip()]
    except Exception as e:
        raise ValueError(f"Formato inválido: {e}")


def tcp_check(ip: str, port: int, timeout=TCP_TIMEOUT) -> bool:
    """Verifica puerto TCP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except:
        return False


def detect_device(ip: str) -> dict:
    """Detecta tipo de dispositivo"""
    ports = {135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP', 5900: 'VNC'}
    
    open_ports = {}
    for port, service in ports.items():
        if tcp_check(ip, port, timeout=SCAN_TIMEOUT):
            open_ports[port] = service
    
    device_info = {
        'ip': ip,
        'alive': len(open_ports) > 0,
        'open_ports': open_ports,
        'type': 'unknown'
    }
    
    if 445 in open_ports or 3389 in open_ports or 135 in open_ports:
        device_info['type'] = 'windows'
    
    return device_info


def pull_files_via_admin_share(ip: str, username: str, password: str, local_dest: Path, pattern: str = "*Inventario*"):

   
    copied = []
    try:
        # crear destino local
        local_dest.mkdir(parents=True, exist_ok=True)
        # Mapear admin share
        net_use_cmd = ['net', 'use', f'\\\\{ip}\\C$', password, '/user:' + username]
        subprocess.run(net_use_cmd, capture_output=True, text=True, timeout=30)
        # Enumerar y copiar
        remote_temp = f"\\\\{ip}\\C$\\Windows\\Temp"
        # usar dir para listar (más compatible)
        proc = subprocess.run(['cmd', '/c', f'dir "{remote_temp}\\{pattern}" /b'], capture_output=True, text=True, timeout=30)
        if proc.returncode == 0 and proc.stdout.strip():
            files = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            for fname in files:
                remote_file = os.path.join(remote_temp, fname)
                local_file = local_dest / f"{ip}_{fname}"
                try:
                    cp = subprocess.run(['cmd', '/c', f'copy "{remote_file}" "{local_file}"'], capture_output=True, text=True, timeout=30)
                    if cp.returncode == 0:
                        copied.append(str(local_file))
                except Exception:
                    pass
        # Desconectar
        subprocess.run(['net', 'use', f'\\\\{ip}\\C$', '/delete'], capture_output=True, text=True, timeout=10)
    except Exception as e:
        # intentar limpiar si algo quedó
        try:
            subprocess.run(['net', 'use', f'\\\\{ip}\\C$', '/delete'], capture_output=True, text=True, timeout=10)
        except:
            pass
    return copied


# --- reemplaza tu execute_remote_script por esta versión todo-en-uno ---

def execute_remote_script(ip: str, username: str, password: str, share_path: str, wait_secs: int = 6) -> dict:
    """
    Lanza el script remoto (intenta PsExec, WMI, PSRemoting), espera unos segundos
    y luego intenta recoger resultados primero del share UNC y, si no, desde C$ (Windows\\Temp).
    Devuelve un dict con detalles del método usado y archivos recuperados.
    """

    import os, subprocess, time, datetime
    from pathlib import Path

    result = {
        'ip': ip,
        'success': False,
        'error': None,
        'method': None,
        'attempts': [],
        'share_files_found': [],
        'pulled_files': [],
        'debug_file': None,
    }

    # -------- Helpers --------

    def now_utc_ts():
        return datetime.datetime.utcnow().timestamp()

    def list_recent_files(folder: Path, pattern: str = "*.json", max_age_seconds: int = 900):
        """Lista ficheros recientes en 'folder' con 'pattern'. Devuelve lista de Path."""
        if not folder.exists():
            return []
        cutoff = now_utc_ts() - max_age_seconds
        found = []
        for p in folder.glob(pattern):
            try:
                # mtime en epoch del sistema local
                if p.stat().st_mtime >= cutoff:
                    found.append(p)
            except Exception:
                pass
        # ordenar por mtime desc
        found.sort(key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)
        return found

    def collect_from_share_for_host(share_path_str: str, max_age_seconds: int = 900):
        """
        Mira \\MI_IP\\InventarioRed\\resultados y devuelve JSONs recientes.
        No filtra por hostname concreto porque no lo conocemos antes de ejecutar.
        """
        res_dir = Path(share_path_str) / "resultados"
        try:
            files = list_recent_files(res_dir, "*.json", max_age_seconds=max_age_seconds)
            return [str(f.resolve()) for f in files]
        except Exception:
            return []

    def try_pull_from_cshare(ip_str: str, user: str, pwd: str, local_dir: Path, max_age_seconds: int = 1800):
        """
        Monta \\ip\\C$, lista Windows\\Temp para *.json recientes, los copia a local_dir.
        También intenta copiar inventory_debug.txt si existe.
        """
        local_dir.mkdir(parents=True, exist_ok=True)
        copied = []
        debug_copied = None
        try:
            # Mapear C$
            subprocess.run(['net', 'use', f'\\\\{ip_str}\\C$', pwd, '/user:' + user],
                           capture_output=True, text=True, timeout=30)

            remote_temp = f'\\\\{ip_str}\\C$\\Windows\\Temp'
            # Listar TODOS los JSON y filtrar por edad con 'dir /T:W' si se quiere,
            # aquí listamos y luego copiamos intentando; es simple y robusto:
            proc = subprocess.run(['cmd', '/c', f'dir "{remote_temp}\\*.json" /b'],
                                  capture_output=True, text=True, timeout=20)

            candidate_files = []
            if proc.returncode == 0 and proc.stdout.strip():
                candidate_files = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]

            # Copiar sólo los "recién" modificados (no tenemos mtime remota fiable desde cmd /b),
            # así que copiamos, y luego en local filtramos por edad
            for fname in candidate_files:
                remote_file = f'{remote_temp}\\{fname}'
                local_file = local_dir / f'{ip_str}_{fname}'
                cp = subprocess.run(['cmd', '/c', f'copy /Y "{remote_file}" "{local_file}"'],
                                    capture_output=True, text=True, timeout=20)
                if cp.returncode == 0 and local_file.exists():
                    # Filtrar por edad en local
                    age_ok = (time.time() - local_file.stat().st_mtime) <= max_age_seconds
                    if age_ok:
                        copied.append(str(local_file.resolve()))
                    else:
                        # Si es viejo, lo borramos para no confundir
                        try:
                            local_file.unlink(missing_ok=True)
                        except Exception:
                            pass

            # Intentar traer el log de debug si existe
            dbg_local = local_dir / f'{ip_str}_inventory_debug.txt'
            cp_dbg = subprocess.run(['cmd', '/c', f'copy /Y "{remote_temp}\\inventory_debug.txt" "{dbg_local}"'],
                                    capture_output=True, text=True, timeout=10)
            if cp_dbg.returncode == 0 and dbg_local.exists():
                debug_copied = str(dbg_local.resolve())

        except Exception as e:
            # no interrumpimos el flujo por errores aquí
            pass
        finally:
            # Desconectar
            try:
                subprocess.run(['net', 'use', f'\\\\{ip_str}\\C$', '/delete'],
                               capture_output=True, text=True, timeout=10)
            except Exception:
                pass

        return copied, debug_copied

    # -------- Detección de host y puertos (usa tu propia función si la tienes) --------
    try:
        device = detect_device(ip)  # <- asume que ya existe en tu código
    except NameError:
        device = {'alive': True, 'type': 'windows', 'open_ports': {445: True, 135: True}}  # fallback
    result['device_type'] = device.get('type', 'unknown')
    result['open_ports'] = device.get('open_ports', {})

    if not device.get('alive'):
        result['error'] = 'Host no responde'
        return result
    if device.get('type') != 'windows':
        result['error'] = f"No es Windows: {device.get('type')}"
        return result

    # Ruta UNC al PS en el share (tu script lo deja ahí)
    remote_script_path = f"{share_path}\\recopilar.ps1"

    # -------- Métodos de ejecución --------

    def method_psexec():
        try:
            # Usa psexec incluido en el bundle (si tienes helper resource_path, úsalo aquí)
            psexec_exe = 'psexec64.exe'  # reemplaza por resource_path('psexec64.exe') si lo tienes
            cmd = [psexec_exe, f'\\\\{ip}', '-accepteula', '-nobanner', '-h']
            if username:
                cmd.extend(['-u', username])
            if password:
                cmd.extend(['-p', password])
            cmd.extend([
                'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', remote_script_path, '-SharePath', share_path
            ])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0:
                return True, (proc.stdout.strip() or "PsExec OK")
            else:
                return False, (proc.stderr.strip() or f"PsExec returncode={proc.returncode}")
        except FileNotFoundError:
            return False, "PsExec no encontrado"
        except subprocess.TimeoutExpired:
            return False, "PsExec timeout"
        except Exception as e:
            return False, f"PsExec error: {str(e)[:200]}"

    def method_wmi():
        try:
            ps_cmd = f"""
$secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{username}', $secure)
Invoke-WmiMethod -ComputerName {ip} -Credential $cred -Class Win32_Process -Name Create -ArgumentList "powershell.exe -NoProfile -ExecutionPolicy Bypass -File {remote_script_path} -SharePath {share_path}"
"""
            proc = subprocess.run(['powershell.exe', '-NoProfile', '-Command', ps_cmd],
                                  capture_output=True, text=True, timeout=90)
            if proc.returncode == 0:
                return True, "WMI ejecutado"
            return False, proc.stderr.strip() or "WMI error"
        except subprocess.TimeoutExpired:
            return False, "WMI timeout"
        except Exception as e:
            return False, f"WMI error: {str(e)[:200]}"

    def method_psremoting():
        try:
            ps_cmd = f"""
$secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{username}', $secure)
$session = New-PSSession -ComputerName {ip} -Credential $cred -ErrorAction Stop
Invoke-Command -Session $session -ScriptBlock {{
    & '{remote_script_path}' -SharePath '{share_path}'
}}
Remove-PSSession $session
"""
            proc = subprocess.run(['powershell.exe', '-NoProfile', '-Command', ps_cmd],
                                  capture_output=True, text=True, timeout=90)
            if proc.returncode == 0:
                return True, "PSRemoting ejecutado"
            return False, proc.stderr.strip() or "PSRemoting error"
        except subprocess.TimeoutExpired:
            return False, "PSRemoting timeout"
        except Exception as e:
            return False, f"PSRemoting error: {str(e)[:200]}"

    methods = []
    if 445 in device['open_ports']:
        methods.append(('PsExec', method_psexec))
    if 135 in device['open_ports']:
        methods.append(('WMI', method_wmi))
    # Siempre dejamos PSRemoting como último intento
    methods.append(('PSRemoting', method_psremoting))

    # -------- Ejecutar, esperar y recoger --------
    for name, func in methods:
        ok = False
        msg = ""
        try:
            ok, msg = func()
        except Exception as e:
            msg = f"{name} lanzó excepción: {str(e)[:200]}"
            ok = False

        result['attempts'].append({name: msg})

        if ok:
            result['method'] = name
            # Espera breve para que el .ps1 escriba ficheros
            time.sleep(max(2, min(wait_secs, 20)))

            # 1) Buscar en UNC (share resultados)
            share_files = collect_from_share_for_host(share_path, max_age_seconds=900)
            result['share_files_found'] = share_files

            # Si encuentra algo en el share, ya lo damos por bueno
            if share_files:
                result['success'] = True
                return result

            # 2) Intentar Pull desde C$
            local_collect_dir = Path('collected_from_C$')
            pulled, dbg = try_pull_from_cshare(ip, username, password, local_collect_dir, max_age_seconds=1800)
            result['pulled_files'] = pulled
            result['debug_file'] = dbg

            if pulled:
                result['success'] = True
                return result
            else:
                # No hay nada aún; seguimos con otro método por si acaso
                result['error'] = f"{name} ejecutado pero no se encontraron resultados todavía."
        else:
            # probar siguiente método
            result['error'] = msg

    # Si llegamos aquí, todos fallaron o no hubo ficheros
    return result

def collect_results_from_share(timeout=120):
    """Recopila resultados JSON de la carpeta compartida"""
    results = []
    start_time = time.time()
    processed_files = set()
    
    while (time.time() - start_time) < timeout:
        try:
            if RESULTS_FOLDER.exists():
                for json_file in RESULTS_FOLDER.glob("*.json"):
                    if json_file.name not in processed_files:
                        try:
                            with open(json_file, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                results.append({
                                    'file': json_file.name,
                                    'data': data,
                                    'success': data.get('Success', True)
                                })
                                processed_files.add(json_file.name)
                        except Exception as e:
                            print(f"Error leyendo {json_file}: {e}")
            
            time.sleep(2)  # Esperar 2 segundos antes de volver a verificar
        
        except Exception as e:
            print(f"Error recopilando resultados: {e}")
    
    return results


def flatten_to_csv(data: dict, ip: str = '') -> dict:
    """Aplana JSON para CSV"""
    row = {}
    
    if not data:
        return row
    
    row['ComputerName'] = data.get('Computer', '')
    row['Domain'] = data.get('Domain', '')
    row['IP'] = ip or 'N/A'
    
    os_info = data.get('OS', {})
    row['OS'] = os_info.get('Name', '')
    row['OS_Version'] = os_info.get('Version', '')
    row['OS_Build'] = os_info.get('Build', '')
    
    cpu = data.get('CPU', {})
    row['CPU'] = cpu.get('Name', '')
    row['CPU_Cores'] = cpu.get('Cores', '')
    
    mem = data.get('Memory', {})
    row['Memory_GB'] = mem.get('TotalGB', '')
    
    disks = data.get('Disks', [])
    disk_summary = [f"{d.get('DeviceID','')}:{d.get('SizeGB','')}GB" for d in disks]
    row['Disks'] = '; '.join(disk_summary)
    
    nets = data.get('Network', [])
    net_summary = []
    for n in nets:
        ips = n.get('IP', [])
        if isinstance(ips, list):
            ips = ','.join(ips)
        net_summary.append(f"{n.get('Description','')}[{ips}]")
    row['Network'] = '; '.join(net_summary)
    
    programs = data.get('Programs', [])
    row['Programs_Count'] = len(programs)
    
    services = data.get('Services', [])
    row['Services_Running'] = len(services)
    
    usb = data.get('USB', [])
    row['USB_Count'] = len(usb)
    
    row['Timestamp'] = data.get('Timestamp', '')
    
    return row


def generate_html_report(results: list, output_dir: str = '.') -> Path:
    """Genera reporte HTML"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    html_file = Path(output_dir) / f'reporte_{timestamp}.html'
    
    successful = [r for r in results if r.get('success')]
    failed = [r for r in results if not r.get('success')]
    
    html_content = f'''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte Inventario</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 12px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; border-radius: 12px 12px 0 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }}
        .stat-card {{ background: white; padding: 25px; border-radius: 8px; text-align: center; border-top: 4px solid #667eea; }}
        .stat-number {{ font-size: 48px; font-weight: bold; color: #667eea; }}
        .device-card {{ background: white; border: 1px solid #eee; border-radius: 8px; padding: 20px; margin: 15px 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Reporte de Inventario</h1>
            <p>{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
        </div>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{len(successful)}</div>
                <div>Equipos Exitosos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #ffa94d;">{len(failed)}</div>
                <div>Fallos</div>
            </div>
        </div>
        <div style="padding: 20px;">
'''
    
    for r in successful:
        data = r.get('data', {})
        html_content += f'''
            <div class="device-card">
                <h3>💻 {data.get('Computer', 'N/A')}</h3>
                <p><strong>OS:</strong> {data.get('OS', {}).get('Name', 'N/A')}</p>
                <p><strong>CPU:</strong> {data.get('CPU', {}).get('Name', 'N/A')[:60]}</p>
                <p><strong>RAM:</strong> {data.get('Memory', {}).get('TotalGB', 'N/A')} GB</p>
            </div>
'''
    
    html_content += '</div></div></body></html>'
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return html_file


def save_results(results: list, config: ConfigManager, output_dir: str = '.'):
    """Guarda resultados"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    files = {}
    
    if config.get('Output', 'generate_json', 'yes') == 'yes':
        json_file = output_path / f'inventario_{timestamp}.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        files['json'] = json_file
    
    if config.get('Output', 'generate_csv', 'yes') == 'yes':
        csv_file = output_path / f'inventario_{timestamp}.csv'
        successful = [r for r in results if r.get('success') and r.get('data')]
        
        if successful:
            csv_rows = [flatten_to_csv(r['data']) for r in successful]
            if csv_rows:
                with open(csv_file, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
                    writer.writeheader()
                    writer.writerows(csv_rows)
                files['csv'] = csv_file
    
    if config.get('Output', 'generate_html', 'yes') == 'yes':
        html_file = generate_html_report(results, output_dir)
        files['html'] = html_file
    
    return files


class InventarioGUI:
    """Interfaz gráfica"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"Inventario de Red v{VERSION}")
        self.root.geometry("900x700")
        
        self.config = ConfigManager()
        self.scanning = False
        self.share_active = False
        
        self.setup_ui()
    
    def setup_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        scan_frame = ttk.Frame(notebook, padding=20)
        notebook.add(scan_frame, text='🔍 Escaneo')
        
        config_frame = ttk.Frame(notebook, padding=20)
        notebook.add(config_frame, text='⚙️ Configuración')
        
        self.setup_scan_tab(scan_frame)
        self.setup_config_tab(config_frame)
    
    def setup_scan_tab(self, parent):
        ttk.Label(parent, text="Inventario de Red - Carpeta Compartida", font=('Arial', 16, 'bold')).pack(pady=(0, 20))
        
        # Info carpeta compartida
        share_info = ttk.LabelFrame(parent, text="Carpeta Compartida", padding=15)
        share_info.pack(fill='x', pady=(0, 15))
        
        self.share_status_var = tk.StringVar(value="❌ No configurada")
        ttk.Label(share_info, textvariable=self.share_status_var, font=('Arial', 10, 'bold')).pack(anchor='w')
        
        share_btn_frame = ttk.Frame(share_info)
        share_btn_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Button(share_btn_frame, text="🔧 Crear Carpeta Compartida", command=self.create_share).pack(side='left', padx=5)
        ttk.Button(share_btn_frame, text="🗑️ Eliminar Compartida", command=self.remove_share).pack(side='left', padx=5)
        
        # Configuración escaneo
        scan_config = ttk.LabelFrame(parent, text="Configuración de Escaneo", padding=15)
        scan_config.pack(fill='x', pady=(0, 15))
        
        ttk.Label(scan_config, text="Rango de IPs:").grid(row=0, column=0, sticky='w', pady=5)
        self.ip_range_var = tk.StringVar(value=self.config.get('Network', 'default_range'))
        ttk.Entry(scan_config, textvariable=self.ip_range_var, width=40).grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(scan_config, text="Usuario Windows:").grid(row=1, column=0, sticky='w', pady=5)
        self.username_var = tk.StringVar(value=self.config.get('Credentials', 'username'))
        ttk.Entry(scan_config, textvariable=self.username_var, width=40).grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(scan_config, text="Contraseña:").grid(row=2, column=0, sticky='w', pady=5)
        self.password_var = tk.StringVar(value=self.config.get('Credentials', 'password'))
        ttk.Entry(scan_config, textvariable=self.password_var, width=40, show='*').grid(row=2, column=1, padx=10, pady=5)
        
        ttk.Label(scan_config, text="Hilos:").grid(row=3, column=0, sticky='w', pady=5)
        self.threads_var = tk.StringVar(value='20')
        ttk.Spinbox(scan_config, from_=1, to=50, textvariable=self.threads_var, width=38).grid(row=3, column=1, padx=10, pady=5)
        
        self.scan_button = ttk.Button(parent, text="🚀 Iniciar Escaneo", command=self.start_scan)
        self.scan_button.pack(pady=15)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', pady=(0, 10))
        
        self.status_var = tk.StringVar(value="Configura la carpeta compartida primero")
        status_label = ttk.Label(parent, textvariable=self.status_var, font=('Arial', 10))
        status_label.pack()
        
        log_frame = ttk.LabelFrame(parent, text="Log de Escaneo", padding=10)
        log_frame.pack(fill='both', expand=True, pady=(15, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, wrap='word', state='disabled')
        self.log_text.pack(fill='both', expand=True)
    
    def setup_config_tab(self, parent):
        net_frame = ttk.LabelFrame(parent, text="Red", padding=15)
        net_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Label(net_frame, text="Rango por defecto:").grid(row=0, column=0, sticky='w', pady=5)
        self.cfg_range_var = tk.StringVar(value=self.config.get('Network', 'default_range'))
        ttk.Entry(net_frame, textvariable=self.cfg_range_var, width=40).grid(row=0, column=1, padx=10, pady=5)
        
        cred_frame = ttk.LabelFrame(parent, text="Credenciales", padding=15)
        cred_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Label(cred_frame, text="Usuario por defecto:").grid(row=0, column=0, sticky='w', pady=5)
        self.cfg_user_var = tk.StringVar(value=self.config.get('Credentials', 'username'))
        ttk.Entry(cred_frame, textvariable=self.cfg_user_var, width=40).grid(row=0, column=1, padx=10, pady=5)
        
        output_frame = ttk.LabelFrame(parent, text="Salida", padding=15)
        output_frame.pack(fill='x', pady=(0, 15))
        
        self.cfg_gen_html_var = tk.BooleanVar(value=self.config.get('Output', 'generate_html') == 'yes')
        ttk.Checkbutton(output_frame, text="Generar HTML", variable=self.cfg_gen_html_var).pack(anchor='w', pady=5)
        
        self.cfg_gen_csv_var = tk.BooleanVar(value=self.config.get('Output', 'generate_csv') == 'yes')
        ttk.Checkbutton(output_frame, text="Generar CSV", variable=self.cfg_gen_csv_var).pack(anchor='w', pady=5)
        
        self.cfg_gen_json_var = tk.BooleanVar(value=self.config.get('Output', 'generate_json') == 'yes')
        ttk.Checkbutton(output_frame, text="Generar JSON", variable=self.cfg_gen_json_var).pack(anchor='w', pady=5)
        
        ttk.Label(output_frame, text="Directorio:").pack(anchor='w', pady=(10, 5))
        dir_frame = ttk.Frame(output_frame)
        dir_frame.pack(fill='x')
        
        self.cfg_output_dir_var = tk.StringVar(value=self.config.get('Output', 'directory'))
        ttk.Entry(dir_frame, textvariable=self.cfg_output_dir_var).pack(side='left', fill='x', expand=True, padx=(0, 10))
        ttk.Button(dir_frame, text="Examinar...", command=self.browse_output_dir).pack(side='right')
        
        ttk.Button(parent, text="💾 Guardar Configuración", command=self.save_config).pack(pady=20)
        
        info_text = ttk.Label(parent, 
                             text="⚠️ Importante:\n"
                                  "• Se requiere PsExec.exe en la carpeta del programa\n"
                                  "• El programa debe ejecutarse como Administrador\n"
                                  "• Los equipos remotos deben poder acceder a la carpeta compartida",
                             foreground='red', 
                             font=('Arial', 9, 'italic'),
                             justify='left')
        info_text.pack(pady=10)
    
    def create_share(self):
        """Crea carpeta compartida"""
        success, message = setup_shared_folder()
        if success:
            self.share_active = True
            local_ip = get_local_ip()
            share_path = f"\\\\{local_ip}\\{SHARE_NAME}"
            self.share_status_var.set(f"✅ Activa: {share_path}")
            self.log(f"✅ {message}")
            messagebox.showinfo("Éxito", f"Carpeta compartida creada:\n{share_path}")
        else:
            self.share_status_var.set("❌ Error al crear")
            self.log(f"❌ {message}")
            messagebox.showerror("Error", f"No se pudo crear carpeta compartida:\n{message}")
    
    def remove_share(self):
        """Elimina carpeta compartida"""
        cleanup_shared_folder()
        self.share_active = False
        self.share_status_var.set("❌ No configurada")
        self.log("Carpeta compartida eliminada")
        messagebox.showinfo("Info", "Carpeta compartida eliminada")
    
    def save_config(self):
        self.config.set('Network', 'default_range', self.cfg_range_var.get())
        self.config.set('Credentials', 'username', self.cfg_user_var.get())
        self.config.set('Output', 'generate_html', 'yes' if self.cfg_gen_html_var.get() else 'no')
        self.config.set('Output', 'generate_csv', 'yes' if self.cfg_gen_csv_var.get() else 'no')
        self.config.set('Output', 'generate_json', 'yes' if self.cfg_gen_json_var.get() else 'no')
        self.config.set('Output', 'directory', self.cfg_output_dir_var.get())
        self.config.save()
        messagebox.showinfo("Configuración", "Configuración guardada")
    
    def browse_output_dir(self):
        directory = filedialog.askdirectory(initialdir=self.cfg_output_dir_var.get())
        if directory:
            self.cfg_output_dir_var.set(directory)
    
    def log(self, message):
        self.log_text.configure(state='normal')
        self.log_text.insert('end', f"{message}\n")
        self.log_text.see('end')
        self.log_text.configure(state='disabled')
    
    def start_scan(self):
        if self.scanning:
            messagebox.showwarning("Escaneo en curso", "Ya hay un escaneo activo")
            return
        
        if not self.share_active:
            messagebox.showerror("Error", "Debes crear la carpeta compartida primero")
            return
        
        try:
            ips = parse_cidr_range(self.ip_range_var.get())
        except Exception as e:
            messagebox.showerror("Error", f"Rango inválido: {e}")
            return
        
        # Limpiar carpeta de resultados
        if RESULTS_FOLDER.exists():
            for file in RESULTS_FOLDER.glob("*.json"):
                try:
                    file.unlink()
                except:
                    pass
        
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, 'end')
        self.log_text.configure(state='disabled')
        
        self.scanning = True
        self.scan_button.configure(state='disabled')
        
        thread = threading.Thread(target=self.run_scan, args=(ips,), daemon=True)
        thread.start()
    
    def run_scan(self, ips):
        try:
            username = self.username_var.get()
            password = self.password_var.get()
            concurrency = int(self.threads_var.get())
            
            local_ip = get_local_ip()
            share_path = f"\\\\{local_ip}\\{SHARE_NAME}"
            
            self.log(f"Iniciando escaneo de {len(ips)} IPs...")
            self.log(f"Carpeta compartida: {share_path}")
            self.log(f"Hilos concurrentes: {concurrency}")
            self.log("="*60)
            self.status_var.set(f"Distribuyendo scripts a {len(ips)} equipos...")
            
            executed = []
            failed = []
            
            # Fase 1: Distribuir y ejecutar scripts
            completed = 0
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = {
                    executor.submit(execute_remote_script, ip, username, password, share_path): ip 
                    for ip in ips
                }
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result['success']:
                            executed.append(result)
                            self.log(f"✅ {ip} - Script ejecutado ({result.get('method', 'N/A')})")
                        else:
                            failed.append(result)
                            error = result.get('error', 'Error')[:60]
                            self.log(f"⚠️ {ip} - {error}")
                    except Exception as e:
                        failed.append({'ip': ip, 'error': str(e)})
                        self.log(f"❌ {ip} - Excepción: {str(e)[:60]}")
                    
                    completed += 1
                    progress = (completed / len(ips)) * 50  # Primera mitad del progreso
                    self.progress_var.set(progress)
                    self.status_var.set(f"Ejecutados: {completed}/{len(ips)} ({progress:.1f}%)")
            
            self.log("\n" + "="*60)
            self.log(f"Scripts ejecutados: {len(executed)}")
            self.log(f"Fallos: {len(failed)}")
            self.log("="*60)
            
            # Fase 2: Esperar y recopilar resultados
            self.log("\n⏳ Esperando resultados de los equipos remotos...")
            self.log("(Esto puede tardar 1-2 minutos mientras los equipos procesan)")
            self.status_var.set("Recopilando resultados...")
            
            # Esperar resultados con timeout
            wait_time = 120  # 2 minutos
            results_collected = []
            
            for i in range(wait_time):
                if RESULTS_FOLDER.exists():
                    json_files = list(RESULTS_FOLDER.glob("*.json"))
                    
                    for json_file in json_files:
                        if json_file.name not in [r['file'] for r in results_collected]:
                            try:
                                with open(json_file, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    results_collected.append({
                                        'file': json_file.name,
                                        'data': data,
                                        'success': data.get('Success', True)
                                    })
                                    comp_name = data.get('Computer', json_file.name)
                                    self.log(f"📥 Resultado recibido: {comp_name}")
                            except Exception as e:
                                self.log(f"⚠️ Error leyendo {json_file.name}: {e}")
                
                progress = 50 + (i / wait_time * 50)  # Segunda mitad del progreso
                self.progress_var.set(progress)
                self.status_var.set(f"Resultados: {len(results_collected)}/{len(executed)} ({progress:.1f}%)")
                time.sleep(1)
            
            self.log("\n" + "="*60)
            self.log(f"✅ Resultados recopilados: {len(results_collected)}")
            self.log("="*60)
            
            # Guardar resultados finales
            self.log("\n💾 Generando archivos finales...")
            output_dir = self.config.get('Output', 'directory', '.')
            files = save_results(results_collected, self.config, output_dir)
            
            self.log("\n✅ ESCANEO COMPLETADO")
            self.log(f"   • Equipos exitosos: {len(results_collected)}")
            self.log(f"   • Equipos sin respuesta: {len(executed) - len(results_collected)}")
            self.log(f"   • Fallos de conexión: {len(failed)}")
            
            for file_type, file_path in files.items():
                self.log(f"   • {file_type.upper()}: {file_path.name}")
            
            self.status_var.set("Escaneo completado")
            self.progress_var.set(100)
            
            messagebox.showinfo("Completado",
                              f"Escaneo completado:\n\n"
                              f"✅ Resultados: {len(results_collected)}\n"
                              f"⚠️ Sin respuesta: {len(executed) - len(results_collected)}\n"
                              f"❌ Fallos: {len(failed)}\n\n"
                              f"Archivos en: {output_dir}")
        
        except Exception as e:
            self.log(f"\n❌ Error fatal: {e}")
            import traceback
            self.log(traceback.format_exc())
            self.status_var.set("Error")
            messagebox.showerror("Error", f"Error durante escaneo:\n{e}")
        
        finally:
            self.scanning = False
            self.scan_button.configure(state='normal')
            self.progress_var.set(0)
    
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        if self.share_active:
            if messagebox.askyesno("Salir", "¿Eliminar carpeta compartida antes de salir?"):
                cleanup_shared_folder()
        self.root.destroy()


def main():
    """Punto de entrada"""
    # Verificar que se ejecuta como administrador en Windows
    if sys.platform == 'win32':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                messagebox.showwarning("Advertencia", 
                                      "Este programa debe ejecutarse como Administrador\n"
                                      "para crear carpetas compartidas.\n\n"
                                      "Click derecho → Ejecutar como administrador")
        except:
            pass
    
    app = InventarioGUI()
    app.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Interrumpido")
        cleanup_shared_folder()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)