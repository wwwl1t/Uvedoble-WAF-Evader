import sys
import subprocess
import shutil
import re
import requests
import base64
import binascii
import codecs
import urllib.parse
import json
import logging
import hashlib  # Importar hashlib para funciones de hash
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox, QGroupBox,
    QComboBox, QDialog, QDialogButtonBox, QAction, QSizePolicy, QSpacerItem
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QPoint
from PyQt5.QtGui import QFont, QIcon, QMouseEvent, QPixmap

# Configuración del logging
logging.basicConfig(
    filename='evasor_waf.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Funciones auxiliares para la detección de WAF
def is_wafw00f_installed():
    """
    Verifica si wafw00f está instalado y disponible en PATH.
    """
    return shutil.which("wafw00f") is not None

def install_wafw00f(parent=None):
    """
    Función para instalar wafw00f si no está instalado.
    """
    try:
        import wafw00f
    except ImportError:
        reply = QMessageBox.question(
            parent,
            'Instalación Necesaria',
            'wafw00f no está instalado. ¿Deseas instalarlo ahora?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "wafw00f"])
                QMessageBox.information(
                    parent,
                    'Instalación Completa',
                    'wafw00f ha sido instalado correctamente. Por favor, reinicia la aplicación.'
                )
                sys.exit()
            except subprocess.CalledProcessError:
                QMessageBox.critical(
                    parent,
                    'Error de Instalación',
                    'No se pudo instalar wafw00f. Por favor, instálalo manualmente.'
                )
                sys.exit()
        else:
            QMessageBox.warning(
                parent,
                'wafw00f No Instalado',
                'La aplicación no puede funcionar sin wafw00f.'
            )
            sys.exit()

def remove_ansi_escape_sequences(text):
    """
    Elimina las secuencias de escape ANSI de un texto.
    """
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def is_valid_url(url):
    """
    Valida que la URL ingresada sea válida y comience con http:// o https://
    """
    regex = re.compile(
        r'^(?:http|https)://'  # http:// o https://
        r'\w+(?:\.\w+)+',      # Dominio
        re.IGNORECASE
    )
    return re.match(regex, url) is not None

# Estilos para los modos claro y oscuro
light_mode_stylesheet = """
/* Modo Claro */
QWidget {
    background-color: #f0f0f0;
    color: #000000;
}
QLineEdit, QTextEdit {
    background-color: #ffffff;
    color: #000000;
    border: 1px solid #c0c0c0;
}
QPushButton {
    background-color: #e0e0e0;
    color: #000000;
    border: none;
    padding: 10px;
    font-size: 12px;
    border-radius: 5px;
}
QPushButton:hover {
    background-color: #d0d0d0;
}
QTabWidget::pane {
    border: 1px solid #c0c0c0;
}
QTabBar::tab {
    background: #e0e0e0;
    padding: 10px;
    min-width: 120px;
}
QTabBar::tab:selected {
    background: #ffffff;
}
QGroupBox {
    border: 1px solid #5c5c5c;
    margin-top: 10px;
    padding: 10px;
}
"""

dark_mode_stylesheet = """
/* Modo Oscuro */
QWidget {
    background-color: #2b2b2b;
    color: #d3d3d3;
}
QLineEdit, QTextEdit {
    background-color: #3c3c3c;
    color: #d3d3d3;
    border: 1px solid #5c5c5c;
}
QPushButton {
    background-color: #4a4a4a;
    color: #ffffff;
    border: none;
    padding: 10px;
    font-size: 12px;
    border-radius: 5px;
}
QPushButton:hover {
    background-color: #5a5a5a;
}
QTabWidget::pane {
    border: 1px solid #5c5c5c;
}
QTabBar::tab {
    background: #3c3c3c;
    padding: 10px;
    min-width: 120px;
}
QTabBar::tab:selected {
    background: #2b2b2b;
}
QGroupBox {
    border: 1px solid #5c5c5c;
    margin-top: 10px;
    padding: 10px;
}
"""

# Worker thread para wafw00f
class Wafw00fWorker(QThread):
    result_ready = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        if not is_wafw00f_installed():
            install_wafw00f()

        try:
            # Ejecutar wafw00f y capturar la salida
            result = subprocess.run(
                ["wafw00f", self.url],
                capture_output=True,
                text=True,
                timeout=60  # Tiempo de espera de 60 segundos
            )

            if result.returncode != 0:
                raise Exception(result.stderr.strip())

            output = result.stdout.strip()
            output = remove_ansi_escape_sequences(output)  # Limpiar secuencias de colores

            # Procesar la salida para extraer el WAF detectado
            if "wafw00f could not find a WAF" in output.lower():
                display_result = "No se detectó ningún WAF."
            else:
                # Extraer la línea que contiene la información del WAF
                lines = output.splitlines()
                waf_info = ""
                for line in lines:
                    if "WAF" in line.upper() or "firewall" in line.lower():
                        waf_info += line + "\n"
                if waf_info:
                    display_result = waf_info.strip()
                else:
                    display_result = "No se detectó ningún WAF."

            self.result_ready.emit(display_result)

        except subprocess.TimeoutExpired:
            self.result_ready.emit("Tiempo agotado durante la detección con wafw00f.")
        except Exception as e:
            self.result_ready.emit(f"Error durante la detección con wafw00f: {e}")

# Worker thread para detección por encabezados
class HeaderDetectorWorker(QThread):
    result_ready = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            # Ampliamos y actualizamos la base de datos de firmas de WAFs
            waf_signatures = {
                'Cloudflare': {
                    'headers': ['Server', 'CF-RAY', 'CF-Cache-Status', 'CF-Request-ID'],
                    'header_values': ['cloudflare'],
                    'body_patterns': [r'Cloudflare Ray ID', r'Attention Required! \| Cloudflare'],
                    'status_codes': [403, 503]
                },
                'AWS WAF': {
                    'headers': ['X-Amzn-Requestid', 'X-Amz-Cf-Id'],
                    'body_patterns': [r'403 Forbidden', r'Request blocked'],
                    'status_codes': [403]
                },
                'Akamai': {
                    'headers': ['Akamai-Origin-Hop', 'X-Akamai-Session-Info'],
                    'body_patterns': [r'Reference #[0-9a-f\.]+'],
                    'status_codes': [403, 400]
                },
                'F5 BIG-IP': {
                    'headers': ['X-WA-Info', 'X-Cnection'],
                    'header_values': ['BigIP'],
                    'body_patterns': [r'The requested URL was rejected'],
                    'status_codes': [403]
                },
                'Imperva Incapsula': {
                    'headers': ['X-CDN'],
                    'header_values': ['Incapsula'],
                    'body_patterns': [r'Incapsula incident ID'],
                    'status_codes': [403]
                },
                'Sucuri WAF': {
                    'headers': ['Server'],
                    'header_values': ['Sucuri/Cloudproxy'],
                    'body_patterns': [r'Access Denied - Sucuri Website Firewall'],
                    'status_codes': [403]
                },
                'Barracuda WAF': {
                    'headers': ['Server'],
                    'header_values': ['Barracuda'],
                    'body_patterns': [r'Barracuda Web Application Firewall'],
                    'status_codes': [403, 406]
                },
                'ModSecurity': {
                    'headers': [],
                    'body_patterns': [r'Mod_Security', r'ModSecurity'],
                    'status_codes': [406, 501]
                },
                'DenyAll WAF': {
                    'headers': [],
                    'body_patterns': [r'Condition Intercepted'],
                    'status_codes': [200]
                },
                'Wallarm': {
                    'headers': ['X-Wallarm-Reason', 'X-Wallarm-Reason-Code'],
                    'body_patterns': [],
                    'status_codes': [493]
                },
                # Agrega más WAFs y firmas según sea necesario
            }

            response = requests.get(self.url, timeout=30)
            headers = response.headers
            status_code = response.status_code
            content = response.text

            detected_wafs = []

            # Analizar cada WAF y sus firmas
            for waf_name, waf_info in waf_signatures.items():
                header_detected = False
                body_detected = False
                status_detected = False

                # Verificar encabezados
                for header in waf_info.get('headers', []):
                    if header in headers:
                        if 'header_values' in waf_info and waf_info['header_values']:
                            for value in waf_info['header_values']:
                                if value.lower() in headers[header].lower():
                                    header_detected = True
                                    break
                        else:
                            header_detected = True
                    if header_detected:
                        break

                # Verificar códigos de estado
                if status_code in waf_info.get('status_codes', []):
                    status_detected = True

                # Verificar patrones en el cuerpo de la respuesta
                for pattern in waf_info.get('body_patterns', []):
                    if re.search(pattern, content, re.IGNORECASE):
                        body_detected = True
                        break

                # Si se detecta por encabezado, código de estado o cuerpo, se añade a la lista
                if header_detected or status_detected or body_detected:
                    detected_wafs.append(waf_name)

            if detected_wafs:
                # Eliminar duplicados y crear una lista única
                detected_wafs = list(set(detected_wafs))
                display_result = "WAFs Detectados por Encabezados y Respuesta HTTP:\n" + ", ".join(detected_wafs)
            else:
                display_result = "No se detectó ningún WAF por Encabezados y Respuesta HTTP."

            self.result_ready.emit(display_result)

        except requests.Timeout:
            self.result_ready.emit("Tiempo agotado durante la detección por Encabezados HTTP.")
        except requests.RequestException as e:
            self.result_ready.emit(f"Error durante la detección por Encabezados HTTP: {e}")

class EditarPalabrasClaveDialog(QDialog):
    """Diálogo para editar palabras clave."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Editar Palabras Clave")
        self.setModal(True)
        self.setFixedSize(400, 200)

        # Obtener palabras clave actuales desde el EvasorWAF
        evasor = EvasorWAF()
        self.palabras_clave = evasor.palabras_clave.copy()

        # Layout principal
        layout = QVBoxLayout()

        # Label
        label = QLabel("Palabras Clave (separadas por comas):")
        layout.addWidget(label)

        # TextEdit
        self.text_edit = QTextEdit()
        self.text_edit.setText(", ".join(self.palabras_clave))
        layout.addWidget(self.text_edit)

        # Botones
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.guardar_palabras_clave)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def guardar_palabras_clave(self):
        """Guarda las nuevas palabras clave."""
        nuevas = self.text_edit.toPlainText().strip()
        if nuevas:
            self.palabras_clave = [palabra.strip().upper() for palabra in nuevas.split(',')]
            evasor = EvasorWAF()
            evasor.palabras_clave = self.palabras_clave
            evasor.guardar_config()
            QMessageBox.information(self, "Éxito", "Palabras clave actualizadas.")
            self.accept()
        else:
            QMessageBox.warning(self, "Entrada Vacía", "Debe ingresar al menos una palabra clave.")

class EvasorWAF:
    """Clase que encapsula las técnicas de evasión para pruebas de seguridad."""

    def __init__(self):
        self.config_file = 'config.json'
        self.palabras_clave = ['SELECT', 'UNION', 'WHERE', 'OR', 'AND']
        self.cargar_config()

    def cargar_config(self):
        """Carga la configuración de palabras clave desde un archivo."""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.palabras_clave = config.get('palabras_clave', self.palabras_clave)
        except FileNotFoundError:
            logging.warning("Archivo de configuración no encontrado, usando palabras clave predeterminadas.")
        except Exception as e:
            logging.error(f"Error al cargar configuración: {e}")

    def guardar_config(self):
        """Guarda la configuración de palabras clave en un archivo."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump({'palabras_clave': self.palabras_clave}, f, indent=4)
            logging.info("Configuración guardada exitosamente.")
        except Exception as e:
            logging.error(f"Error al guardar configuración: {e}")

    @staticmethod
    def codificar_url(payload, doble=False):
        """Codificación URL estándar o doble."""
        try:
            if doble:
                return urllib.parse.quote(urllib.parse.quote(payload))
            else:
                return urllib.parse.quote(payload)
        except Exception as e:
            logging.error(f"Error en codificación URL: {e}")
            return payload

    @staticmethod
    def codificar_base64(payload):
        """Codificación en Base64."""
        try:
            return base64.b64encode(payload.encode()).decode()
        except Exception as e:
            logging.error(f"Error en codificación Base64: {e}")
            return payload

    @staticmethod
    def codificar_hexadecimal(payload):
        """Codificación en Hexadecimal."""
        try:
            return ''.join(f'%{ord(c):02X}' for c in payload)
        except Exception as e:
            logging.error(f"Error en codificación hexadecimal: {e}")
            return payload

    def insertar_comentarios(self, payload):
        """Inserta comentarios en palabras clave."""
        try:
            for palabra in self.palabras_clave:
                pattern = rf'(?i)\b{re.escape(palabra)}\b'
                payload = re.sub(
                    pattern,
                    lambda match: f"/**/{match.group(0)}/**/",
                    payload
                )
            return payload
        except Exception as e:
            logging.error(f"Error al insertar comentarios: {e}")
            return payload

    @staticmethod
    def alternar_mayusculas(payload):
        """Alterna entre mayúsculas y minúsculas."""
        try:
            resultado = []
            mayuscula = True
            for c in payload:
                if c.isalpha():
                    resultado.append(c.upper() if mayuscula else c.lower())
                    mayuscula = not mayuscula
                else:
                    resultado.append(c)
            return ''.join(resultado)
        except Exception as e:
            logging.error(f"Error al alternar mayúsculas: {e}")
            return payload

    @staticmethod
    def reemplazar_espacios(payload, tipo='tab'):
        """Reemplaza espacios por el carácter especificado."""
        reemplazos = {
            'tab': '%09',
            'salto_linea': '%0A',
            'retorno_carro': '%0D'
        }
        try:
            return payload.replace(' ', reemplazos.get(tipo, '%09'))
        except Exception as e:
            logging.error(f"Error al reemplazar espacios: {e}")
            return payload

    def codificar_espacios_alternativos(self, payload):
        """Reemplaza espacios por caracteres alternativos."""
        try:
            return {
                "Tabulación (%09)": self.reemplazar_espacios(payload, 'tab'),
                "Salto de Línea (%0A)": self.reemplazar_espacios(payload, 'salto_linea'),
                "Retorno de Carro (%0D)": self.reemplazar_espacios(payload, 'retorno_carro')
            }
        except Exception as e:
            logging.error(f"Error en codificación de espacios alternativos: {e}")
            return payload

class DecodeHashWorker(QThread):
    """Worker thread para decodificar hashes usando la API de md5decrypt.net."""
    result_ready = pyqtSignal(str)

    def __init__(self, hash_value, hash_type, api_key, email):
        super().__init__()
        self.hash_value = hash_value
        self.hash_type = hash_type
        self.api_key = api_key
        self.email = email

    def run(self):
        try:
            # URL de la API real para decodificar hashes
            api_url = "https://api.md5decrypt.net/Api/api.php"
            payload = {
                'hash': self.hash_value,
                'hash_type': self.hash_type.lower(),
                'email': self.email,
                'code': self.api_key
            }
            headers = {
                'Content-Type': 'application/json'
            }

            response = requests.post(api_url, data=json.dumps(payload), headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    original_text = data.get('original')
                    if original_text:
                        display_result = f"Hash Decodificado: {original_text}"
                    else:
                        display_result = "No se encontró una coincidencia para el hash proporcionado."
                else:
                    display_result = f"Error de la API: {data.get('message', 'Sin mensaje')}"
            else:
                display_result = f"Error en la solicitud: Código {response.status_code}"

            self.result_ready.emit(display_result)

        except requests.Timeout:
            self.result_ready.emit("Tiempo agotado durante la decodificación del hash.")
        except requests.RequestException as e:
            self.result_ready.emit(f"Error durante la decodificación del hash: {e}")
        except Exception as e:
            self.result_ready.emit(f"Ocurrió un error inesperado: {e}")

class App(QMainWindow):
    """Clase principal de la aplicación."""
    def __init__(self):
        super().__init__()

        # Remover el marco de la ventana y establecer título y tamaño
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setGeometry(100, 100, 1000, 700)

        # Establecer una fuente más amigable y grande
        font = QFont("Segoe UI", 10)
        self.setFont(font)

        # Main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.main_widget.setLayout(self.main_layout)

        # Variable para rastrear el tema actual
        self.current_theme = 'light'

        # Custom title bar
        self.setup_title_bar()

        # Initialize tabs
        self.setup_gui()

        # Barra inferior para opciones adicionales
        self.setup_bottom_bar()

        # Variable para rastrear la posición antigua (para mover la ventana)
        self.oldPos = self.pos()

        # Establecer el modo claro por defecto
        self.setStyleSheet(light_mode_stylesheet)

        # Configurar API Key y Email (Reemplaza con tus credenciales)
        self.api_key = 'YOUR_API_KEY'  # Reemplaza con tu clave API de md5decrypt.net
        self.email = 'YOUR_EMAIL'      # Reemplaza con tu email registrado en md5decrypt.net

    def setup_title_bar(self):
        # Title bar layout
        self.title_bar = QWidget()
        self.title_bar.setFixedHeight(30)
        self.title_bar_layout = QHBoxLayout()
        self.title_bar_layout.setContentsMargins(0, 0, 0, 0)
        self.title_bar_layout.setSpacing(0)
        self.title_bar.setLayout(self.title_bar_layout)

        # Title label con tu nombre añadido
        self.title_label = QLabel("  Detector de WAF y Herramientas - Uvedoble")
        self.title_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.title_bar_layout.addWidget(self.title_label)

        # Spacer
        self.title_bar_layout.addStretch()

        # Botones de control de ventana
        button_style = """
        QPushButton {
            background-color: transparent;
            border: none;
            font-size: 14px;
            padding: 5px;
        }
        QPushButton:hover {
            background-color: #d6d6d6;
        }
        """

        # Minimize button
        self.minimize_button = QPushButton("–")
        self.minimize_button.setFixedSize(30, 30)
        self.minimize_button.clicked.connect(self.showMinimized)
        self.minimize_button.setStyleSheet(button_style)
        self.title_bar_layout.addWidget(self.minimize_button)

        # Maximize button
        self.maximize_button = QPushButton("□")
        self.maximize_button.setFixedSize(30, 30)
        self.maximize_button.clicked.connect(self.toggle_maximize_restore)
        self.maximize_button.setStyleSheet(button_style)
        self.title_bar_layout.addWidget(self.maximize_button)

        # Close button
        self.close_button = QPushButton("✕")
        self.close_button.setFixedSize(30, 30)
        self.close_button.clicked.connect(self.close)
        close_button_style = button_style + """
        QPushButton:hover {
            background-color: red;
        }
        """
        self.close_button.setStyleSheet(close_button_style)
        self.title_bar_layout.addWidget(self.close_button)

        self.main_layout.addWidget(self.title_bar)

    def toggle_maximize_restore(self):
        """Alterna entre maximizar y restaurar la ventana."""
        if self.isMaximized():
            self.showNormal()
            self.maximize_button.setText("□")
        else:
            self.showMaximized()
            self.maximize_button.setText("❐")

    def setup_bottom_bar(self):
        """Configura la barra inferior con el botón para cambiar el tema y tu nombre."""
        bottom_bar = QWidget()
        bottom_bar.setFixedHeight(40)
        bottom_bar_layout = QHBoxLayout()
        bottom_bar_layout.setContentsMargins(10, 0, 10, 0)
        bottom_bar_layout.setSpacing(0)
        bottom_bar.setLayout(bottom_bar_layout)

        # Spacer para centrar el botón
        bottom_bar_layout.addStretch()

        # Botón para cambiar el tema
        self.toggle_theme_button = QPushButton("Modo Oscuro")
        self.toggle_theme_button.setCheckable(True)
        self.toggle_theme_button.clicked.connect(self.toggle_theme)
        self.toggle_theme_button.setStyleSheet("""
            QPushButton {
                background-color: #e0e0e0;
                color: #000000;
                border: none;
                padding: 10px 20px;
                font-size: 12px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #d0d0d0;
            }
            QPushButton:checked {
                background-color: #4a4a4a;
                color: #ffffff;
            }
            QPushButton:checked:hover {
                background-color: #5a5a5a;
            }
        """)
        bottom_bar_layout.addWidget(self.toggle_theme_button)

        # Spacer para mantener el botón centrado
        bottom_bar_layout.addStretch()

        # Añadir etiqueta con tu nombre en la barra inferior
        self.developer_label = QLabel("Desarrollado por Uvedoble")
        self.developer_label.setStyleSheet("font-size: 12px;")
        bottom_bar_layout.addWidget(self.developer_label)

        self.main_layout.addWidget(bottom_bar)

    def setup_gui(self):
        """Configura la interfaz gráfica con las pestañas."""
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabBar::tab { min-width: 120px; }")
        self.main_layout.addWidget(self.tabs)

        # ----------------------- Pestaña 1: Detección de WAF -----------------------
        self.tab1 = QWidget()
        self.tabs.addTab(self.tab1, QIcon("icons/detect.png"), "Detección de WAF")
        self.setup_tab1()

        # ----------------------- Pestaña 2: Encode y Decode -----------------------
        self.tab2 = QWidget()
        self.tabs.addTab(self.tab2, QIcon("icons/encode.png"), "Encode/Decode")
        self.setup_tab2()

        # ----------------------- Pestaña 3: Evasor WAF SQLi -----------------------
        self.tab3 = QWidget()
        self.tabs.addTab(self.tab3, QIcon("icons/evasor.png"), "Evasor WAF SQLi")
        self.setup_tab3()

    def setup_tab1(self):
        """Configura la Pestaña 1: Detección de WAF."""
        layout = QVBoxLayout()

        # Instrucciones
        label = QLabel("Ingrese la URL de la página web:")
        layout.addWidget(label)

        # Campo de entrada para la URL
        self.url_entry = QLineEdit()
        self.url_entry.setPlaceholderText("https://www.ejemplo.com")
        layout.addWidget(self.url_entry)

        # Botón para iniciar la detección
        detect_button = QPushButton("Detectar WAFs")
        detect_button.clicked.connect(self.detect_wafs)
        detect_button.setMinimumHeight(40)
        detect_button.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: #ffffff;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0069d9;
            }
        """)
        layout.addWidget(detect_button)

        # Resultados de WAFW00F
        wafw00f_label = QLabel("Resultados de WAFW00F:")
        wafw00f_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(wafw00f_label)

        self.wafw00f_text = QTextEdit()
        self.wafw00f_text.setReadOnly(True)
        layout.addWidget(self.wafw00f_text)

        # Resultados del Detector por Encabezados
        header_label = QLabel("Resultados del Detector por Encabezados:")
        header_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header_label)

        self.header_text = QTextEdit()
        self.header_text.setReadOnly(True)
        layout.addWidget(self.header_text)

        self.tab1.setLayout(layout)

    def setup_tab2(self):
        """Configura la Pestaña 2: Encode/Decode."""
        layout = QVBoxLayout()

        # Sección de Encode
        encode_group = QGroupBox("Codificar")
        encode_layout = QGridLayout()

        # Método de Codificación
        encode_method_label = QLabel("Método de Codificación:")
        self.encode_method = QComboBox()
        self.encode_method.addItems([
            "Base64",
            "URL Encode",
            "Hex",
            "Rot13",
            "MD5",      # Nueva opción
            "SHA1",     # Nueva opción
            "SHA256"    # Nueva opción
        ])
        encode_layout.addWidget(encode_method_label, 0, 0)
        encode_layout.addWidget(self.encode_method, 0, 1)

        # Texto a codificar
        encode_text_label = QLabel("Texto a codificar:")
        self.encode_entry = QLineEdit()
        encode_layout.addWidget(encode_text_label, 1, 0)
        encode_layout.addWidget(self.encode_entry, 1, 1)

        # Botón de Codificación
        encode_btn = QPushButton("Codificar")
        encode_btn.clicked.connect(self.encode_text)
        encode_btn.setMinimumHeight(40)
        encode_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: #ffffff;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        encode_layout.addWidget(encode_btn, 2, 0, 1, 2)

        # Resultado Codificado
        encode_result_label = QLabel("Texto codificado:")
        self.encode_result = QTextEdit()
        self.encode_result.setReadOnly(True)
        encode_layout.addWidget(encode_result_label, 3, 0)
        encode_layout.addWidget(self.encode_result, 3, 1)

        encode_group.setLayout(encode_layout)
        layout.addWidget(encode_group)

        # Espaciador entre secciones
        layout.addSpacing(20)

        # Sección de Decode
        decode_group = QGroupBox("Decodificar")
        decode_layout = QGridLayout()

        # Método de Decodificación
        decode_method_label = QLabel("Método de Decodificación:")
        self.decode_method = QComboBox()
        self.decode_method.addItems([
            "Base64",
            "URL Decode",
            "Hex",
            "Rot13",
            "MD5",
            "SHA1",
            "SHA256"
            # Agregaremos estos métodos ahora
        ])
        decode_layout.addWidget(decode_method_label, 0, 0)
        decode_layout.addWidget(self.decode_method, 0, 1)

        # Texto a decodificar
        decode_text_label = QLabel("Texto a decodificar:")
        self.decode_entry = QLineEdit()
        decode_layout.addWidget(decode_text_label, 1, 0)
        decode_layout.addWidget(self.decode_entry, 1, 1)

        # Botón de Decodificación
        decode_btn = QPushButton("Decodificar")
        decode_btn.clicked.connect(self.decode_text)
        decode_btn.setMinimumHeight(40)
        decode_btn.setStyleSheet("""
            QPushButton {
                background-color: #ffc107;
                color: #ffffff;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e0a800;
            }
        """)
        decode_layout.addWidget(decode_btn, 2, 0, 1, 2)

        # Resultado Decodificado
        decode_result_label = QLabel("Texto decodificado:")
        self.decode_result = QTextEdit()
        self.decode_result.setReadOnly(True)
        decode_layout.addWidget(decode_result_label, 3, 0)
        decode_layout.addWidget(self.decode_result, 3, 1)

        decode_group.setLayout(decode_layout)
        layout.addWidget(decode_group)

        # Espaciador al final
        layout.addStretch()

        self.tab2.setLayout(layout)

    def setup_tab3(self):
        """Configura la Pestaña 3: Evasor WAF SQLi."""
        layout = QVBoxLayout()

        # Grupo de Evasión de WAF
        evasor_group = QGroupBox("Evasor de WAF SQLi Profesional")
        evasor_layout = QGridLayout()

        # Payload Original
        payload_label = QLabel("Payload Original:")
        self.payload_entry = QLineEdit()
        evasor_layout.addWidget(payload_label, 0, 0)
        evasor_layout.addWidget(self.payload_entry, 0, 1)

        # Selección de Técnica
        tecnica_label = QLabel("Seleccione Técnica:")
        self.tecnica_combo = QComboBox()
        self.tecnica_combo.addItems([
            "Codificación URL Estándar",
            "Doble Codificación URL",
            "Codificación Base64",
            "Codificación Hexadecimal",
            "Inserción de Comentarios en Palabras Clave",
            "Alternancia de Mayúsculas y Minúsculas",
            "Reemplazo de Espacios por Tabulaciones",
            "Reemplazo por Caracteres Alternativos"
        ])
        self.tecnica_combo.currentIndexChanged.connect(self.actualizar_descripcion_evasor)
        evasor_layout.addWidget(tecnica_label, 1, 0)
        evasor_layout.addWidget(self.tecnica_combo, 1, 1)

        # Descripción de la Técnica
        descripcion_label = QLabel("Descripción de la Técnica:")
        self.descripcion_tecnica = QTextEdit()
        self.descripcion_tecnica.setReadOnly(True)
        evasor_layout.addWidget(descripcion_label, 2, 0)
        evasor_layout.addWidget(self.descripcion_tecnica, 2, 1)

        # Resultado de la Técnica
        resultado_label = QLabel("Resultado:")
        self.resultado_evasor = QTextEdit()
        self.resultado_evasor.setReadOnly(True)
        evasor_layout.addWidget(resultado_label, 3, 0)
        evasor_layout.addWidget(self.resultado_evasor, 3, 1)

        # Botón para aplicar la técnica
        aplicar_btn = QPushButton("Aplicar Técnica")
        aplicar_btn.clicked.connect(self.aplicar_tecnica_gui)
        aplicar_btn.setMinimumHeight(40)
        aplicar_btn.setStyleSheet("""
            QPushButton {
                background-color: #17a2b8;
                color: #ffffff;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #138496;
            }
        """)
        evasor_layout.addWidget(aplicar_btn, 4, 0, 1, 2)

        # Botón para editar palabras clave
        editar_palabras_btn = QPushButton("Editar Palabras Clave")
        editar_palabras_btn.clicked.connect(self.editar_palabras_clave)
        editar_palabras_btn.setMinimumHeight(40)
        editar_palabras_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: #ffffff;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        evasor_layout.addWidget(editar_palabras_btn, 5, 0, 1, 2)

        evasor_group.setLayout(evasor_layout)
        layout.addWidget(evasor_group)

        # Espaciador al final
        layout.addStretch()

        self.tab3.setLayout(layout)

    def toggle_theme(self, checked):
        if checked:
            # Aplicar el estilo del modo oscuro
            self.setStyleSheet(dark_mode_stylesheet)
            self.toggle_theme_button.setText('Modo Claro')
            self.current_theme = 'dark'
        else:
            # Aplicar el estilo del modo claro
            self.setStyleSheet(light_mode_stylesheet)
            self.toggle_theme_button.setText('Modo Oscuro')
            self.current_theme = 'light'

    def detect_wafs(self):
        url = self.url_entry.text().strip()
        if not url:
            QMessageBox.critical(self, "Entrada Vacía", "Por favor, ingresa una URL.")
            return

        if not is_valid_url(url):
            QMessageBox.critical(self, "URL Inválida", "Por favor, ingresa una URL válida que comience con http:// o https://")
            return

        # Limpiar las áreas de resultados
        self.wafw00f_text.setPlainText("Detectando WAF con wafw00f...\n")
        self.header_text.setPlainText("Detectando WAF por Encabezados HTTP...\n")

        # Ejecutar ambos detectores en hilos separados para evitar bloquear la GUI
        self.wafw00f_worker = Wafw00fWorker(url)
        self.wafw00f_worker.result_ready.connect(self.update_wafw00f_result)
        self.wafw00f_worker.start()

        self.header_detector_worker = HeaderDetectorWorker(url)
        self.header_detector_worker.result_ready.connect(self.update_header_result)
        self.header_detector_worker.start()

    def update_wafw00f_result(self, result):
        self.wafw00f_text.setPlainText(result)

    def update_header_result(self, result):
        self.header_text.setPlainText(result)

    def encode_text(self):
        """Codifica el texto ingresado."""
        method = self.encode_method.currentText()
        text = self.encode_entry.text()
        if not text:
            QMessageBox.warning(self, "Entrada Faltante", "Por favor, ingresa el texto a codificar.")
            return
        try:
            if method == "Base64":
                encoded_bytes = base64.b64encode(text.encode('utf-8'))
                resultado = encoded_bytes.decode('utf-8')
            elif method == "URL Encode":
                resultado = urllib.parse.quote(text)
            elif method == "Hex":
                resultado = binascii.hexlify(text.encode('utf-8')).decode('utf-8')
            elif method == "Rot13":
                resultado = codecs.encode(text, 'rot_13')
            elif method == "MD5":
                hash_object = hashlib.md5(text.encode())
                resultado = hash_object.hexdigest()
            elif method == "SHA1":
                hash_object = hashlib.sha1(text.encode())
                resultado = hash_object.hexdigest()
            elif method == "SHA256":
                hash_object = hashlib.sha256(text.encode())
                resultado = hash_object.hexdigest()
            else:
                resultado = "Método no soportado."
        except Exception as e:
            logging.error(f"Error al codificar: {e}")
            resultado = f"Error al codificar: {e}"

        self.encode_result.setPlainText(resultado)

    def decode_text(self):
        """Decodifica el texto ingresado."""
        method = self.decode_method.currentText()
        text = self.decode_entry.text()
        if not text:
            QMessageBox.warning(self, "Entrada Faltante", "Por favor, ingresa el texto a decodificar.")
            return
        try:
            if method == "Base64":
                decoded_bytes = base64.b64decode(text)
                resultado = decoded_bytes.decode('utf-8')
            elif method == "URL Decode":
                resultado = urllib.parse.unquote(text)
            elif method == "Hex":
                resultado = binascii.unhexlify(text).decode('utf-8')
            elif method == "Rot13":
                resultado = codecs.decode(text, 'rot_13')
            elif method in ["MD5", "SHA1", "SHA256"]:
                # Intentar decodificar el hash usando una API en línea
                self.decode_hash(text, method)
                return  # Salir para esperar la respuesta de la API
            else:
                resultado = "Método no soportado."
        except binascii.Error:
            QMessageBox.critical(self, "Error de Decodificación", "El texto proporcionado no es válido para decodificar.")
            resultado = "Error de Decodificación."
        except Exception as e:
            logging.error(f"Error al decodificar: {e}")
            resultado = f"Error al decodificar: {e}"

        self.decode_result.setPlainText(resultado)

    def decode_hash(self, hash_value, hash_type):
        """Inicia el proceso de decodificación del hash utilizando una API en línea."""
        # Informar al usuario que la decodificación está en progreso
        self.decode_result.setPlainText("Decodificando hash...")

        # Validar que el usuario haya ingresado su API Key y Email
        if not self.api_key or not self.email:
            QMessageBox.critical(self, "Credenciales Faltantes",
                                 "Por favor, establece tu API Key y Email en el código antes de intentar decodificar hashes.")
            self.decode_result.setPlainText("Error: Credenciales faltantes.")
            return

        # Iniciar el worker thread para decodificar el hash
        self.decode_hash_worker = DecodeHashWorker(hash_value, hash_type, self.api_key, self.email)
        self.decode_hash_worker.result_ready.connect(self.update_decode_hash_result)
        self.decode_hash_worker.start()

    def update_decode_hash_result(self, result):
        """Actualiza el área de texto con el resultado de la decodificación del hash."""
        self.decode_result.setPlainText(result)

    def actualizar_descripcion_evasor(self):
        """Actualiza la descripción de la técnica seleccionada."""
        tecnica = self.tecnica_combo.currentText()
        descripciones = {
            "Codificación URL Estándar": "Aplica una codificación URL estándar al payload.",
            "Doble Codificación URL": "Aplica una codificación URL dos veces al payload.",
            "Codificación Base64": "Codifica el payload en formato Base64.",
            "Codificación Hexadecimal": "Codifica el payload en formato hexadecimal.",
            "Inserción de Comentarios en Palabras Clave": "Inserta comentarios en palabras clave SQL para evadir filtros.",
            "Alternancia de Mayúsculas y Minúsculas": "Alterna entre mayúsculas y minúsculas en el payload para evitar detecciones basadas en patrones.",
            "Reemplazo de Espacios por Tabulaciones": "Reemplaza espacios por tabulaciones (%09) en el payload.",
            "Reemplazo por Caracteres Alternativos": "Reemplaza espacios por diferentes caracteres (%09, %0A, %0D) en el payload."
        }
        descripcion = descripciones.get(tecnica, "")
        self.descripcion_tecnica.setPlainText(descripcion)

    def aplicar_tecnica_gui(self):
        """Aplica la técnica seleccionada al payload."""
        payload = self.payload_entry.text().strip()
        if not payload:
            QMessageBox.warning(self, "Entrada Vacía", "El payload no puede estar vacío.")
            return
        tecnica = self.tecnica_combo.currentText()
        if tecnica == "Seleccione una técnica":
            QMessageBox.warning(self, "Selección Vacía", "Debe seleccionar una técnica.")
            return

        evasor = EvasorWAF()
        try:
            if tecnica == "Codificación URL Estándar":
                resultado = evasor.codificar_url(payload)
            elif tecnica == "Doble Codificación URL":
                resultado = evasor.codificar_url(payload, doble=True)
            elif tecnica == "Codificación Base64":
                resultado = evasor.codificar_base64(payload)
            elif tecnica == "Codificación Hexadecimal":
                resultado = evasor.codificar_hexadecimal(payload)
            elif tecnica == "Inserción de Comentarios en Palabras Clave":
                resultado = evasor.insertar_comentarios(payload)
            elif tecnica == "Alternancia de Mayúsculas y Minúsculas":
                resultado = evasor.alternar_mayusculas(payload)
            elif tecnica == "Reemplazo de Espacios por Tabulaciones":
                resultado = evasor.reemplazar_espacios(payload, tipo='tab')
            elif tecnica == "Reemplazo por Caracteres Alternativos":
                resultado = evasor.codificar_espacios_alternativos(payload)
            else:
                resultado = "Técnica no soportada."

            if isinstance(resultado, dict):
                resultados_text = "\n".join([f"{metodo}: {res}" for metodo, res in resultado.items()])
            else:
                resultados_text = resultado

            self.resultado_evasor.setPlainText(resultados_text)

        except Exception as e:
            logging.error(f"Error al aplicar la técnica de evasión: {e}")
            QMessageBox.critical(self, "Error", f"Error al aplicar la técnica de evasión: {e}")

    def editar_palabras_clave(self):
        """Permite al usuario editar la lista de palabras clave."""
        dialog = EditarPalabrasClaveDialog(self)
        dialog.exec_()

def main():
    app = QApplication(sys.argv)
    # Establecer una fuente más amigable y grande para toda la aplicación
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    window = App()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
