import base64
from urllib.parse import quote
import re
import sys
import argparse
import json
import logging
import tkinter as tk
from tkinter import ttk, messagebox

# Configuración del logging
logging.basicConfig(
    filename='evasor_waf.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class EvasorWAF:
    """Clase que encapsula las técnicas de evasión para pruebas de seguridad."""

    def __init__(self):
        self.cargar_config()

    def cargar_config(self):
        """Carga la configuración de palabras clave desde un archivo."""
        CONFIG_FILE = 'config.json'
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.PALABRAS_CLAVE = config.get('palabras_clave', ['SELECT', 'UNION', 'WHERE', 'OR', 'AND'])
        except FileNotFoundError:
            self.PALABRAS_CLAVE = ['SELECT', 'UNION', 'WHERE', 'OR', 'AND']
        except Exception as e:
            print(f"Error al cargar configuración: {e}")
            self.PALABRAS_CLAVE = ['SELECT', 'UNION', 'WHERE', 'OR', 'AND']

    def guardar_config(self):
        """Guarda la configuración de palabras clave en un archivo."""
        CONFIG_FILE = 'config.json'
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump({'palabras_clave': self.PALABRAS_CLAVE}, f, indent=4)
            print("Configuración guardada exitosamente.")
        except Exception as e:
            print(f"Error al guardar configuración: {e}")

    @staticmethod
    def codificar_url(payload, doble=False):
        """Codificación URL estándar o doble."""
        try:
            return quote(payload) if not doble else quote(quote(payload))
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
            for palabra in self.PALABRAS_CLAVE:
                payload = re.sub(
                    rf'(?i)\b{re.escape(palabra)}\b',
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
            return ''.join(
                c.upper() if i % 2 == 0 else c.lower()
                if c.isalpha() else c
                for i, c in enumerate(payload)
            )
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

    def editar_palabras_clave(self):
        """Permite al usuario editar la lista de palabras clave."""
        print(f"Palabras clave actuales: {', '.join(self.PALABRAS_CLAVE)}")
        nuevas = input("Ingrese nuevas palabras clave separadas por comas: ").strip()
        if nuevas:
            self.PALABRAS_CLAVE = [palabra.strip().upper() for palabra in nuevas.split(',')]
            self.guardar_config()
            print("Palabras clave actualizadas.")
        else:
            print("No se realizaron cambios.")

def mostrar_menu():
    """Muestra el menú de opciones sin descripciones detalladas."""
    menu = """
=== Evasor de WAF Profesional ===
Seleccione una opción:
1. Codificación URL Estándar
2. Doble Codificación URL
3. Codificación Base64
4. Codificación Hexadecimal
5. Inserción de Comentarios en Palabras Clave
6. Alternancia de Mayúsculas y Minúsculas
7. Reemplazo de Espacios por Tabulaciones
8. Reemplazo de Espacios por Caracteres Alternativos
9. Editar Palabras Clave
10. Salir
"""
    print(menu)

def ejecutar_tecnica(evasor, payload, opcion):
    """Ejecuta la técnica seleccionada."""
    tecnicas = {
        "1": ("Codificación URL Estándar", evasor.codificar_url),
        "2": ("Doble Codificación URL", lambda p: evasor.codificar_url(p, doble=True)),
        "3": ("Codificación Base64", evasor.codificar_base64),
        "4": ("Codificación Hexadecimal", evasor.codificar_hexadecimal),
        "5": ("Inserción de Comentarios en Palabras Clave", evasor.insertar_comentarios),
        "6": ("Alternancia de Mayúsculas y Minúsculas", evasor.alternar_mayusculas),
        "7": ("Reemplazo de Espacios por Tabulaciones", lambda p: evasor.reemplazar_espacios(p, 'tab')),
        "8": ("Reemplazo de Espacios por Caracteres Alternativos", evasor.codificar_espacios_alternativos),
        "9": ("Editar Palabras Clave", evasor.editar_palabras_clave)
    }

    tecnica = tecnicas.get(opcion)
    if tecnica:
        nombre_tecnica, funcion = tecnica
        if opcion == "9":
            funcion()
            return None
        print(f"\n=== {nombre_tecnica} ===")
        resultado = funcion(payload)
        if isinstance(resultado, dict):
            for metodo, resultado_parcial in resultado.items():
                print(f"{metodo}: {resultado_parcial}")
        else:
            print(f"Resultado:\n{resultado}")
        # Registro de resultados
        logging.info(f"Aplicando técnica: {nombre_tecnica} al payload: {payload}")
        if isinstance(resultado, dict):
            for metodo, res in resultado.items():
                logging.info(f"{metodo}: {res}")
        else:
            logging.info(f"Resultado: {resultado}")
    else:
        print("Opción no válida.")
        logging.warning(f"Opción no válida seleccionada: {opcion}")

def mostrar_ayuda():
    """Muestra la ayuda detallada del script."""
    ayuda = """
=== Ayuda del Evasor de WAF Profesional ===

Este script permite aplicar diversas técnicas de evasión a payloads para pruebas de seguridad.

**Opciones de Menú:**
1. Codificación URL Estándar
2. Doble Codificación URL
3. Codificación Base64
4. Codificación Hexadecimal
5. Inserción de Comentarios en Palabras Clave
6. Alternancia de Mayúsculas y Minúsculas
7. Reemplazo por Tabulaciones
8. Reemplazo por Caracteres Alternativos
9. Editar Palabras Clave
10. Salir

**Uso del Script:**
- Ejecuta el script sin argumentos para utilizar la interfaz de línea de comandos.
- Utiliza `--help` para ver esta ayuda.

**Notas:**
- Utiliza este script únicamente para pruebas de seguridad autorizadas.
- Asegúrate de tener permisos adecuados antes de realizar cualquier prueba.
"""
    print(ayuda)

def main_cli():
    """Función principal para la interfaz de línea de comandos."""
    parser = argparse.ArgumentParser(
        description='Evasor de WAF Profesional - Herramienta para aplicar técnicas de evasión a payloads.',
        add_help=False
    )
    parser.add_argument('--help', action='store_true', help='Muestra esta ayuda y sale.')

    args = parser.parse_args()

    if args.help:
        mostrar_ayuda()
        sys.exit(0)

    print("Este script debe ser utilizado únicamente para pruebas de seguridad autorizadas.")
    payload = input("Ingrese el payload original: ").strip()
    if not payload:
        print("El payload no puede estar vacío.")
        sys.exit(1)

    evasor = EvasorWAF()

    while True:
        mostrar_menu()
        opcion = input("Seleccione una opción (1-10): ").strip()
        if opcion == "10":
            print("Saliendo...")
            break
        elif opcion in map(str, range(1, 10)):
            ejecutar_tecnica(evasor, payload, opcion)
            volver = input("\n¿Desea probar otra técnica? (s/n): ").strip().lower()
            if volver == 'n':
                print("Saliendo...")
                break
        else:
            print("Opción no válida. Intente nuevamente.\n")

def main_gui():
    """Función principal para la interfaz gráfica de usuario."""
    evasor = EvasorWAF()

    def aplicar_tecnica_gui():
        payload = entry_payload.get().strip()
        if not payload:
            messagebox.showwarning("Entrada Vacía", "El payload no puede estar vacío.")
            return
        opcion = combo_tecnicas.get()
        if not opcion or opcion == "Seleccione una técnica":
            messagebox.showwarning("Selección Vacía", "Debe seleccionar una técnica.")
            return
        tecnica_num = tecnicas_gui[opcion][0]
        tecnica_nombre, funcion = tecnicas_gui[opcion][1], tecnicas_gui[opcion][2]
        logging.info(f"Aplicando técnica: {tecnica_nombre} al payload: {payload}")
        if tecnica_num == "9":
            evasor.editar_palabras_clave()
            messagebox.showinfo("Éxito", "Palabras clave actualizadas.")
            return
        resultado = funcion(payload)
        if isinstance(resultado, dict):
            resultados_text = "\n".join([f"{metodo}: {res}" for metodo, res in resultado.items()])
        else:
            resultados_text = resultado
        logging.info(f"Resultado: {resultado}")
        text_resultado.config(state='normal')
        text_resultado.delete(1.0, tk.END)
        text_resultado.insert(tk.END, resultados_text)
        text_resultado.config(state='disabled')

    # Definición de técnicas para GUI
    tecnicas_gui = {
        "Codificación URL Estándar": ("1", "Codificación URL Estándar", evasor.codificar_url),
        "Doble Codificación URL": ("2", "Doble Codificación URL", lambda p: evasor.codificar_url(p, doble=True)),
        "Codificación Base64": ("3", "Codificación Base64", evasor.codificar_base64),
        "Codificación Hexadecimal": ("4", "Codificación Hexadecimal", evasor.codificar_hexadecimal),
        "Inserción de Comentarios en Palabras Clave": ("5", "Inserción de Comentarios en Palabras Clave", evasor.insertar_comentarios),
        "Alternancia de Mayúsculas y Minúsculas": ("6", "Alternancia de Mayúsculas y Minúsculas", evasor.alternar_mayusculas),
        "Reemplazo de Espacios por Tabulaciones": ("7", "Reemplazo de Espacios por Tabulaciones", lambda p: evasor.reemplazar_espacios(p, 'tab')),
        "Reemplazo por Caracteres Alternativos": ("8", "Reemplazo por Caracteres Alternativos", evasor.codificar_espacios_alternativos),
        "Editar Palabras Clave": ("9", "Editar Palabras Clave", evasor.editar_palabras_clave)
    }

    # Creación de la ventana principal
    root = tk.Tk()
    root.title("Evasor de WAF Profesional")
    root.geometry("1000x700")  # Tamaño inicial más pequeño
    root.resizable(True, True)  # Permitir redimensionar en ambos ejes

    # Aplicar un tema predeterminado
    style = ttk.Style(root)
    style.theme_use('clam')  # Puedes cambiar a 'alt', 'default', etc.

    # Definir fuentes más estéticas y pequeñas
    fuente_etiquetas = ('Segoe UI', 12, 'bold')
    fuente_entradas = ('Segoe UI', 12)
    fuente_botones = ('Segoe UI', 12)

    # Configuración de la Grilla Principal
    root.grid_rowconfigure(0, weight=1)
    root.grid_rowconfigure(1, weight=1)
    root.grid_rowconfigure(2, weight=1)
    root.grid_rowconfigure(3, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # Entrada de Payload
    frame_payload = ttk.Frame(root, padding="10 5 10 5")
    frame_payload.grid(row=0, column=0, sticky="nsew", padx=20, pady=10)

    lbl_payload = ttk.Label(frame_payload, text="Payload Original:", font=fuente_etiquetas)
    lbl_payload.grid(row=0, column=0, sticky='w')
    entry_payload = ttk.Entry(frame_payload, font=fuente_entradas)
    entry_payload.grid(row=1, column=0, sticky='ew', pady=5)
    frame_payload.grid_columnconfigure(0, weight=1)

    # Selección de Técnica
    frame_tecnica = ttk.Frame(root, padding="10 5 10 5")
    frame_tecnica.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)

    lbl_tecnica = ttk.Label(frame_tecnica, text="Seleccione Técnica:", font=fuente_etiquetas)
    lbl_tecnica.grid(row=0, column=0, sticky='w')
    combo_tecnicas = ttk.Combobox(
        frame_tecnica,
        values=list(tecnicas_gui.keys()),
        state='readonly',
        font=fuente_entradas
    )
    combo_tecnicas.grid(row=1, column=0, sticky='ew', pady=5)
    combo_tecnicas.set("Seleccione una técnica")
    frame_tecnica.grid_columnconfigure(0, weight=1)

    # Descripción de la Técnica
    frame_descripcion = ttk.Frame(root, padding="10 5 10 5")
    frame_descripcion.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)
    frame_descripcion.grid_rowconfigure(1, weight=1)
    frame_descripcion.grid_columnconfigure(0, weight=1)

    lbl_descripcion = ttk.Label(frame_descripcion, text="Descripción:", font=fuente_etiquetas)
    lbl_descripcion.grid(row=0, column=0, sticky='w')
    text_descripcion = tk.Text(frame_descripcion, height=4, wrap='word', state='disabled', font=('Segoe UI', 11))
    text_descripcion.grid(row=1, column=0, sticky='nsew', pady=5)

    # Resultado
    frame_resultado = ttk.Frame(root, padding="10 5 10 5")
    frame_resultado.grid(row=3, column=0, sticky="nsew", padx=20, pady=10)
    frame_resultado.grid_rowconfigure(1, weight=1)
    frame_resultado.grid_columnconfigure(0, weight=1)

    lbl_resultado = ttk.Label(frame_resultado, text="Resultado:", font=fuente_etiquetas)
    lbl_resultado.grid(row=0, column=0, sticky='w')
    text_resultado = tk.Text(frame_resultado, wrap='word', state='disabled', font=('Segoe UI', 11))
    text_resultado.grid(row=1, column=0, sticky='nsew', pady=5)

    # Botones
    frame_botones = ttk.Frame(root, padding="10 5 10 5")
    frame_botones.grid(row=4, column=0, sticky="ew", padx=20, pady=20)
    frame_botones.grid_columnconfigure(0, weight=1)
    frame_botones.grid_columnconfigure(1, weight=1)

    btn_aplicar = ttk.Button(frame_botones, text="Aplicar Técnica", command=aplicar_tecnica_gui, style='Accent.TButton')
    btn_aplicar.grid(row=0, column=0, sticky='ew', padx=10, pady=10)

    btn_salir = ttk.Button(frame_botones, text="Cerrar GUI", command=root.quit, style='Accent.TButton')
    btn_salir.grid(row=0, column=1, sticky='ew', padx=10, pady=10)

    # Función para actualizar la descripción al seleccionar una técnica
    descripciones_tecnicas = {
        "Codificación URL Estándar": "Aplica una codificación URL estándar al payload.",
        "Doble Codificación URL": "Aplica una codificación URL dos veces al payload.",
        "Codificación Base64": "Codifica el payload en formato Base64.",
        "Codificación Hexadecimal": "Codifica el payload en formato hexadecimal.",
        "Inserción de Comentarios en Palabras Clave": "Inserta comentarios en palabras clave SQL para evadir filtros.",
        "Alternancia de Mayúsculas y Minúsculas": "Alterna entre mayúsculas y minúsculas en el payload para evitar detecciones basadas en patrones.",
        "Reemplazo de Espacios por Tabulaciones": "Reemplaza espacios por tabulaciones (%09) en el payload.",
        "Reemplazo por Caracteres Alternativos": "Reemplaza espacios por diferentes caracteres (%09, %0A, %0D) en el payload.",
        "Editar Palabras Clave": "Modifica la lista de palabras clave para inserción de comentarios."
    }

    def actualizar_descripcion(event):
        tecnica = combo_tecnicas.get()
        descripcion = descripciones_tecnicas.get(tecnica, "")
        text_descripcion.config(state='normal')
        text_descripcion.delete(1.0, tk.END)
        text_descripcion.insert(tk.END, descripcion)
        text_descripcion.config(state='disabled')

    combo_tecnicas.bind("<<ComboboxSelected>>", actualizar_descripcion)

    # Configuración de Pesos para la Grilla
    root.grid_rowconfigure(0, weight=1)
    root.grid_rowconfigure(1, weight=1)
    root.grid_rowconfigure(2, weight=2)
    root.grid_rowconfigure(3, weight=3)
    root.grid_rowconfigure(4, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # Estilo de la GUI para un aspecto más moderno
    style.configure('TButton', font=fuente_botones)
    style.configure('TLabel', font=fuente_etiquetas)
    style.configure('TEntry', font=fuente_entradas)
    style.configure('TCombobox', font=fuente_entradas)
    style.configure('Accent.TButton', foreground='white', background='#0078D7')  # Color azul para los botones

    root.mainloop()

def main():
    """Función principal que decide entre CLI y GUI."""
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'gui':
        main_gui()
    else:
        main_cli()

if __name__ == "__main__":
    main()
