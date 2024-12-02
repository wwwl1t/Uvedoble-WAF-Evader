# UveDoble WAF Evader

## Descripción

**UveDoble WAF Evader** es una herramienta diseñada para aplicar diversas técnicas de evasión a Web Application Firewalls (WAF) durante pruebas de seguridad. Ofrece tanto una interfaz de línea de comandos (CLI) como una interfaz gráfica de usuario (GUI), proporcionando flexibilidad y facilidad de uso para profesionales en ciberseguridad.

## Características

- **Interfaz de Línea de Comandos (CLI):**
  - Aplicación rápida de técnicas de evasión.
  - Soporte para múltiples técnicas (codificación URL, Base64, Hexadecimal, etc.).
  - Registro de actividades en un archivo de log.

- **Interfaz Gráfica de Usuario (GUI):**
  - Ventana redimensionable y adaptable.
  - Selección intuitiva de técnicas mediante combobox.
  - Visualización de descripciones y resultados en tiempo real.
  - Botones accesibles para aplicar técnicas y cerrar la GUI.

## Instalación

### Requisitos Previos

- **Python 3.6 o superior**.
- **Bibliotecas Python:**
  - `tkinter` (generalmente incluido con Python).
  - `ttk` (incluido con `tkinter`).

### Pasos de Instalación

1. **Clonar el Repositorio:**

   ```bash
   git clone https://github.com/tu_usuario/UveDoble-WAF-Evader.git
   cd UveDoble-WAF-Evader

   
# Evasor WAF - Instrucciones de Uso

## Interfaz de Línea de Comandos (CLI)

### Ejecutar la CLI:

```bash
python evasor_waf.py
```

### Pasos Básicos:

1. **Ingresar el Payload:**

   Se te solicitará ingresar el payload original que deseas procesar.

   ```plaintext
   Ingrese el payload original: SELECT * FROM users WHERE id=1
   ```

2. **Seleccionar una Técnica:**

   Elige una opción del menú numerado para aplicar la técnica deseada.

   ```plaintext
   Seleccione una opción (1-10): 1
   ```

3. **Ver el Resultado:**

   El resultado de la técnica aplicada se mostrará en la terminal.

   ```plaintext
   Resultado:
   SELECT%20*%20FROM%20users%20WHERE%20id%3D1
   ```

4. **Opciones Adicionales:**

   Después de aplicar una técnica, puedes optar por aplicar otra o salir.

### Mostrar Ayuda:

Para ver la ayuda y opciones disponibles:

```bash
python evasor_waf.py --help
```

## Interfaz Gráfica de Usuario (GUI)

### Ejecutar la GUI:

```bash
python evasor_waf.py gui
```

