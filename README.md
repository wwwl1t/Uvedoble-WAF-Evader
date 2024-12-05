# Detector de WAF y Herramientas - Uvedoble

Esta herramienta fue creada para utilizarse dentro de lo legal dígase pruebas de penetración, no me hago responsable del mal uso que le des. chau

## Tabla de Contenidos

- [Descripción](#descripción)
- [Características](#características)
- [Prerequisitos](#prerequisitos)
- [Instalación](#instalación)
- [Configuración](#configuración)
- [Uso](#uso)
- [Contribución](#contribución)
- [Licencia](#licencia)
- [Contacto](#contacto)

## Descripción

**Detector de WAF y Herramientas - Uvedoble** es una aplicación de escritorio desarrollada en Python utilizando PyQt5. Esta herramienta permite a los usuarios:

- **Detectar WAFs (Web Application Firewalls)** en sitios web mediante el uso de `wafw00f` y análisis de encabezados HTTP.
- **Codificar y Decodificar** textos utilizando diversos métodos como Base64, URL Encode, Hex, Rot13, MD5, SHA1 y SHA256.
- **Decodificar Hashes** mediante la integración con la API de [md5decrypt.net](https://md5decrypt.net/en/API/).
- **Aplicar Técnicas de Evasión WAF SQLi** para pruebas de seguridad.

El proyecto está personalizado y desarrollado por **Uvedoble**, ofreciendo una interfaz amigable y funcionalidades robustas para profesionales de la seguridad informática.

## Características

- **Detección de WAFs**:
  - Utiliza `wafw00f` para detectar WAFs comunes.
  - Análisis adicional de encabezados HTTP y patrones en el cuerpo de las respuestas para identificar WAFs.

- **Encode/Decode**:
  - Soporte para múltiples métodos de codificación y decodificación.
  - Funcionalidades para funciones hash como MD5, SHA1 y SHA256.

- **Decodificación de Hashes**:
  - Integración con la API de [md5decrypt.net](https://md5decrypt.net/en/API/) para intentar recuperar valores originales a partir de hashes conocidos.

- **Evasor WAF SQLi**:
  - Diversas técnicas para modificar payloads y evadir detecciones de WAFs.
  - Personalización de palabras clave utilizadas en las técnicas de evasión.

- **Interfaz Personalizada**:
  - Modo claro y oscuro.
  - Barra de título y barra inferior personalizada con el nombre del desarrollador, **Uvedoble**.


## Prerequisitos

Antes de instalar y ejecutar la aplicación, asegúrate de tener instalados los siguientes componentes:

- **Sistema Operativo**: Windows, macOS o Linux.
- **Python**: Versión 3.7 o superior.
- **pip**: Administrador de paquetes de Python.
- **wafw00f**: Herramienta para la detección de WAFs.

## Instalación

Sigue estos pasos para instalar y configurar la aplicación:

### 1. Clonar el Repositorio

```bash
git clone https://github.com/wwwl1t/Detector-de-WAF-y-Herramientas-Uvedoble.git
cd Detector-de-WAF-y-Herramientas-Uvedoble

### Instalar Dependencias
sudo pip install -r requirements.txt
```

