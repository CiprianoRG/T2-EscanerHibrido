
# Proyecto: Escáner Híbrido de Puertos y Sniffing en C++

## Descripción General
Herramienta en C++ para Linux que combina escaneo real de puertos TCP/UDP y captura de la primera trama de respuesta. Al finalizar, genera un informe JSON con servicios detectados y primeros bytes de cabecera.

## Integrantes del Equipo
- DIEGO AGUAYO FRIAS
- VALERIA ABIGAIL NAVARRO CASAREZ
- ASHLEY KARINA RIOS RODRIGUEZ
- LUIS CIPRIANO RODRIGUEZ GONZALEZ

## Características Principales
-  **Escaneo concurrente** TCP y UDP
-  **Captura en tiempo real** de respuestas
-  **Alto rendimiento** con concurrencia nativa
-  **Reportes JSON** estructurados
-  **Detección precisa** de estados (Abierto/Cerrado/Filtrado)

## Requisitos
- **Sistema operativo**: Ubuntu/Debian Linux
- **Compilador**: g++ (C++17 o superior)
- **Dependencias**: libpcap-dev, build-essential

## Instalación de Dependencias
```bash
sudo apt-get update
sudo apt-get install g++ make libpcap-dev libpcap0.8-dev build-essential
```

## Compilación
### Opción 1: Usando Makefile
```bash
make clean && make
```

### Opción 2: Compilación manual
```bash
g++ -std=c++17 -Iinclude -o escaner_hibrido main.cpp src/*.cpp -lpcap -pthread
```

## Ejecución
```bash
sudo ./escaner_hibrido
```
**Ejemplo de entrada:**
```
IP objetivo: 192.168.1.100
Rango puertos (ej. 20-80): 20-1024
Timeout (ms): 500
Archivo JSON: resultado.json
```

## Estructura del Proyecto
```
proyecto_escanner/
├── src/
│   ├── Escaner.cpp      # Escaneo concurrente TCP/UDP
│   ├── Sniffer.cpp      # Captura de paquetes con libpcap
│   ├── JSONGen.cpp      # Generación de reportes JSON
│   └── Validaciones.cpp # Validación de entradas
├── include/
│   ├── Escaner.h
│   ├── Sniffer.h
│   ├── JSONGen.h
│   ├── Validaciones.h
│   └── nlohmann/        # Biblioteca JSON header-only
├── main.cpp             # Programa principal
└── Makefile             # Sistema de build
```

## Enfoque Técnico
- **Escaneo TCP**: Conexiones no bloqueantes con `select()`
- **Escaneo UDP**: `sendto()` + detección de respuestas
- **Sniffing**: `libpcap` con filtros BPF dinámicos
- **Concurrencia**: `std::async` y `std::future` para paralelismo
- **JSON**: Biblioteca nlohmann/json para serialización

## Ejemplo de JSON Generado
```json
[
  {
    "ip": "192.168.1.100",
    "port": 22,
    "protocol": "TCP",
    "service": "ssh",
    "header_bytes": "45 00 00 34 12 34 40 00"
  },
  {
    "ip": "192.168.1.100", 
    "port": 80,
    "protocol": "TCP",
    "service": "http",
    "header_bytes": "45 00 00 28 56 78 00 00"
  }
]
```

## Estados de Puertos Detectados
- **TCP**: "Abierto", "Cerrado", "Filtrado", "Error"
- **UDP**: "Abierto", "Cerrado/Filtrado", "Error"

## Notas Importantes
-  **Se requieren permisos root** para la captura de paquetes
-  **Timeout recomendado**: 1000-5000ms para mejores resultados
-  **Solución de problemas**: Verificar que libpcap esté instalado correctamente

---

**¡Proyecto desarrollado como parte de la Tarea 2 de Programación en Ciberseguridad!**
