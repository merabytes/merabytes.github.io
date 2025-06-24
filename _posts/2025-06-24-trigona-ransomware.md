---
layout: default
title: "Anatomía de un Compromiso de Ransomware: Trigona Ransomware"
description: "Análisis técnico detallado de un ataque real de ransomware realizado por el grupo Trigona."
author: "Merabytes"
date: 2025-06-24
image: "https://media.licdn.com/dms/image/v2/D4D12AQGvJXnugt_Wxg/article-cover_image-shrink_720_1280/article-cover_image-shrink_720_1280/0/1721751819863?e=1756339200&v=beta&t=gdb7-AePbjMn0lDvCJb3KP1rJ7BYr6myIIZ4iqlUhS4"
categories: [ransomware, analisis-forense]
tags: [trigona, ransomware, malware, forense, xdr, edr, redteam, pentest]
---

🔑 **Puntos clave**

A principios de noviembre de 2023, observamos un ataque significativo de ransomware que involucró al actor de amenazas Trigona. Los actores de amenazas accedieron a la infraestructura interna de la empresa afectada mediante un servicio RDWeb (Terminal Services) expuesto públicamente conectado a un servidor SQL interno, lo que llevó a la exfiltración de datos y la detonación del ransomware en toda su infraestructura interna.

...

🗑️ **Borrado de Copias y Bases de Datos tras la Detonación**

**coba.bat**

```bat
timeout /t 1 /nobreak
wbadmin delete systemstatebackup -quiet
...
```

Uso de **Wise Force Deleter** para borrar las bases de datos SQL.

---

## Detección y IOCs

**Direcciones IP**

- 77.83.36.6
- 193.106.31.98

**Hashes y archivos relacionados**

- `disable-defender.exe`: `feb09cc39b1520d228e9e9274500b8c229016d6fc8018a2bf19aa9d3601492c5`
...

**URLs en VirusTotal**

- [disable-defender.exe](https://www.virustotal.com/gui/file/feb09cc39b1520d228e9e9274500b8c229016d6fc8018a2bf19aa9d3601492c5)
...

---

> Si te interesa acceder a otros informes privados o reglas específicas para EDR/XDR, visita [merabytes.com](https://www.merabytes.com) y solicita acceso a nuestros servicios avanzados de detección y simulación de amenazas.
