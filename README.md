# NanoChat - Sistema de Chat Seguro

Un sistema de chat en tiempo real con cifrado SSL, gestión de salas y panel de administración.

## 📋 Características Principales

- **Chat en tiempo real** con múltiples salas
- **Cifrado SSL/TLS** para comunicaciones seguras
- **Panel de administración** (Dashboard) para gestión del servidor
- **Historial de mensajes** persistente y cifrado
- **Gestión de usuarios** con nicknames personalizados
- **Bloqueo de IPs** para moderación
- **Reconexión automática** en caso de pérdida de conexión
- **Interfaz gráfica** intuitiva con Tkinter

## 🏗️ Arquitectura del Sistema

### Componentes Principales

1. **Servidor Backend** (`backend_chat_server.py`)
   - Servidor de chat principal (Puerto 8080)
   - API REST para administración (Puerto 8081)
   - Gestión de salas y usuarios
   - Cifrado de datos y comunicaciones

2. **Cliente de Chat** (`client.py`)
   - Interfaz gráfica para usuarios finales
   - Conexión segura al servidor
   - Gestión de salas y mensajes

3. **Panel de Administración** (`dashboard.py`)
   - Control del servidor (encender/apagar)
   - Gestión de salas y usuarios
   - Moderación (bloqueo de IPs)
   - Visualización de estadísticas

### Flujo de Funcionamiento

```
[Cliente] ←→ [Servidor Chat:8080] ←→ [Base de Datos Cifrada]
    ↓              ↓
[Dashboard] ←→ [API REST:8081]
```

## 🚀 Instalación y Configuración

### Requisitos

- Python 3.7+
- Dependencias listadas en `requirements.txt`

### Instalación

1. **Clonar el repositorio**
   ```bash
   git clone <repository-url>
   cd nanochat
   ```

2. **Instalar dependencias**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configurar variables de entorno**
   - Editar el archivo `.env`
   - Configurar el puerto del servidor (por defecto: 8080)

4. **Generar certificados SSL**
   - El sistema genera automáticamente `cert.pem` y `key.pem` al iniciar

## 🎮 Uso del Sistema

### 1. Iniciar el Servidor

**Opción A: Desde el Dashboard**
```bash
python dashboard.py
```
- Usar el botón "Encender Servidor" en la interfaz

**Opción B: Directamente**
```bash
python backend_chat_server.py
```

### 2. Conectar Clientes

```bash
python client.py
```

**Configuración inicial:**
1. Introducir IP del servidor (127.0.0.1 para local)
2. Configurar puerto (8080 por defecto)
3. Establecer nickname personalizado
4. Conectar al servidor

### 3. Usar el Chat

1. **Seleccionar sala** de la lista disponible
2. **Unirse a la sala** haciendo clic en "Unirse"
3. **Enviar mensajes** escribiendo en el campo de texto
4. **Ver historial** automáticamente al unirse
5. **Desconectar** usando el botón correspondiente

## 🔧 Funcionalidades Detalladas

### Servidor de Chat

- **Gestión de conexiones**: Manejo concurrente de múltiples clientes
- **Salas dinámicas**: Creación y eliminación automática de salas
- **Cifrado de datos**: Todos los datos se almacenan cifrados
- **Historial persistente**: Los mensajes se guardan con timestamp, IP y nickname
- **Moderación**: Sistema de bloqueo de IPs problemáticas

### Cliente

- **Interfaz intuitiva**: Lista de salas, chat y usuarios conectados
- **Reconexión automática**: Reintenta conectar en caso de pérdida
- **Historial completo**: Muestra formato `[timestamp] Nickname (IP): mensaje`
- **Gestión de estado**: Controles habilitados/deshabilitados según conexión

### Dashboard de Administración

- **Control del servidor**: Encender/apagar con un clic
- **Gestión de salas**: Crear, eliminar y monitorear salas
- **Moderación**: Bloquear/desbloquear IPs
- **Estadísticas**: Ver usuarios conectados y actividad
- **Historial**: Revisar conversaciones por sala

## 🔒 Seguridad

### Cifrado
- **SSL/TLS**: Todas las comunicaciones están cifradas
- **Fernet**: Cifrado simétrico para almacenamiento de datos
- **Certificados**: Generación automática de certificados SSL

### Moderación
- **Bloqueo de IPs**: Prevención de acceso a usuarios problemáticos
- **Validación de datos**: Sanitización de entradas de usuario
- **Gestión de sesiones**: Control de conexiones activas

## 📁 Estructura de Archivos

```
nanochat/
├── backend_chat_server.py    # Servidor principal
├── client.py                 # Cliente de chat
├── dashboard.py              # Panel de administración
├── requirements.txt          # Dependencias Python
├── .env                      # Variables de entorno
├── cert.pem                  # Certificado SSL (auto-generado)
├── key.pem                   # Clave privada SSL (auto-generado)
├── chat_data.json           # Base de datos cifrada
└── README.md                # Documentación
```

## 🌐 Puertos y Comunicación

- **Puerto 8080**: Servidor de chat principal (conexiones de clientes)
- **Puerto 8081**: API REST (dashboard y operaciones administrativas)

### Endpoints API

- `GET /api/rooms` - Lista de salas disponibles
- `GET /api/blocked_ips` - IPs bloqueadas
- `GET /api/room_history` - Historial de sala
- `GET /api/room_users` - Usuarios en sala
- `POST /api/create_room` - Crear nueva sala
- `POST /api/delete_room` - Eliminar sala
- `POST /api/block_ip` - Bloquear IP
- `POST /api/unblock_ip` - Desbloquear IP

## 📝 Notas Técnicas

- **Concurrencia**: El servidor maneja múltiples clientes usando threading
- **Persistencia**: Los datos se guardan automáticamente tras cada operación
- **Escalabilidad**: Diseñado para uso en redes locales pequeñas a medianas
- **Compatibilidad**: Funciona en Windows, Linux y macOS

**Desarrollado como proyecto educativo de sistemas de chat en tiempo real con Python**