# ChatSSL - Sistema de Chat Seguro

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
   git clone https://github.com/j-liszt/chat-ssl
   cd chat-ssl
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

## 🔒 Seguridad y Cifrado

### Arquitectura de Seguridad Multicapa

El sistema ChatSSL implementa múltiples capas de seguridad para garantizar la confidencialidad e integridad de las comunicaciones:

#### 1. Cifrado SSL/TLS (Capa de Transporte)

**Generación Automática de Certificados:**
```python
# El servidor genera automáticamente certificados SSL auto-firmados
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cert = x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .sign(key, hashes.SHA256())
```

**Características del Certificado SSL:**
- **Algoritmo**: RSA 2048 bits
- **Hash**: SHA-256
- **Validez**: 365 días
- **SAN**: Incluye localhost para desarrollo local
- **Archivos generados**: `cert.pem` (certificado público) y `key.pem` (clave privada)

**Implementación HTTPS:**
- **Puerto 8080**: Servidor de chat con SSL/TLS
- **Puerto 8081**: API REST con SSL/TLS
- **Handshake SSL**: Verificación automática en cada conexión
- **Contexto SSL**: `ssl.create_default_context()` con configuración segura

#### 2. Cifrado Fernet (Capa de Aplicación)

**Generación y Gestión de Claves:**
```python
# Clave Fernet de 256 bits generada automáticamente
key = Fernet.generate_key()  # 44 caracteres en base64
cipher_suite = Fernet(key)
```

**Almacenamiento Seguro de la Clave:**
- La clave se almacena en el archivo `.env` como `FERNET_KEY`
- Si no existe, se genera automáticamente una nueva clave
- **Importante**: La misma clave debe usarse para mantener acceso a datos históricos

**Cifrado de Mensajes en Tiempo Real:**
```python
# Los mensajes se cifran antes de enviarse entre clientes
encrypted_data = cipher_suite.encrypt(message.encode('utf-8'))
client.send(encrypted_data)

# Y se descifran al recibirlos
decrypted_data = cipher_suite.decrypt(data).decode('utf-8')
```

#### 3. Cifrado de Base de Datos

**Estructura de Datos Cifrados:**
La base de datos JSON (`chat_data.json`) almacena toda la información cifrada:

```json
{
  "rooms": {"General": []},
  "blocked_ips": ["192.168.1.100"],
  "chat_history": {
    "General": [
      {
        "ip": "127.0.0.1",
        "nickname": "Usuario1",
        "message": "gAAAAABh..." // Mensaje cifrado con Fernet
        "timestamp": "2024-01-15T10:30:00"
      }
    ]
  }
}
```

**Proceso de Cifrado de Datos:**
1. **Escritura**: Los datos se serializan a JSON, se cifran con Fernet y se escriben como binario
2. **Lectura**: Los datos binarios se descifran, se deserializan desde JSON
3. **Integridad**: Fernet incluye verificación de integridad automática

```python
# Guardado seguro
json_data = json.dumps(data).encode('utf-8')
encrypted_data = cipher_suite.encrypt(json_data)
with open(DATA_FILE, 'wb') as f:
    f.write(encrypted_data)

# Carga segura
with open(DATA_FILE, 'rb') as f:
    encrypted_data = f.read()
decrypted_data = cipher_suite.decrypt(encrypted_data)
data = json.loads(decrypted_data.decode('utf-8'))
```

#### 4. Flujo Completo de Seguridad

**Conexión de Cliente:**
1. **Handshake SSL**: Establecimiento de canal seguro TLS
2. **Autenticación**: Verificación de certificado del servidor
3. **Cifrado de canal**: Todo el tráfico posterior está cifrado con SSL

**Envío de Mensaje:**
1. **Cliente**: Mensaje en texto plano → Cifrado Fernet → Envío por SSL
2. **Servidor**: Recepción por SSL → Descifrado Fernet → Procesamiento
3. **Almacenamiento**: Mensaje → Cifrado Fernet → Guardado en JSON cifrado
4. **Retransmisión**: Cifrado Fernet → Envío por SSL a otros clientes

**API REST:**
1. **HTTPS**: Todas las peticiones van por SSL/TLS
2. **Descifrado dinámico**: Los mensajes se descifran solo para mostrar
3. **No persistencia**: Los datos descifrados no se almacenan en memoria

#### 5. Características de Seguridad Adicionales

**Validación y Sanitización:**
- Validación de formato de mensajes
- Límites de longitud de datos
- Escape de caracteres especiales

**Control de Acceso:**
- Sistema de bloqueo de IPs
- Validación de conexiones
- Gestión de sesiones activas

**Resistencia a Ataques:**
- **Man-in-the-middle**: Prevenido por SSL/TLS
- **Eavesdropping**: Datos cifrados en tránsito y reposo
- **Data tampering**: Verificación de integridad con Fernet
- **Replay attacks**: Timestamps y nonces en SSL

### Moderación
- **Bloqueo de IPs**: Prevención de acceso a usuarios problemáticos
- **Validación de datos**: Sanitización de entradas de usuario
- **Gestión de sesiones**: Control de conexiones activas

## 📁 Estructura de Archivos

```
chat-ssl/
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
