import json
import os
import ssl
import socket
import threading
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

import os
from dotenv import load_dotenv

load_dotenv()

# Load encryption key from environment variable or generate a new one
key = os.getenv('FERNET_KEY')

# Validate key length and format
if not key or len(key) != 44:
    new_key = Fernet.generate_key().decode()
    print(f"Warning: No valid FERNET_KEY found in .env, generated a new key: {new_key}. Save this key to .env to persist data.")
    key = new_key
    # Update .env file
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    with open(env_path, 'r') as f:
        lines = f.readlines()
    with open(env_path, 'w') as f:
        key_written = False
        for line in lines:
            if line.startswith('FERNET_KEY='):
                f.write(f"FERNET_KEY={key}\n")
                key_written = True
            else:
                f.write(line)
        if not key_written:
            f.write(f"FERNET_KEY={key}\n")

cipher_suite = Fernet(key.encode() if isinstance(key, str) else key)

DATA_FILE = 'chat_data.json'

# Ensure the data file exists with default content
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump({'rooms': {'General': []}, 'blocked_ips': [], 'chat_history': {}}, f)

from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import urllib.parse

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # socket -> (ip, room, nickname)
        self.rooms = {}  # room_name -> set of sockets
        self.blocked_ips = set()
        self.load_data()

    def load_data(self):
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'rb') as f:
                encrypted_data = f.read()
                try:
                    decrypted_data = cipher_suite.decrypt(encrypted_data)
                    data = json.loads(decrypted_data.decode('utf-8'))
                    # Initialize rooms as empty sets (clients will join at runtime)
                    self.rooms = {room: set() for room in data.get('rooms', {}).keys()}
                    self.blocked_ips = set(data.get('blocked_ips', []))
                    self.chat_history = data.get('chat_history', {})
                except Exception as e:
                    print(f"Failed to decrypt or load data: {e}")
                    self.rooms = {}
                    self.blocked_ips = set()
                    self.chat_history = {}
        else:
            self.rooms = {}
            self.blocked_ips = set()
            self.chat_history = {}
        # Ensure default room "General" exists
        if 'General' not in self.rooms:
            self.rooms['General'] = set()
            self.save_data()


    def save_data(self):
        # Only save room names and blocked IPs, not client sockets
        data = {
            'rooms': {room: [] for room in self.rooms.keys()},  # Just save room names
            'blocked_ips': list(self.blocked_ips),
            'chat_history': self.chat_history
        }
        json_data = json.dumps(data).encode('utf-8')
        encrypted_data = cipher_suite.encrypt(json_data)
        with open(DATA_FILE, 'wb') as f:
            f.write(encrypted_data)

    def start(self):
        # Start REST API server in separate thread
        def run_api_server():
            class RequestHandler(BaseHTTPRequestHandler):
                def _set_headers(self, status=200, content_type='application/json'):
                    self.send_response(status)
                    self.send_header('Content-type', content_type)
                    self.end_headers()

                def do_GET(self):
                    parsed_path = urllib.parse.urlparse(self.path)
                    if parsed_path.path == '/api/rooms':
                        rooms_list = list(self.server.chat_server.rooms.keys())
                        self._set_headers()
                        self.wfile.write(json.dumps(rooms_list).encode('utf-8'))
                    elif parsed_path.path == '/api/blocked_ips':
                        blocked_list = list(self.server.chat_server.blocked_ips)
                        self._set_headers()
                        self.wfile.write(json.dumps(blocked_list).encode('utf-8'))
                    elif parsed_path.path == '/api/room_history':
                        query = urllib.parse.parse_qs(parsed_path.query)
                        room = query.get('room', [None])[0]
                        if room:
                            if room not in self.server.chat_server.chat_history:
                                self.server.chat_server.chat_history[room] = []
                            encrypted_history = self.server.chat_server.chat_history[room]
                            if not encrypted_history:
                                self._set_headers()
                                self.wfile.write(json.dumps([{ "ip": "", "message": "No messages in this room.", "timestamp": "" }]).encode('utf-8'))
                                return
                            # Decrypt messages before sending
                            decrypted_history = []
                            for entry in encrypted_history:
                                try:
                                    decrypted_message = cipher_suite.decrypt(entry['message'].encode('utf-8')).decode('utf-8')
                                    decrypted_entry = {
                                        'ip': entry['ip'],
                                        'nickname': entry.get('nickname', 'Anonymous'),
                                        'message': decrypted_message,
                                        'timestamp': entry['timestamp']
                                    }
                                    decrypted_history.append(decrypted_entry)
                                except Exception as e:
                                    # If decryption fails, skip or include raw
                                    decrypted_history.append(entry)
                            self._set_headers()
                            self.wfile.write(json.dumps(decrypted_history).encode('utf-8'))
                        else:
                            self._set_headers(404)
                            self.wfile.write(json.dumps({'error': 'Room not found or no history'}).encode('utf-8'))
                    elif parsed_path.path == '/api/room_history_dashboard':
                        query = urllib.parse.parse_qs(parsed_path.query)
                        room = query.get('room', [None])[0]
                        if room:
                            if room not in self.server.chat_server.chat_history:
                                self.server.chat_server.chat_history[room] = []
                            encrypted_history = self.server.chat_server.chat_history[room]
                            if not encrypted_history:
                                self._set_headers()
                                self.wfile.write(json.dumps([{ "ip": "", "message": "No messages in this room.", "timestamp": "" }]).encode('utf-8'))
                                return
                            # Decrypt messages for dashboard (show nickname and IP)
                            decrypted_history = []
                            for entry in encrypted_history:
                                try:
                                    decrypted_message = cipher_suite.decrypt(entry['message'].encode('utf-8')).decode('utf-8')
                                    decrypted_entry = {
                                        'ip': entry['ip'],
                                        'nickname': entry.get('nickname', 'Anonymous'),
                                        'message': decrypted_message,
                                        'timestamp': entry['timestamp']
                                    }
                                    decrypted_history.append(decrypted_entry)
                                except Exception as e:
                                    # If decryption fails, skip or include raw
                                    decrypted_history.append(entry)
                            self._set_headers()
                            self.wfile.write(json.dumps(decrypted_history).encode('utf-8'))
                        else:
                            self._set_headers(404)
                            self.wfile.write(json.dumps({'error': 'Room not found or no history'}).encode('utf-8'))
                    elif parsed_path.path == '/api/room_users':
                        query = urllib.parse.parse_qs(parsed_path.query)
                        room = query.get('room', [None])[0]
                        if room and room in self.server.chat_server.rooms:
                            users = []
                            for client in self.server.chat_server.rooms[room]:
                                ip, _, nickname = self.server.chat_server.clients[client]
                                users.append({'ip': ip, 'nickname': nickname or 'Anonymous'})
                            user_count = len(users)
                            self._set_headers()
                            self.wfile.write(json.dumps({'users': users, 'count': user_count, 'max_users': 100}).encode('utf-8'))
                        else:
                            self._set_headers(404)
                            self.wfile.write(json.dumps({'error': 'Room not found'}).encode('utf-8'))
                    else:
                        self._set_headers(404)
                        self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))

                def do_POST(self):
                    parsed_path = urllib.parse.urlparse(self.path)
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    post_params = urllib.parse.parse_qs(post_data)

                    if parsed_path.path == '/api/create_room':
                        room = post_params.get('room', [None])[0]
                        if room:
                            self.server.chat_server.create_room(room)
                            self._set_headers()
                            self.wfile.write(json.dumps({'status': 'ok'}).encode('utf-8'))
                        else:
                            self._set_headers(400)
                            self.wfile.write(json.dumps({'error': 'Missing room parameter'}).encode('utf-8'))
                    elif parsed_path.path == '/api/delete_room':
                        room = post_params.get('room', [None])[0]
                        if room:
                            self.server.chat_server.delete_room(room)
                            self._set_headers()
                            self.wfile.write(json.dumps({'status': 'ok'}).encode('utf-8'))
                        else:
                            self._set_headers(400)
                            self.wfile.write(json.dumps({'error': 'Missing room parameter'}).encode('utf-8'))
                    elif parsed_path.path == '/api/block_ip':
                        ip = post_params.get('ip', [None])[0]
                        if ip:
                            self.server.chat_server.block_ip(ip)
                            self._set_headers()
                            self.wfile.write(json.dumps({'status': 'ok'}).encode('utf-8'))
                        else:
                            self._set_headers(400)
                            self.wfile.write(json.dumps({'error': 'Missing ip parameter'}).encode('utf-8'))
                    elif parsed_path.path == '/api/unblock_ip':
                        ip = post_params.get('ip', [None])[0]
                        if ip:
                            self.server.chat_server.unblock_ip(ip)
                            self._set_headers()
                            self.wfile.write(json.dumps({'status': 'ok'}).encode('utf-8'))
                        else:
                            self._set_headers(400)
                            self.wfile.write(json.dumps({'error': 'Missing ip parameter'}).encode('utf-8'))
                    else:
                        self._set_headers(404)
                        self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))

            api_port = int(os.getenv('PORT', 8080)) + 1  # API en puerto siguiente al chat
            api_server = HTTPServer(('127.0.0.1', api_port), RequestHandler)
            api_server.chat_server = self
            
            # Configurar SSL para el servidor API
            api_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            api_context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
            api_server.socket = api_context.wrap_socket(api_server.socket, server_side=True)
            
            print(f'API server running on https://127.0.0.1:{api_port}')
            api_server.serve_forever()

        threading.Thread(target=run_api_server, daemon=True).start()

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f'Chat server listening on {self.host}:{self.port}')

        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                ip = addr[0]
                print(f"Nueva conexión desde {ip}:{addr[1]}")
                
                if ip in self.blocked_ips:
                    print(f"IP bloqueada: {ip}")
                    client_socket.close()
                    continue
                    
                print(f"Iniciando handshake SSL con {ip}")
                ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
                print(f"SSL handshake exitoso con {ip}")
                threading.Thread(target=self.handle_client, args=(ssl_client_socket, ip)).start()
            except Exception as e:
                print(f"Error en conexión SSL: {e}")

    def handle_client(self, client_socket, ip):
        self.clients[client_socket] = (ip, None, None)  # ip, room, nickname
        print(f"Cliente {ip} conectado exitosamente")
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    print(f"Cliente {ip} desconectado (no data)")
                    break
                print(f"Datos recibidos de {ip}: {len(data)} bytes")
                decrypted_data = cipher_suite.decrypt(data).decode('utf-8')
                print(f"Mensaje descifrado de {ip}: {decrypted_data}")
                self.process_message(client_socket, decrypted_data)
        except Exception as e:
            print(f"Error manejando cliente {ip}: {e}")
        finally:
            print(f"Desconectando cliente {ip}")
            self.disconnect_client(client_socket)

    def process_message(self, client_socket, message):
        # Message format: COMMAND|ARGS
        parts = message.split('|', 1)
        command = parts[0]
        args = parts[1] if len(parts) > 1 else ''

        if command == 'SET_NICKNAME':
            self.set_nickname(client_socket, args)
        elif command == 'JOIN':
            room = args
            self.join_room(client_socket, room)
        elif command == 'LEAVE':
            self.leave_room(client_socket)
        elif command == 'MSG':
            self.send_message(client_socket, args)
        elif command == 'CREATE_ROOM':
            self.create_room(args)
        elif command == 'DELETE_ROOM':
            self.delete_room(args)
        elif command == 'BLOCK_IP':
            self.block_ip(args)
        elif command == 'UNBLOCK_IP':
            self.unblock_ip(args)

    def set_nickname(self, client_socket, nickname):
        ip, room, _ = self.clients[client_socket]
        self.clients[client_socket] = (ip, room, nickname)
        if room:
            self.update_users_in_room(room)
    
    def join_room(self, client_socket, room):
        ip, current_room, nickname = self.clients[client_socket]
        if current_room:
            self.leave_room(client_socket)
        if room not in self.rooms:
            self.rooms[room] = set()
        self.rooms[room].add(client_socket)
        self.clients[client_socket] = (ip, room, nickname)
        self.update_users_in_room(room)

    def leave_room(self, client_socket):
        ip, room, nickname = self.clients[client_socket]
        if room and room in self.rooms:
            self.rooms[room].discard(client_socket)
            self.clients[client_socket] = (ip, None, nickname)
            self.update_users_in_room(room)

    def send_message(self, client_socket, message):
        ip, room, nickname = self.clients[client_socket]
        if not room:
            return
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        encrypted_message = cipher_suite.encrypt(message.encode('utf-8')).decode('utf-8')
        if room not in self.chat_history:
            self.chat_history[room] = []
        self.chat_history[room].append({'ip': ip, 'nickname': nickname or 'Anonymous', 'message': encrypted_message, 'timestamp': timestamp})
        self.save_data()
        for client in self.rooms.get(room, []):
            try:
                display_name = nickname or 'Anonymous'
                formatted_timestamp = timestamp[:19].replace('T', ' ')
                client.send(cipher_suite.encrypt(f'MSG|{display_name}|{ip}|{formatted_timestamp}|{message}'.encode('utf-8')))
            except:
                pass

    def create_room(self, room):
        if room not in self.rooms:
            self.rooms[room] = set()
            self.save_data()

    def delete_room(self, room):
        if room in self.rooms:
            for client in self.rooms[room]:
                ip, _, nickname = self.clients[client]
                self.clients[client] = (ip, None, nickname)
            del self.rooms[room]
            if room in self.chat_history:
                del self.chat_history[room]
            self.save_data()

    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        self.save_data()

    def unblock_ip(self, ip):
        self.blocked_ips.discard(ip)
        self.save_data()

    def update_users_in_room(self, room):
        users = []
        for client in self.rooms.get(room, []):
            ip, _, nickname = self.clients[client]
            users.append({'ip': ip, 'nickname': nickname or 'Anonymous'})
        
        user_count = len(users)
        for client in self.rooms.get(room, []):
            try:
                client.send(cipher_suite.encrypt(f'USERS|{json.dumps({"users": users, "count": user_count})}'.encode('utf-8')))
            except:
                pass

    def disconnect_client(self, client_socket):
        ip, room, nickname = self.clients.get(client_socket, (None, None, None))
        if room and room in self.rooms:
            self.rooms[room].discard(client_socket)
            self.update_users_in_room(room)
        if client_socket in self.clients:
            del self.clients[client_socket]
        client_socket.close()


from dotenv import load_dotenv
import os

load_dotenv()

if __name__ == '__main__':
    import os
    from dotenv import load_dotenv

    load_dotenv()

    # Generate self-signed cert and key if not exist
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False).sign(key, hashes.SHA256(), default_backend())

        with open("key.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open("cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    port = int(os.getenv('PORT', 8080))
    server = ChatServer('127.0.0.1', port)
    server.start()