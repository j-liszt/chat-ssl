import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import socket
import ssl
import threading
import json
import requests
from cryptography.fernet import Fernet
import time
import os
from dotenv import load_dotenv
import urllib3

# Suprimir advertencias SSL para certificados autofirmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cargar clave de cifrado desde .env
load_dotenv()
key = os.getenv('FERNET_KEY')
if not key:
    raise ValueError("FERNET_KEY no encontrada en el archivo .env")
cipher_suite = Fernet(key.encode() if isinstance(key, str) else key)

class ConnectionDialog:
    def __init__(self, parent):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Conectar al Servidor")
        self.dialog.geometry("450x320")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Centrar la ventana
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (450 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (320 // 2)
        self.dialog.geometry(f"450x320+{x}+{y}")
        
        self.create_widgets()
        
    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        title_label = ttk.Label(main_frame, text="Configuración de Conexión", font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # IP del servidor
        ttk.Label(main_frame, text="IP del Servidor:").pack(anchor=tk.W)
        self.ip_entry = ttk.Entry(main_frame, width=30)
        self.ip_entry.pack(fill=tk.X, pady=(5, 10))
        self.ip_entry.insert(0, "localhost")
        
        # Puerto
        ttk.Label(main_frame, text="Puerto:").pack(anchor=tk.W)
        self.port_entry = ttk.Entry(main_frame, width=30)
        self.port_entry.pack(fill=tk.X, pady=(5, 10))
        self.port_entry.insert(0, "8080")
        
        # Nombre de usuario
        ttk.Label(main_frame, text="Nombre de Usuario:").pack(anchor=tk.W)
        self.username_entry = ttk.Entry(main_frame, width=30)
        self.username_entry.pack(fill=tk.X, pady=(5, 20))
        
        # Botones
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Conectar", command=self.connect).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Cancelar", command=self.cancel).pack(side=tk.RIGHT)
        
        # Enfocar el campo de usuario
        self.username_entry.focus()
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.connect())
        
    def connect(self):
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()
        username = self.username_entry.get().strip()
        
        if not ip or not port or not username:
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return
            
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "El puerto debe ser un número entre 1 y 65535")
            return
            
        self.result = {'ip': ip, 'port': port, 'username': username}
        self.dialog.destroy()
        
    def cancel(self):
        self.dialog.destroy()

class ChatClient:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Cliente de Chat")
        self.root.geometry("900x700")
        
        self.socket = None
        self.connected = False
        self.current_room = None
        self.server_ip = None
        self.server_port = None
        self.username = None
        self.api_base_url = None
        
        self.create_widgets()
        self.show_connection_dialog()
        
    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(title_frame, text="Cliente de Chat", font=('Arial', 16, 'bold')).pack(side=tk.LEFT)
        
        # Frame para status y botones de conexión
        connection_frame = ttk.Frame(title_frame)
        connection_frame.pack(side=tk.RIGHT)
        
        self.disconnect_button = ttk.Button(connection_frame, text="Desconectar", command=self.disconnect_from_server)
        self.disconnect_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        self.status_label = ttk.Label(connection_frame, text="Desconectado", foreground="red")
        self.status_label.pack(side=tk.RIGHT)
        
        # Frame de salas
        rooms_frame = ttk.LabelFrame(main_frame, text="Salas Disponibles", padding="10")
        rooms_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Lista de salas con scrollbar
        rooms_list_frame = ttk.Frame(rooms_frame)
        rooms_list_frame.pack(fill=tk.X)
        
        self.rooms_listbox = tk.Listbox(rooms_list_frame, height=4)
        rooms_scrollbar = ttk.Scrollbar(rooms_list_frame, orient=tk.VERTICAL, command=self.rooms_listbox.yview)
        self.rooms_listbox.configure(yscrollcommand=rooms_scrollbar.set)
        
        self.rooms_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rooms_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Botones de sala
        rooms_buttons_frame = ttk.Frame(rooms_frame)
        rooms_buttons_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(rooms_buttons_frame, text="Unirse a Sala", command=self.join_room).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(rooms_buttons_frame, text="Salir de Sala", command=self.leave_room).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(rooms_buttons_frame, text="Actualizar", command=self.refresh_rooms).pack(side=tk.LEFT)
        
        # Frame principal de chat
        chat_frame = ttk.Frame(main_frame)
        chat_frame.pack(fill=tk.BOTH, expand=True)
        
        # Frame izquierdo - Chat
        left_frame = ttk.Frame(chat_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Información de sala actual
        self.room_info_label = ttk.Label(left_frame, text="No hay sala seleccionada", font=('Arial', 12, 'bold'))
        self.room_info_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Área de chat
        self.chat_area = scrolledtext.ScrolledText(left_frame, state=tk.DISABLED, height=15)
        self.chat_area.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Frame de entrada de mensaje
        message_frame = ttk.Frame(left_frame)
        message_frame.pack(fill=tk.X)
        
        self.message_entry = ttk.Entry(message_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        ttk.Button(message_frame, text="Enviar", command=self.send_message).pack(side=tk.RIGHT)
        
        # Frame derecho - Usuarios
        right_frame = ttk.LabelFrame(chat_frame, text="Usuarios Conectados", padding="10")
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        right_frame.configure(width=250)
        right_frame.pack_propagate(False)
        
        # Contador de usuarios
        self.user_count_label = ttk.Label(right_frame, text="0/100", font=('Arial', 12, 'bold'))
        self.user_count_label.pack(pady=(0, 10))
        
        # Lista de usuarios
        users_list_frame = ttk.Frame(right_frame)
        users_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.users_listbox = tk.Listbox(users_list_frame)
        users_scrollbar = ttk.Scrollbar(users_list_frame, orient=tk.VERTICAL, command=self.users_listbox.yview)
        self.users_listbox.configure(yscrollcommand=users_scrollbar.set)
        
        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Deshabilitar controles inicialmente
        self.disable_controls()
        
        # Inicialmente ocultar el botón de desconectar
        self.disconnect_button.config(state=tk.DISABLED)
        
    def show_connection_dialog(self):
        dialog = ConnectionDialog(self.root)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            self.server_ip = dialog.result['ip']
            self.server_port = dialog.result['port']
            self.username = dialog.result['username']
            # Configurar la URL base de la API (puerto del chat + 1)
            chat_port = int(self.server_port)
            api_port = chat_port + 1
            self.api_base_url = f"https://{self.server_ip}:{api_port}"
            self.connect_to_server()
        else:
            # Si no hay resultado y no estamos conectados, cerrar la aplicación
            if not self.connected:
                self.root.quit()
            
    def connect_to_server(self):
        try:
            print(f"Intentando conectar a {self.server_ip}:{self.server_port}")
            
            # Cerrar socket anterior si existe
            if hasattr(self, 'socket') and self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # No establecer timeout para permitir recepción continua
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Conectar primero, luego envolver con SSL
            print("Conectando socket...")
            raw_socket.connect((self.server_ip, self.server_port))
            print("Socket conectado, iniciando SSL handshake...")
            self.socket = context.wrap_socket(raw_socket, server_hostname=self.server_ip)
            print("SSL handshake completado")
            
            # Enviar nickname al servidor
            nickname_command = f"SET_NICKNAME|{self.username}"
            encrypted_command = cipher_suite.encrypt(nickname_command.encode('utf-8'))
            print(f"Enviando comando de nickname: {nickname_command}")
            self.socket.send(encrypted_command)
            print("Comando de nickname enviado")
            
            self.connected = True
            self.status_label.config(text=f"Conectado como {self.username}", foreground="green")
            
            # Habilitar botón de desconectar
            self.disconnect_button.config(state=tk.NORMAL)
            
            # Iniciar hilo para recibir mensajes
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
            # Cargar salas disponibles automáticamente
            self.refresh_rooms()
            
            # Habilitar controles
            self.enable_controls()
            
        except Exception as e:
            print(f"Error de conexión: {e}")
            messagebox.showerror("Error de Conexión", f"No se pudo conectar al servidor: {str(e)}")
            self.show_connection_dialog()
            
    def disconnect_from_server(self):
        """Desconecta del servidor y permite nueva configuración"""
        try:
            # Marcar como desconectado
            self.connected = False
            
            # Cerrar socket si existe
            if hasattr(self, 'socket') and self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            
            # Limpiar estado
            self.current_room = None
            self.server_ip = None
            self.server_port = None
            self.username = None
            self.api_base_url = None
            
            # Actualizar interfaz
            self.status_label.config(text="Desconectado", foreground="red")
            self.disconnect_button.config(state=tk.DISABLED)
            self.room_info_label.config(text="No hay sala seleccionada")
            
            # Limpiar listas
            self.rooms_listbox.delete(0, tk.END)
            self.users_listbox.delete(0, tk.END)
            self.user_count_label.config(text="0/100")
            
            # Limpiar chat
            self.chat_area.config(state=tk.NORMAL)
            self.chat_area.delete(1.0, tk.END)
            self.chat_area.config(state=tk.DISABLED)
            
            # Deshabilitar controles
            self.disable_controls()
            
            # Mostrar diálogo de conexión nuevamente
            self.show_connection_dialog()
            
        except Exception as e:
            print(f"Error al desconectar: {e}")
            messagebox.showerror("Error", f"Error al desconectar: {str(e)}")
            
    def receive_messages(self):
        while self.connected:
            try:
                self.socket.settimeout(1.0)  # Timeout corto para verificar self.connected
                data = self.socket.recv(4096)
                if not data:
                    print("Servidor cerró la conexión")
                    break
                    
                decrypted_data = cipher_suite.decrypt(data).decode('utf-8')
                print(f"Mensaje recibido: {decrypted_data}")
                parts = decrypted_data.split('|')
                command = parts[0]
                
                if command == 'MSG':
                    nickname = parts[1]
                    ip = parts[2]
                    timestamp = parts[3]
                    message = parts[4]
                    # Usar after() para actualizar la GUI desde el hilo principal
                    self.root.after(0, self.display_message, nickname, ip, timestamp, message)
                elif command == 'USERS':
                    users_data = json.loads(parts[1])
                    self.root.after(0, self.update_users_list, users_data)
                    
            except socket.timeout:
                # Timeout normal, continuar el bucle
                continue
            except Exception as e:
                if self.connected:
                    print(f"Error receiving message: {e}")
                break
        print("Hilo de recepción terminado")
                
    def display_message(self, nickname, ip, timestamp, message):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"[{timestamp}] {nickname} ({ip}): {message}\n")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.see(tk.END)
        
    def update_users_list(self, users_data):
        self.users_listbox.delete(0, tk.END)
        
        if 'users' in users_data and 'count' in users_data:
            users = users_data['users']
            count = users_data['count']
            max_users = users_data.get('max_users', 100)
            
            self.user_count_label.config(text=f"{count}/{max_users}")
            
            for user in users:
                nickname = user.get('nickname', 'Anonymous')
                ip = user.get('ip', 'Unknown')
                self.users_listbox.insert(tk.END, f"{nickname} ({ip})")
        
    def refresh_rooms(self):
        if not self.connected:
            return
            
        try:
            response = requests.get(f"{self.api_base_url}/api/rooms", timeout=5, verify=False)
            if response.status_code == 200:
                rooms = response.json()
                self.rooms_listbox.delete(0, tk.END)
                for room in rooms:
                    self.rooms_listbox.insert(tk.END, room)
        except Exception as e:
            print(f"Error refreshing rooms: {e}")
            
    def join_room(self):
        selection = self.rooms_listbox.curselection()
        if not selection:
            messagebox.showwarning("Advertencia", "Selecciona una sala para unirte")
            return
            
        room = self.rooms_listbox.get(selection[0])
        
        try:
            if not self.connected or not self.socket:
                messagebox.showwarning("Advertencia", "No hay conexión con el servidor")
                return
                
            join_command = f"JOIN|{room}"
            encrypted_command = cipher_suite.encrypt(join_command.encode('utf-8'))
            self.socket.send(encrypted_command)
            
            self.current_room = room
            self.room_info_label.config(text=f"Sala actual: {room}")
            
            # Cargar historial de la sala
            self.load_room_history(room)
            
        except Exception as e:
            # Si hay error SSL, intentar reconectar
            if "EOF occurred in violation of protocol" in str(e) or "SSL" in str(e):
                self.reconnect()
            else:
                messagebox.showerror("Error", f"No se pudo unir a la sala: {str(e)}")
            
    def leave_room(self):
        if not self.current_room:
            messagebox.showwarning("Advertencia", "No estás en ninguna sala")
            return
            
        try:
            if self.connected and self.socket:
                leave_command = "LEAVE"
                encrypted_command = cipher_suite.encrypt(leave_command.encode('utf-8'))
                self.socket.send(encrypted_command)
            
            self.current_room = None
            self.room_info_label.config(text="No hay sala seleccionada")
            self.chat_area.config(state=tk.NORMAL)
            self.chat_area.delete(1.0, tk.END)
            self.chat_area.config(state=tk.DISABLED)
            
            self.users_listbox.delete(0, tk.END)
            self.user_count_label.config(text="0/100")
            
        except Exception as e:
            # Si hay error SSL, intentar reconectar
            if "EOF occurred in violation of protocol" in str(e) or "SSL" in str(e):
                self.reconnect()
            else:
                messagebox.showerror("Error", f"No se pudo salir de la sala: {str(e)}")
            
    def load_room_history(self, room):
        try:
            response = requests.get(f"{self.api_base_url}/api/room_history?room={room}", timeout=5, verify=False)
            if response.status_code == 200:
                history = response.json()
                
                self.chat_area.config(state=tk.NORMAL)
                self.chat_area.delete(1.0, tk.END)
                
                for entry in history:
                    nickname = entry.get('nickname', 'Anonymous')
                    ip = entry.get('ip', 'Unknown')
                    message = entry['message']  # Los mensajes ya vienen descifrados de la API
                    timestamp = entry['timestamp'][:19].replace('T', ' ')
                    self.chat_area.insert(tk.END, f"[{timestamp}] {nickname} ({ip}): {message}\n")
                    
                self.chat_area.config(state=tk.DISABLED)
                self.chat_area.see(tk.END)
                
        except Exception as e:
            print(f"Error loading room history: {e}")
            
    def send_message(self):
        if not self.current_room:
            messagebox.showwarning("Advertencia", "Debes unirte a una sala primero")
            return
            
        message = self.message_entry.get().strip()
        if not message:
            return
            
        try:
            if not self.connected or not self.socket:
                messagebox.showwarning("Advertencia", "No hay conexión con el servidor")
                return
                
            msg_command = f"MSG|{message}"
            encrypted_command = cipher_suite.encrypt(msg_command.encode('utf-8'))
            self.socket.send(encrypted_command)
            
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            # Si hay error SSL, intentar reconectar
            if "EOF occurred in violation of protocol" in str(e) or "SSL" in str(e):
                self.reconnect()
            else:
                messagebox.showerror("Error", f"No se pudo enviar el mensaje: {str(e)}")
            
    def enable_controls(self):
        self.rooms_listbox.config(state=tk.NORMAL)
        self.message_entry.config(state=tk.NORMAL)
        
    def disable_controls(self):
        self.rooms_listbox.config(state=tk.DISABLED)
        self.message_entry.config(state=tk.DISABLED)
        
    def reconnect(self):
        """Intenta reconectar al servidor"""
        self.connected = False
        self.status_label.config(text="Reconectando...", foreground="orange")
        
        try:
            # Esperar un momento antes de reconectar
            threading.Timer(2.0, self.connect_to_server).start()
        except Exception as e:
            messagebox.showerror("Error de Reconexión", f"No se pudo reconectar: {str(e)}")
            # Si falla la reconexión, permitir nueva configuración
            self.disconnect_from_server()
    
    def on_closing(self):
        if self.connected and self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.root.quit()
        
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

if __name__ == '__main__':
    client = ChatClient()
    client.run()