import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import requests
import json
from threading import Thread
import time
import subprocess
import os
import urllib3

# Suprimir advertencias SSL para certificados autofirmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ChatDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Server Dashboard")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Configurar la URL base de la API basada en el puerto del .env
        chat_port = int(os.getenv('PORT', 8080))
        api_port = chat_port + 1
        self.api_base = f"https://127.0.0.1:{api_port}/api"
        
        # Server control variables
        self.server_process = None
        self.server_running = False
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Chat Server Dashboard", font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Server control (centered below title)
        server_control_frame = ttk.Frame(main_frame)
        server_control_frame.grid(row=1, column=0, columnspan=2, pady=(0, 20))
        
        self.server_button = ttk.Button(server_control_frame, text="Encender Servidor", command=self.toggle_server)
        self.server_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.server_status_label = ttk.Label(server_control_frame, text="Servidor: Apagado", font=('Arial', 10), foreground='red')
        self.server_status_label.pack(side=tk.LEFT)
        
        # Rooms section
        rooms_frame = ttk.LabelFrame(main_frame, text="Gestión de Salas", padding="10")
        rooms_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        rooms_frame.columnconfigure(0, weight=1)
        rooms_frame.rowconfigure(1, weight=1)
        
        # Rooms buttons
        rooms_buttons_frame = ttk.Frame(rooms_frame)
        rooms_buttons_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.create_room_btn = ttk.Button(rooms_buttons_frame, text="Crear Sala", command=self.create_room, state='disabled')
        self.create_room_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.delete_room_btn = ttk.Button(rooms_buttons_frame, text="Eliminar Sala", command=self.delete_room, state='disabled')
        self.delete_room_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.refresh_rooms_btn = ttk.Button(rooms_buttons_frame, text="Actualizar", command=self.refresh_rooms, state='disabled')
        self.refresh_rooms_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.view_history_btn = ttk.Button(rooms_buttons_frame, text="Ver Historial", command=self.view_room_history, state='disabled')
        self.view_history_btn.pack(side=tk.LEFT)
        
        # Rooms listbox
        rooms_list_frame = ttk.Frame(rooms_frame)
        rooms_list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        rooms_list_frame.columnconfigure(0, weight=1)
        rooms_list_frame.rowconfigure(0, weight=1)
        
        self.rooms_listbox = tk.Listbox(rooms_list_frame, font=('Arial', 10), state='disabled')
        self.rooms_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        rooms_scrollbar = ttk.Scrollbar(rooms_list_frame, orient="vertical", command=self.rooms_listbox.yview)
        rooms_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.rooms_listbox.configure(yscrollcommand=rooms_scrollbar.set)
        
        # Blocked IPs section
        blocked_frame = ttk.LabelFrame(main_frame, text="IPs Bloqueadas", padding="10")
        blocked_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        blocked_frame.columnconfigure(0, weight=1)
        blocked_frame.rowconfigure(1, weight=1)
        
        # Blocked IPs buttons
        blocked_buttons_frame = ttk.Frame(blocked_frame)
        blocked_buttons_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.block_ip_btn = ttk.Button(blocked_buttons_frame, text="Bloquear IP", command=self.block_ip, state='disabled')
        self.block_ip_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.unblock_ip_btn = ttk.Button(blocked_buttons_frame, text="Desbloquear IP", command=self.unblock_ip, state='disabled')
        self.unblock_ip_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.refresh_blocked_btn = ttk.Button(blocked_buttons_frame, text="Actualizar", command=self.refresh_blocked_ips, state='disabled')
        self.refresh_blocked_btn.pack(side=tk.LEFT)
        
        # Blocked IPs listbox
        blocked_list_frame = ttk.Frame(blocked_frame)
        blocked_list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        blocked_list_frame.columnconfigure(0, weight=1)
        blocked_list_frame.rowconfigure(0, weight=1)
        
        self.blocked_listbox = tk.Listbox(blocked_list_frame, font=('Arial', 10), state='disabled')
        self.blocked_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        blocked_scrollbar = ttk.Scrollbar(blocked_list_frame, orient="vertical", command=self.blocked_listbox.yview)
        blocked_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.blocked_listbox.configure(yscrollcommand=blocked_scrollbar.set)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Listo")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Don't load initial data or start auto-refresh until server is running
        self.status_var.set("Servidor apagado - Presiona 'Encender Servidor' para comenzar")
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def toggle_server(self):
        """Toggle server on/off"""
        if self.server_running:
            self.stop_server()
        else:
            self.start_server()
    
    def start_server(self):
        """Start the chat server"""
        try:
            # Start the server process (minimized window)
            startupinfo = None
            if os.name == 'nt':  # Windows
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 2  # SW_SHOWMINIMIZED = 2
            
            self.server_process = subprocess.Popen(
                ['python', 'backend_chat_server.py'],
                cwd=os.getcwd(),
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0,
                startupinfo=startupinfo
            )
            
            self.server_running = True
            self.server_button.config(text="Apagar Servidor")
            self.server_status_label.config(text="Servidor: Encendido", foreground='green')
            self.status_var.set("Servidor iniciado exitosamente")
            
            # Enable all controls
            self.enable_controls()
            
            # Wait a moment for server to start, then load data
            self.root.after(3000, self.initial_load)
            
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo iniciar el servidor: {str(e)}")
            self.status_var.set(f"Error al iniciar servidor: {str(e)}")
    
    def stop_server(self):
        """Stop the chat server"""
        try:
            if self.server_process:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                self.server_process = None
            
            self.server_running = False
            self.server_button.config(text="Encender Servidor")
            self.server_status_label.config(text="Servidor: Apagado", foreground='red')
            self.status_var.set("Servidor detenido")
            
            # Disable all controls
            self.disable_controls()
            
            # Clear lists
            self.rooms_listbox.config(state='normal')
            self.blocked_listbox.config(state='normal')
            self.rooms_listbox.delete(0, tk.END)
            self.blocked_listbox.delete(0, tk.END)
            self.rooms_listbox.config(state='disabled')
            self.blocked_listbox.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al detener el servidor: {str(e)}")
    
    def enable_controls(self):
        """Enable all dashboard controls"""
        self.create_room_btn.config(state='normal')
        self.delete_room_btn.config(state='normal')
        self.refresh_rooms_btn.config(state='normal')
        self.view_history_btn.config(state='normal')
        self.block_ip_btn.config(state='normal')
        self.unblock_ip_btn.config(state='normal')
        self.refresh_blocked_btn.config(state='normal')
        self.rooms_listbox.config(state='normal')
        self.blocked_listbox.config(state='normal')
    
    def disable_controls(self):
        """Disable all dashboard controls"""
        self.create_room_btn.config(state='disabled')
        self.delete_room_btn.config(state='disabled')
        self.refresh_rooms_btn.config(state='disabled')
        self.view_history_btn.config(state='disabled')
        self.block_ip_btn.config(state='disabled')
        self.unblock_ip_btn.config(state='disabled')
        self.refresh_blocked_btn.config(state='disabled')
        self.rooms_listbox.config(state='disabled')
        self.blocked_listbox.config(state='disabled')
    
    def initial_load(self):
        """Load initial data and start auto-refresh"""
        self.refresh_all()
        self.auto_refresh()
    
    def auto_refresh(self):
        """Auto refresh data every 30 seconds"""
        def refresh_loop():
            while True:
                time.sleep(30)
                if self.server_running:
                    try:
                        self.refresh_all()
                    except:
                        pass
        
        Thread(target=refresh_loop, daemon=True).start()
    
    def make_request(self, method, endpoint, data=None):
        """Make HTTPS request to the API"""
        try:
            url = f"{self.api_base}{endpoint}"
            if method == 'GET':
                response = requests.get(url, timeout=5, verify=False)
            elif method == 'POST':
                response = requests.post(url, data=data, timeout=5, verify=False)
            
            if response.status_code == 200:
                return response.json()
            else:
                self.status_var.set(f"Error: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            self.status_var.set(f"Error de conexión: {str(e)}")
            return None
    
    def refresh_rooms(self):
        """Refresh rooms list"""
        self.status_var.set("Actualizando salas...")
        rooms = self.make_request('GET', '/rooms')
        if rooms is not None:
            self.rooms_listbox.delete(0, tk.END)
            for room in rooms:
                self.rooms_listbox.insert(tk.END, room)
            self.status_var.set(f"Salas actualizadas: {len(rooms)} salas")
    
    def refresh_blocked_ips(self):
        """Refresh blocked IPs list"""
        self.status_var.set("Actualizando IPs bloqueadas...")
        blocked_ips = self.make_request('GET', '/blocked_ips')
        if blocked_ips is not None:
            self.blocked_listbox.delete(0, tk.END)
            for ip in blocked_ips:
                self.blocked_listbox.insert(tk.END, ip)
            self.status_var.set(f"IPs actualizadas: {len(blocked_ips)} IPs bloqueadas")
    
    def refresh_all(self):
        """Refresh all data"""
        self.refresh_rooms()
        self.refresh_blocked_ips()
    
    def create_room(self):
        """Create a new room"""
        room_name = simpledialog.askstring("Crear Sala", "Nombre de la nueva sala:")
        if room_name:
            room_name = room_name.strip()
            if room_name:
                result = self.make_request('POST', '/create_room', {'room': room_name})
                if result:
                    self.status_var.set(f"Sala '{room_name}' creada exitosamente")
                    self.refresh_rooms()
                else:
                    messagebox.showerror("Error", "No se pudo crear la sala")
    
    def delete_room(self):
        """Delete selected room"""
        selection = self.rooms_listbox.curselection()
        if not selection:
            messagebox.showwarning("Advertencia", "Selecciona una sala para eliminar")
            return
        
        room_name = self.rooms_listbox.get(selection[0])
        
        # Confirm deletion
        if messagebox.askyesno("Confirmar", f"¿Estás seguro de que quieres eliminar la sala '{room_name}'?"):
            result = self.make_request('POST', '/delete_room', {'room': room_name})
            if result:
                self.status_var.set(f"Sala '{room_name}' eliminada exitosamente")
                self.refresh_rooms()
            else:
                messagebox.showerror("Error", "No se pudo eliminar la sala")
    
    def view_room_history(self):
        """View history of selected room"""
        selection = self.rooms_listbox.curselection()
        if not selection:
            messagebox.showwarning("Advertencia", "Selecciona una sala para ver el historial")
            return
        
        room_name = self.rooms_listbox.get(selection[0])
        history = self.make_request('GET', f'/room_history_dashboard?room={room_name}')
        
        if history is not None:
            # Create history window
            history_window = tk.Toplevel(self.root)
            history_window.title(f"Historial de la sala: {room_name}")
            history_window.geometry("600x400")
            
            # Create text widget with scrollbar
            text_frame = ttk.Frame(history_window)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            text_widget = tk.Text(text_frame, wrap=tk.WORD, font=('Arial', 10))
            scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)
            
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Insert history
            for entry in history:
                timestamp = entry.get('timestamp', 'N/A')
                nickname = entry.get('nickname', 'Anonymous')
                ip = entry.get('ip', 'Unknown')
                message = entry.get('message', 'N/A')
                text_widget.insert(tk.END, f"[{timestamp}] {nickname} ({ip}): {message}\n")
            
            text_widget.config(state=tk.DISABLED)
    
    def block_ip(self):
        """Block an IP address"""
        ip = simpledialog.askstring("Bloquear IP", "Dirección IP a bloquear:")
        if ip:
            ip = ip.strip()
            if ip:
                result = self.make_request('POST', '/block_ip', {'ip': ip})
                if result:
                    self.status_var.set(f"IP '{ip}' bloqueada exitosamente")
                    self.refresh_blocked_ips()
                else:
                    messagebox.showerror("Error", "No se pudo bloquear la IP")
    
    def unblock_ip(self):
        """Unblock selected IP address"""
        selection = self.blocked_listbox.curselection()
        if not selection:
            messagebox.showwarning("Advertencia", "Selecciona una IP para desbloquear")
            return
        
        ip = self.blocked_listbox.get(selection[0])
        
        # Confirm unblocking
        if messagebox.askyesno("Confirmar", f"¿Estás seguro de que quieres desbloquear la IP '{ip}'?"):
            result = self.make_request('POST', '/unblock_ip', {'ip': ip})
            if result:
                self.status_var.set(f"IP '{ip}' desbloqueada exitosamente")
                self.refresh_blocked_ips()
            else:
                messagebox.showerror("Error", "No se pudo desbloquear la IP")

    def on_closing(self):
        """Handle application closing"""
        if self.server_running:
            if messagebox.askokcancel("Cerrar", "El servidor está ejecutándose. ¿Deseas detenerlo y cerrar la aplicación?"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    root = tk.Tk()
    app = ChatDashboard(root)
    root.mainloop()

if __name__ == "__main__":
    main()