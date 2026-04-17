import tkinter as tk
from tkinter import messagebox
import socket
import threading
import os
import time

HOST = '127.0.0.1'
PORT = 5000

class ChatClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Chat - Login")
        self.client_socket = None
        self.current_username = None
        self.chatting_with = None
        self.contacts = {}
        self.login_frame = self.create_login_frame()
        self.typing_status_thread = None
        self.is_typing = False
        self.last_key_press_time = 0

    def create_login_frame(self):
        frame = tk.Frame(self.master, padx=10, pady=10)
        frame.pack(padx=10, pady=10)
        
        tk.Label(frame, text="Nome de Usuário:").grid(row=0, column=0, pady=5, sticky="w")
        self.entry_username = tk.Entry(frame)
        self.entry_username.grid(row=0, column=1, pady=5)

        tk.Label(frame, text="Senha:").grid(row=1, column=0, pady=5, sticky="w")
        self.entry_password = tk.Entry(frame, show="*")
        self.entry_password.grid(row=1, column=1, pady=5)

        tk.Button(frame, text="Login", command=self.handle_login).grid(row=2, column=0, pady=10)
        tk.Button(frame, text="Registrar", command=self.handle_register).grid(row=2, column=1, pady=10)
        return frame

    def handle_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        threading.Thread(target=self.login_thread_handler, args=(username, password), daemon=True).start()

    def login_thread_handler(self, username, password):
        if self.connect_to_server():
            message = f"LOGIN|{username}|{password}"
            self.client_socket.sendall(message.encode('utf-8'))
            response = self.client_socket.recv(1024).decode('utf-8')
            
            if response.startswith("LOGIN_OK"):
                self.current_username = username
                self.master.after(0, self.show_chat_window)
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                self.master.after(0, lambda: messagebox.showerror("Login Falhou", response))
                self.client_socket.close()

    def handle_register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        if self.connect_to_server():
            message = f"REGISTER|{username}|{password}"
            self.client_socket.sendall(message.encode('utf-8'))
            response = self.client_socket.recv(1024).decode('utf-8')
            messagebox.showinfo("Registro", response)
            self.client_socket.close()

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            return True
        except socket.error as e:
            self.master.after(0, lambda: messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}"))
            return False

    def get_contacts_list(self):
        message = "GET_CONTACTS"
        if self.client_socket:
            self.client_socket.sendall(message.encode('utf-8'))

    def show_chat_window(self):
        self.login_frame.destroy()
        self.master.title(f"Chat - {self.current_username}")
        self.master.geometry("800x600")

        main_frame = tk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True)

        contacts_frame = tk.Frame(main_frame, width=200, bg="lightgray")
        contacts_frame.pack(side=tk.LEFT, fill=tk.Y)
        contacts_frame.pack_propagate(False)

        tk.Label(contacts_frame, text="Contatos", bg="gray", fg="white", font=("Arial", 12)).pack(fill=tk.X)
        self.contacts_listbox = tk.Listbox(contacts_frame)
        self.contacts_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.contacts_listbox.bind("<<ListboxSelect>>", self.on_contact_select)
        self.get_contacts_list()

        self.chat_history = tk.Text(main_frame, state='disabled', wrap='word')
        self.chat_history.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.typing_label = tk.Label(main_frame, text="", font=("Arial", 10, "italic"))
        self.typing_label.pack()

        message_frame = tk.Frame(self.master)
        message_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.message_entry = tk.Entry(message_frame, font=("Arial", 12))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        self.message_entry.bind("<Key>", self.handle_key_press)
        
        self.send_button = tk.Button(message_frame, text="Enviar", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)
        
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_contact_select(self, event):
        selected_index = self.contacts_listbox.curselection()
        if selected_index:
            self.chatting_with = self.contacts_listbox.get(selected_index[0])
            self.master.title(f"Chat - {self.current_username} (Conversando com {self.chatting_with})")
            self.chat_history.config(state='normal')
            
            self.chat_history.delete('1.0', tk.END)
            
            self.load_chat_history()
            
            self.chat_history.config(state='disabled')

    def send_message(self):
        message = self.message_entry.get()
        if message and self.chatting_with:
            message_to_send = f"MESSAGE|{self.chatting_with}|{message}"
            self.client_socket.sendall(message_to_send.encode('utf-8'))
            self.update_chat_history(f"Você: {message}", True) # Passa True para salvar

            # Ajusta o foco para a entrada de texto e limpa
            self.message_entry.delete(0, tk.END)
            self.send_typing_stop()

    def handle_key_press(self, event):
        if not self.is_typing:
            self.is_typing = True
            self.send_typing()
            self.typing_status_thread = threading.Thread(target=self.typing_timeout_check, daemon=True)
            self.typing_status_thread.start()
        self.last_key_press_time = time.time()

    def typing_timeout_check(self):
        while self.is_typing:
            if time.time() - self.last_key_press_time > 2:
                self.send_typing_stop()
                self.is_typing = False
            time.sleep(0.5)

    def send_typing(self):
        if self.chatting_with:
            message = f"TYPING|{self.chatting_with}"
            self.client_socket.sendall(message.encode('utf-8'))

    def send_typing_stop(self):
        if self.chatting_with:
            message = f"TYPING_STOP|{self.chatting_with}"
            self.client_socket.sendall(message.encode('utf-8'))

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                parts = data.split('|')
                command = parts[0]

                if command == "MESSAGE":
                    sender = parts[1]
                    message = parts[2]
                    self.master.after(0, lambda: self.handle_message_received(sender, message))
                
                elif command == "CONTACTS_LIST":
                    contacts_list_data = parts[1:]
                    formatted_contacts = []
                    for contact_entry in contacts_list_data:
                        username, status = contact_entry.split(':')
                        if username != self.current_username:
                            formatted_contacts.append(contact_entry)
                    self.master.after(0, lambda: self.update_contacts_list(formatted_contacts))

                elif command == "USER_STATUS":
                    username = parts[1]
                    status = parts[2]
                    self.master.after(0, lambda: self.update_contacts_status(username, status))

                elif command == "TYPING":
                    sender = parts[1]
                    self.master.after(0, lambda: self.typing_label.config(text=f"{sender} está digitando..."))
                    
                elif command == "TYPING_STOP":
                    sender = parts[1]
                    self.master.after(0, lambda: self.typing_label.config(text=""))

                elif command == "INFO":
                    self.master.after(0, lambda: messagebox.showinfo("Informação", parts[1]))
                
                elif command == "ERROR":
                    self.master.after(0, lambda: messagebox.showerror("Erro", parts[1]))

            except socket.error:
                break
        self.client_socket.close()

    def handle_message_received(self, sender, message):
        """Processa a mensagem recebida e a salva no histórico, independente da conversa aberta."""
        # Salva a mensagem no histórico do contato
        self.save_chat_history_direct(sender, f"{sender}: {message}")
        
        # Se a conversa com o remetente estiver aberta, atualiza a GUI
        if self.chatting_with == sender:
            self.update_chat_history(f"{sender}: {message}", False) # Passa False para não salvar de novo

    def update_contacts_list(self, contacts_with_status):
        self.contacts_listbox.delete(0, tk.END)
        for contact_with_status in contacts_with_status:
            if ":" in contact_with_status:
                username, status = contact_with_status.split(':', 1)
                color = "green" if status == "online" else "black"
                self.contacts_listbox.insert(tk.END, username)
                self.contacts_listbox.itemconfig(tk.END, {'fg': color})
            else:
                self.contacts_listbox.insert(tk.END, contact_with_status)

    def update_contacts_status(self, username, status):
        # Lógica para atualizar a cor do contato na lista
        pass

    def update_chat_history(self, message, is_sent_message):
        """Atualiza a caixa de texto da conversa e salva a mensagem no arquivo."""
        self.chat_history.config(state='normal')
        self.chat_history.insert(tk.END, message + "\n")
        self.chat_history.config(state='disabled')
        self.chat_history.see(tk.END)
        if is_sent_message:
            self.save_chat_history(self.chatting_with, message)

    def save_chat_history(self, contact, message):
        """Salva a mensagem no arquivo de histórico de um contato específico."""
        file_path = self.get_history_filename(contact)
        with open(file_path, "a") as f:
            f.write(message + "\n")

    def save_chat_history_direct(self, contact, message):
        """Salva a mensagem no arquivo de histórico de um contato específico."""
        file_path = self.get_history_filename(contact) 
        with open(file_path, "a") as f:
            f.write(message + "\n")
            
    def load_chat_history(self):
        """Carrega o histórico de conversa do arquivo."""
        if self.chatting_with:
            file_path = self.get_history_filename(self.chatting_with) 
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    history = f.read()
                    self.chat_history.insert(tk.END, history)

    def on_closing(self):
        if messagebox.askokcancel("Sair", "Tem certeza que deseja sair?"):
            if self.client_socket:
                self.client_socket.sendall("LOGOUT".encode('utf-8'))
                self.client_socket.close()
            self.master.destroy()
    def get_history_filename(self, contact):
        history_dir = "chat_history"
        if not os.path.exists(history_dir):
            os.makedirs(history_dir)
        
        # Ordena os nomes de usuário para criar um nome de arquivo consistente
        usernames = sorted([self.current_username, contact])
        filename = f"{usernames[0]}_{usernames[1]}.txt"
        return os.path.join(history_dir, filename)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()