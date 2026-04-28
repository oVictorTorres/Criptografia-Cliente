import tkinter as tk
from tkinter import messagebox
import socket
import threading
import os
import time
import base64
import json
import re

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac

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
        self.local_aes_key = None 
        
        self.session_aes_key = None
        self.session_hmac_key = None
        self.dh_private_key = None
        self.dh_salt = None
        self.current_session_id = None
        
        self.e2e_keys = {}

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
        threading.Thread(target=self.login_thread_handler, args=(username,), daemon=True).start()

    def sign_challenge(self, nonce_base64):
        priv_path = os.path.join("keys", f"{self.current_username}_priv.pem")
        
        if not os.path.exists(priv_path):
            return None 
            
        with open(priv_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
            
        nonce_bytes = base64.b64decode(nonce_base64)
        signature = private_key.sign(nonce_bytes)
        return base64.b64encode(signature).decode('utf-8')

    def execute_handshake(self):
        self.dh_private_key = x25519.X25519PrivateKey.generate()
        client_pub = self.dh_private_key.public_key()
        
        client_pub_bytes = client_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        self.dh_salt = os.urandom(16)
        
        msg = f"HANDSHAKE|{base64.b64encode(client_pub_bytes).decode('utf-8')}|{base64.b64encode(self.dh_salt).decode('utf-8')}"
        try:
            self.client_socket.sendall(msg.encode('utf-8'))
        except socket.error:
            pass

    def encrypt_and_mac(self, plaintext_bytes, aes_key, hmac_key):
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(ciphertext)
        mac = h.finalize()
        
        return base64.b64encode(nonce).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(mac).decode('utf-8')

    def verify_and_decrypt(self, nonce_b64, ciphertext_b64, mac_b64, aes_key, hmac_key):
        try:
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            mac_recebido = base64.b64decode(mac_b64)
            
            h = hmac.HMAC(hmac_key, hashes.SHA256())
            h.update(ciphertext)
            h.verify(mac_recebido) 
            
            aesgcm = AESGCM(aes_key)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes
        except Exception:
            return None

    def login_thread_handler(self, username):
        if self.connect_to_server():
            self.current_username = username 
            
            message = f"LOGIN_REQUEST|{username}"
            self.client_socket.sendall(message.encode('utf-8'))
            
            try:
                response = self.client_socket.recv(1024).decode('utf-8')
                
                if response.startswith("CHALLENGE"):
                    parts = response.split('|')
                    nonce_base64 = parts[1]
                    signature_base64 = self.sign_challenge(nonce_base64)
                    
                    if signature_base64:
                        msg_resposta = f"LOGIN|{username}|{signature_base64}"
                        self.client_socket.sendall(msg_resposta.encode('utf-8'))
                        
                        final_response = self.client_socket.recv(1024).decode('utf-8')
                        
                        if final_response.startswith("LOGIN_OK") or "LOGIN_OK" in final_response:
                            self.load_or_generate_identity() 
                            self.execute_handshake()
                            self.master.after(0, self.show_chat_window)
                            threading.Thread(target=self.receive_messages, daemon=True).start()
                        else:
                            self.master.after(0, lambda: messagebox.showerror("Login Falhou", final_response))
                            self.client_socket.close()
                    else:
                        self.master.after(0, lambda: messagebox.showerror("Erro", "Chave privada ausente."))
                        self.client_socket.close()
                        
                else:
                    self.master.after(0, lambda: messagebox.showerror("Login Falhou", response))
                    self.client_socket.close()
            except socket.error:
                pass

    def handle_register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        
        self.current_username = username
        self.load_or_generate_identity()
        
        pub_path = os.path.join("keys", f"{username}_pub.pem")
        with open(pub_path, "rb") as f:
            pub_pem = f.read()
            
        public_key = serialization.load_pem_public_key(pub_pem)
        pub_raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pub_b64 = base64.b64encode(pub_raw).decode('utf-8')
        
        if self.connect_to_server():
            message = f"REGISTER|{username}|{password}|{pub_b64}"
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
            mensagem_erro = f"Não foi possível conectar ao servidor: {e}"
            self.master.after(0, lambda: messagebox.showerror("Erro de Conexão", mensagem_erro))
            return False
        
    def load_or_generate_identity(self):
        keys_dir = "keys"
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)

        priv_path = os.path.join(keys_dir, f"{self.current_username}_priv.pem")
        pub_path = os.path.join(keys_dir, f"{self.current_username}_pub.pem")
        aes_path = os.path.join(keys_dir, f"{self.current_username}_aes.key")

        if not os.path.exists(priv_path):
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            with open(priv_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(pub_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            chave_aes = AESGCM.generate_key(bit_length=256)
            with open(aes_path, "wb") as f:
                f.write(chave_aes)
            
        with open(aes_path, "rb") as f:
            self.local_aes_key = f.read()

    def get_contacts_list(self):
        message = "GET_CONTACTS"
        if self.client_socket:
            try:
                self.client_socket.sendall(message.encode('utf-8'))
            except socket.error:
                pass

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
        
        time.sleep(0.5)
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
            
            if self.chatting_with not in self.e2e_keys:
                self.e2e_keys[self.chatting_with] = {'aes': b'0'*32, 'hmac': b'1'*32}

            e2e_aes = self.e2e_keys[self.chatting_with]['aes']
            e2e_hmac = self.e2e_keys[self.chatting_with]['hmac']
            
            nonce_in, cipher_in, mac_in = self.encrypt_and_mac(message.encode('utf-8'), e2e_aes, e2e_hmac)
            inner_payload = f"{nonce_in}|{cipher_in}|{mac_in}"
            
            if self.session_aes_key and self.session_hmac_key:
                outer_content = f"ROUTED_MSG|{self.chatting_with}|{inner_payload}"
                nonce_out, cipher_out, mac_out = self.encrypt_and_mac(outer_content.encode('utf-8'), self.session_aes_key, self.session_hmac_key)
                
                payload_dict = {
                    "nonce_b64": nonce_out,
                    "ciphertext_b64": cipher_out,
                    "mac_b64": mac_out,
                    "recipient": self.chatting_with
                }
                final_msg = f"SECURE_MESSAGE|{json.dumps(payload_dict)}"
            else:
                final_msg = f"MESSAGE|{self.chatting_with}|{message}"
                
            self.client_socket.sendall(final_msg.encode('utf-8'))
            self.update_chat_history(f"Você: {message}", True) 

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
                data = self.client_socket.recv(8192).decode('utf-8')
                if not data:
                    break
                
                pattern = r'(CONTACTS_LIST\||SECURE_MESSAGE\||HANDSHAKE_OK\||MESSAGE\||TYPING_STOP\||TYPING\||INFO\||ERRO\|)'
                parts = re.split(pattern, data)
                
                messages = []
                for i in range(1, len(parts), 2):
                    messages.append(parts[i] + parts[i+1])
                
                for msg_data in messages:
                    msg_data = msg_data.strip()
                    if not msg_data: continue
                    
                    msg_parts = msg_data.split('|')
                    command = msg_parts[0]

                    if command == "SECURE_MESSAGE":
                        sender = msg_parts[1]
                        payload_b64 = msg_parts[2]
                        
                        inner_payload_bytes = base64.b64decode(payload_b64)
                        inner_parts = inner_payload_bytes.decode('utf-8').split('|')
                        
                        if inner_parts[0] == "ROUTED_MSG":
                            nonce_in = inner_parts[2]
                            cipher_in = inner_parts[3]
                            mac_in = inner_parts[4]
                            
                            if sender not in self.e2e_keys:
                                self.e2e_keys[sender] = {'aes': b'0'*32, 'hmac': b'1'*32}
                            
                            e2e_aes = self.e2e_keys[sender]['aes']
                            e2e_hmac = self.e2e_keys[sender]['hmac']
                            
                            plaintext_bytes = self.verify_and_decrypt(nonce_in, cipher_in, mac_in, e2e_aes, e2e_hmac)
                            if plaintext_bytes:
                                plaintext_msg = plaintext_bytes.decode('utf-8')
                                self.master.after(0, lambda s=sender, m=plaintext_msg: self.handle_message_received(s, m))

                    elif command == "HANDSHAKE_OK":
                        server_pub_bytes = base64.b64decode(msg_parts[1])
                        self.current_session_id = msg_parts[2]
                        
                        server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
                        shared_secret = self.dh_private_key.exchange(server_pub)
                        
                        hkdf = HKDF(
                            algorithm=hashes.SHA256(),
                            length=64,
                            salt=self.dh_salt,
                            info=b"session-keys"
                        )
                        key_material = hkdf.derive(shared_secret)
                        
                        self.session_aes_key = key_material[:32]
                        self.session_hmac_key = key_material[32:]

                    elif command == "MESSAGE":
                        sender = msg_parts[1]
                        message = msg_parts[2]
                        self.master.after(0, lambda: self.handle_message_received(sender, message))
                    
                    elif command == "CONTACTS_LIST":
                        contacts_list_data = msg_parts[1:]
                        formatted_contacts = []
                        for contact_entry in contacts_list_data:
                            if ':' in contact_entry:
                                username, status = contact_entry.split(':', 1)
                                if username != self.current_username:
                                    formatted_contacts.append(contact_entry)
                        self.master.after(0, lambda: self.update_contacts_list(formatted_contacts))

                    elif command == "USER_STATUS":
                        username = msg_parts[1]
                        status = msg_parts[2]
                        self.master.after(0, lambda: self.update_contacts_status(username, status))

                    elif command == "TYPING":
                        sender = msg_parts[1]
                        self.master.after(0, lambda: self.typing_label.config(text=f"{sender} está digitando..."))
                        
                    elif command == "TYPING_STOP":
                        sender = msg_parts[1]
                        self.master.after(0, lambda: self.typing_label.config(text=""))

                    elif command == "INFO":
                        self.master.after(0, lambda: messagebox.showinfo("Informação", msg_parts[1]))
                    
                    elif command == "ERRO":
                        self.master.after(0, lambda: messagebox.showerror("Erro do Servidor", msg_parts[1]))

            except socket.error:
                break
        self.client_socket.close()

    def handle_message_received(self, sender, message):
        self.save_chat_history_direct(sender, f"{sender}: {message}")
        if self.chatting_with == sender:
            self.update_chat_history(f"{sender}: {message}", False) 

    def update_contacts_list(self, contacts_with_status):
        selected_contact = None
        if self.contacts_listbox.curselection():
            selected_contact = self.contacts_listbox.get(self.contacts_listbox.curselection())
            
        self.contacts_listbox.delete(0, tk.END)
        for contact_with_status in contacts_with_status:
            if ":" in contact_with_status:
                username, status = contact_with_status.split(':', 1)
                color = "green" if status == "online" else "black"
                self.contacts_listbox.insert(tk.END, username)
                self.contacts_listbox.itemconfig(tk.END, {'fg': color})
                
                if username == selected_contact:
                    idx = self.contacts_listbox.size() - 1
                    self.contacts_listbox.selection_set(idx)
                    self.contacts_listbox.activate(idx)
            else:
                self.contacts_listbox.insert(tk.END, contact_with_status)

    def update_contacts_status(self, username, status):
        pass

    def update_chat_history(self, message, is_sent_message):
        self.chat_history.config(state='normal')
        self.chat_history.insert(tk.END, message + "\n")
        self.chat_history.config(state='disabled')
        self.chat_history.see(tk.END)
        if is_sent_message:
            self.save_chat_history_direct(self.chatting_with, message)

    def save_chat_history_direct(self, contact, message):
        file_path = self.get_history_filename(contact) 
        if self.local_aes_key:
            aesgcm = AESGCM(self.local_aes_key)
            nonce = os.urandom(12)
            texto_cifrado = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
            pacote = base64.b64encode(nonce + texto_cifrado).decode('utf-8')
            with open(file_path, "a") as f:
                f.write(pacote + "\n")
            
    def load_chat_history(self):
        if self.chatting_with:
            file_path = self.get_history_filename(self.chatting_with) 
            if os.path.exists(file_path):
                if self.local_aes_key:
                    aesgcm = AESGCM(self.local_aes_key)
                    with open(file_path, "r") as f:
                        for linha in f:
                            linha = linha.strip()
                            if linha:
                                try:
                                    pacote_bytes = base64.b64decode(linha)
                                    nonce = pacote_bytes[:12]
                                    texto_cifrado = pacote_bytes[12:]
                                    texto_decifrado = aesgcm.decrypt(nonce, texto_cifrado, None)
                                    self.chat_history.insert(tk.END, texto_decifrado.decode('utf-8') + "\n")
                                except Exception:
                                    pass

    def on_closing(self):
        if messagebox.askokcancel("Sair", "Tem certeza que deseja sair?"):
            if self.client_socket:
                try:
                    self.client_socket.sendall("LOGOUT".encode('utf-8'))
                except socket.error:
                    pass
                finally:
                    self.client_socket.close()
            self.master.destroy()
            
    def get_history_filename(self, contact):
        history_dir = "chat_history"
        if not os.path.exists(history_dir):
            os.makedirs(history_dir)
        filename = f"history_{self.current_username}_{contact}.txt"
        return os.path.join(history_dir, filename)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()