import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import os
import time
import psutil

class FileEncryptorDecryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor/Decryptor")

        self.file_label = tk.Label(root, text="Select File:")
        self.file_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.file_entry = tk.Entry(root, width=40, state="disabled")
        self.file_entry.grid(row=0, column=1, padx=10, pady=10)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=10, pady=10)

        self.password_label = tk.Label(root, text="Enter Password:")
        self.password_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

        self.password_entry = tk.Entry(root, show="*", width=40)
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        self.algo_label = tk.Label(root, text="Select Algorithm:")
        self.algo_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")

        self.algo_var = tk.StringVar()
        self.algo_var.set("AES-256")  # Default algorithm

        self.algo_menu = tk.OptionMenu(root, self.algo_var, "AES-256", "3DES", "RSA")
        self.algo_menu.grid(row=2, column=1, padx=10, pady=10)

        self.encrypt_button = tk.Button(root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.grid(row=3, column=1, pady=20)

        self.decrypt_button = tk.Button(root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.grid(row=4, column=1, pady=20)

        # Workspace for displaying information
        self.workspace = tk.Text(root, height=10, width=70)
        self.workspace.grid(row=5, column=0, columnspan=3, padx=10, pady=10)
        self.workspace.config(state="disabled")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_entry.config(state="normal")
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)
        self.file_entry.config(state="disabled")

    def update_workspace(self, message):
        self.workspace.config(state="normal")
        self.workspace.insert(tk.END, message + "\n")
        self.workspace.config(state="disabled")

    def encrypt_file(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()

        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])

        if not output_path:
            return

        algorithm = self.algo_var.get()
        start_time = time.time()

        logs = f"Encryption Information:\nFile: {file_path}\nAlgorithm: {algorithm}\n"

        if algorithm == "AES-256":
            self.encrypt_aes(file_path, output_path, password, logs)
        elif algorithm == "3DES":
            self.encrypt_3des(file_path, output_path, password, logs)
        elif algorithm == "RSA":
            self.encrypt_rsa(file_path, output_path, password, logs)

        end_time = time.time()
        time_taken = round(end_time - start_time, 2)
        memory_used = round(psutil.Process().memory_info().rss / (1024 * 1024), 2)

        logs += f"Memory Used (MB): {memory_used}\nTime Taken (seconds): {time_taken}\n\n"
        self.update_workspace(logs)

    def decrypt_file(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()

        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".dec", filetypes=[("Decrypted files", "*.dec")])

        if not output_path:
            return

        algorithm = self.algo_var.get()
        start_time = time.time()

        logs = f"Decryption Information:\nFile: {file_path}\nAlgorithm: {algorithm}\n"

        if algorithm == "AES-256":
            self.decrypt_aes(file_path, output_path, password, logs)
        elif algorithm == "3DES":
            self.decrypt_3des(file_path, output_path, password, logs)
        elif algorithm == "RSA":
            self.decrypt_rsa(file_path, output_path, password, logs)

        end_time = time.time()
        time_taken = round(end_time - start_time, 2)
        memory_used = round(psutil.Process().memory_info().rss / (1024 * 1024), 2)

        logs += f"Memory Used (MB): {memory_used}\nTime Taken (seconds): {time_taken}\n\n"
        self.update_workspace(logs)

    def encrypt_aes(self, file_path, output_path, password, logs):
        key = self.derive_key(password)
        cipher = AES.new(key, AES.MODE_CBC)

        with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            outfile.write(cipher.iv)
            while True:
                chunk = infile.read(1024)
                if len(chunk) == 0:
                    break
                elif len(chunk) % AES.block_size != 0:
                    chunk = pad(chunk, AES.block_size)
                outfile.write(cipher.encrypt(chunk))

        logs += "Status: File encrypted successfully!"
        self.update_workspace(logs)

    def decrypt_aes(self, file_path, output_path, password, logs):
        key = self.derive_key(password)
        with open(file_path, 'rb') as infile:
            iv = infile.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            with open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(1024)
                    if len(chunk) == 0:
                        break
                    outfile.write(unpad(cipher.decrypt(chunk), AES.block_size))

        logs += "Status: File decrypted successfully!"
        self.update_workspace(logs)

    def encrypt_3des(self, file_path, output_path, password, logs):
        key = self.derive_key(password)[:24]
        cipher = DES3.new(key, DES3.MODE_CBC)

        with open(file_path, 'rb') as infile:
            data = infile.read()
            if len(data) % DES3.block_size != 0:
                data = pad(data, DES3.block_size)

            with open(output_path, 'wb') as outfile:
                outfile.write(cipher.iv)
                outfile.write(cipher.encrypt(data))

        logs += "Status: File encrypted successfully!"
        self.update_workspace(logs)

    def decrypt_3des(self, file_path, output_path, password, logs):
        key = self.derive_key(password)[:24]
        with open(file_path, 'rb') as infile:
            iv = infile.read(DES3.block_size)
            cipher = DES3.new(key, DES3.MODE_CBC, iv)

            with open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(1024)
                    if len(chunk) == 0:
                        break
                    outfile.write(unpad(cipher.decrypt(chunk), DES3.block_size))

        logs += "Status: File decrypted successfully!"
        self.update_workspace(logs)

    def encrypt_rsa(self, file_path, output_path, password, logs):
        key = RSA.generate(2048)
        public_key = key.publickey()

        with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            session_key = self.derive_key(password)
            cipher_rsa = PKCS1_OAEP.new(public_key)
            outfile.write(cipher_rsa.encrypt(session_key))
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            outfile.write(cipher_aes.nonce)
            while True:
                chunk = infile.read(1024)
                if len(chunk) == 0:
                    break
                outfile.write(cipher_aes.encrypt(chunk))

        logs += "Status: File encrypted successfully!"
        self.update_workspace(logs)

    def decrypt_rsa(self, file_path, output_path, password, logs):
        key = RSA.generate(2048)
        with open(file_path, 'rb') as infile:
            private_key = key.export_key()
            cipher_rsa = PKCS1_OAEP.new(key)
            session_key = cipher_rsa.decrypt(infile.read(256))

            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=infile.read(16))

            with open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(1024)
                    if len(chunk) == 0:
                        break
                    outfile.write(cipher_aes.decrypt(chunk))

        logs += "Status: File decrypted successfully!"
        self.update_workspace(logs)

    def derive_key(self, password):
        return SHA256.new(password.encode()).digest()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorDecryptor(root)
    root.mainloop()
