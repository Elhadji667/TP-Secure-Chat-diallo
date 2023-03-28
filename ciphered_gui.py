import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from basic_gui import BasicGUI


class CipheredGUI(BasicGUI):
    def __init__(self, master=None):
        super().__init__(master)
        self._key = None

    def _create_connection_window(self):
        super()._create_connection_window()
        # Ajout d'un champ pour le mot de passe
        self.password_label = tk.Label(self.conn_win, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self.conn_win, show="*")
        self.password_entry.pack()

    def run_chat(self):
        self._derive_key()
        super().run_chat()
        
    def _derive_key(self, password, salt):
        # Récupération du mot de passe entré par l'utilisateur
        password = self.password_entry.get()
        salt = os.urandom(16)
        backend = default_backend()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )

        self._key = kdf.derive(password.encode())

    def encrypt(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        return iv, encrypted_message

    def decrypt(self, iv_and_encrypted_message):
        iv, encrypted_message = iv_and_encrypted_message
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv),backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_message) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        return decrypted_data.decode("utf-8")

    def send(self, message):
        iv, encrypted_message = self.encrypt(message)
        encrypted_message_base64 = base64.b64encode(encrypted_message).decode()
        iv_base64 = base64.b64encode(iv).decode()
        encrypted_message_and_iv_base64 = f"{iv_base64}:{encrypted_message_base64}"
        super().send(encrypted_message_and_iv_base64)

    def recv(self, message):
        iv_base64, encrypted_message_base64 = message.split(":", 1)
        encrypted_message = base64.b64decode(encrypted_message_base64.encode())
        iv = base64.b64decode(iv_base64.encode())
        decrypted_message = self.decrypt((iv, encrypted_message))
        super().recv(decrypted_message)



    

 
