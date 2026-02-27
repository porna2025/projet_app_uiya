from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
import os
import base64
import json
from datetime import datetime


class CryptoUtils:
    
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int=100000) -> bytes:
        """Dérive une clé depuis un mot de passe"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits pour AES
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def encrypt_file(input_path: str, output_path: str, password: str) -> dict:
        """Chiffre un fichier avec AES-256-CBC"""
        try:
            # Générer salt et IV
            salt = os.urandom(16)
            iv = os.urandom(16)
            
            # Dériver la clé
            key = CryptoUtils.derive_key(password, salt)
            
            # Lire le fichier
            with open(input_path, 'rb') as f:
                plaintext = f.read()
            
            # Chiffrer
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Préparer les données chiffrées
            encrypted_data = {
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(iv).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'algorithm': 'AES-256-CBC',
                'timestamp': datetime.now().isoformat()
            }
            
            # Sauvegarder dans un fichier JSON
            with open(output_path, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
            
            return {
                'success': True,
                'output_path': output_path,
                'original_size': len(plaintext),
                'encrypted_size': len(str(encrypted_data))
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def decrypt_file(input_path: str, output_path: str, password: str) -> dict:
        """Déchiffre un fichier"""
        try:
            # Lire le fichier chiffré
            with open(input_path, 'r') as f:
                encrypted_data = json.load(f)
            
            # Décoder les composants
            salt = base64.b64decode(encrypted_data['salt'])
            iv = base64.b64decode(encrypted_data['iv'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            # Dériver la clé
            key = CryptoUtils.derive_key(password, salt)
            
            # Déchiffrer
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Enlever le padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Sauvegarder le fichier déchiffré
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            return {
                'success': True,
                'output_path': output_path,
                'size': len(plaintext)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def generate_aes_key() -> str:
        """Génère une clé AES sécurisée"""
        return base64.b64encode(os.urandom(32)).decode()
    
    @staticmethod
    def generate_rsa_keypair() -> dict:
        """Génère une paire de clés RSA"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_pem.decode(),
            'public_key': public_pem.decode()
        }
    
    @staticmethod
    def encrypt_text(text: str, password: str) -> str:
        """Chiffre du texte"""
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = CryptoUtils.derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(text.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        
        encrypted_data = {
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode()
        }
        
        return json.dumps(encrypted_data)
    
    @staticmethod
    def decrypt_text(encrypted_text: str, password: str) -> str:
        """Déchiffre du texte"""
        try:
            encrypted_data = json.loads(encrypted_text)
            
            salt = base64.b64decode(encrypted_data['salt'])
            iv = base64.b64decode(encrypted_data['iv'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            key = CryptoUtils.derive_key(password, salt)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_text = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            text = unpadder.update(padded_text) + unpadder.finalize()
            
            return text.decode()
        except Exception:
            return "Erreur de déchiffrement - Mot de passe incorrect ou données corrompues"
    
    @staticmethod
    def validate_password(password: str) -> tuple:
        """Valide la force d'un mot de passe"""
        if not password or len(password) < 12:
            return False, "Le mot de passe doit contenir au moins 12 caractères"
        
        checks = {
            'minuscule': any(c.islower() for c in password),
            'majuscule': any(c.isupper() for c in password),
            'chiffre': any(c.isdigit() for c in password),
            'spécial': any(not c.isalnum() for c in password)
        }
        
        if sum(checks.values()) < 3:
            return False, "Le mot de passe doit contenir au moins 3 types de caractères différents"
        
        return True, "Mot de passe valide"
