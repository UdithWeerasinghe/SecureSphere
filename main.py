from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding

app = FastAPI()
keys = {}  # Dictionary to store keys
rsa_keys = {}  # Dictionary to store RSA keys

SUPPORTED_ALGORITHMS = {
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
    "SHA-1": hashlib.sha1,
    "MD5": hashlib.md5,
    "SHA-224": hashlib.sha224,
    "SHA-384": hashlib.sha384,
    "BLAKE2b": hashlib.blake2b,
    "BLAKE2s": hashlib.blake2s
}

class KeyRequest(BaseModel):
    key_type: str
    key_size: int

class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str

class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str

class HashRequest(BaseModel):
    data: str
    algorithm: str

class VerifyHashRequest(BaseModel):
    data: str
    hash_value: str
    algorithm: str

@app.post("/generate-key")
def generate_key(request: KeyRequest):
    if request.key_type == 'AES' and request.key_size in [128, 192, 256]:
        key = os.urandom(request.key_size // 8)
        key_id = str(len(keys) + 1)
        keys[key_id] = key
        return {"key_id": key_id, "key_value": base64.b64encode(key).decode()}
    elif request.key_type == 'RSA':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=request.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        key_id = str(len(rsa_keys) + 1)
        rsa_keys[key_id] = (private_key, public_key)
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {"key_id": key_id, "public_key": pem_public_key.decode()}
    raise HTTPException(status_code=400, detail="Unsupported key type or size")

@app.post("/encrypt")
def encrypt(request: EncryptRequest):
    if request.algorithm == "AES":
        if request.key_id not in keys:
            raise HTTPException(status_code=400, detail="Invalid key ID")
        key = keys[request.key_id]
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_plaintext = padder.update(request.plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return {"ciphertext": base64.b64encode(iv + ciphertext).decode()}
    elif request.algorithm == "RSA":
        if request.key_id not in rsa_keys:
            raise HTTPException(status_code=400, detail="Invalid key ID")
        public_key = rsa_keys[request.key_id][1]
        ciphertext = public_key.encrypt(
            request.plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"ciphertext": base64.b64encode(ciphertext).decode()}
    raise HTTPException(status_code=400, detail="Unsupported encryption algorithm")

@app.post("/decrypt")
def decrypt(request: DecryptRequest):
    if request.algorithm == "AES":
        if request.key_id not in keys:
            raise HTTPException(status_code=400, detail="Invalid key ID")
        key = keys[request.key_id]
        ciphertext = base64.b64decode(request.ciphertext)
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        return {"plaintext": plaintext.decode()}
    elif request.algorithm == "RSA":
        if request.key_id not in rsa_keys:
            raise HTTPException(status_code=400, detail="Invalid key ID")
        private_key = rsa_keys[request.key_id][0]
        decrypted_text = private_key.decrypt(
            base64.b64decode(request.ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"plaintext": decrypted_text.decode()}
    raise HTTPException(status_code=400, detail="Unsupported decryption algorithm")

@app.post("/generate-hash")
def generate_hash(request: HashRequest):
    if request.algorithm in SUPPORTED_ALGORITHMS:
        digest = SUPPORTED_ALGORITHMS[request.algorithm](request.data.encode()).digest()
    else:
        raise HTTPException(status_code=400, detail="Unsupported hashing algorithm")
    return {"hash_value": base64.b64encode(digest).decode(), "algorithm": request.algorithm}

@app.post("/verify-hash")
def verify_hash(request: VerifyHashRequest):
    provided_hash = base64.b64decode(request.hash_value)
    if request.algorithm in SUPPORTED_ALGORITHMS:
        expected_hash = SUPPORTED_ALGORITHMS[request.algorithm](request.data.encode()).digest()
    else:
        raise HTTPException(status_code=400, detail="Unsupported hashing algorithm")
    is_valid = provided_hash == expected_hash
    return {"is_valid": is_valid, "message": "Hash matches the data." if is_valid else "Hash does not match."}
