# Chiffre collection.json avec un code : AES-256-GCM, clé dérivée par PBKDF2-SHA256.
# Usage : python3 encrypt.py <entrée.json> <sortie.enc.json>   (code dans la variable CARTES_CODE)
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 250_000
code = os.environ["CARTES_CODE"].encode()
salt, iv = os.urandom(16), os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(code)
data = open(sys.argv[1], "rb").read()
ct = AESGCM(key).encrypt(iv, data, None)
b64 = lambda b: base64.b64encode(b).decode()
json.dump({"v": 1, "iter": ITER, "salt": b64(salt), "iv": b64(iv), "data": b64(ct)}, open(sys.argv[2], "w"))
