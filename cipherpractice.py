import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)
nonce = os.urandom(12)


print('data: ' + str(data))

ct = nonce + aesgcm.encrypt(nonce, data, aad) 

print('nonce = ' + str(nonce))
print('ct = ' + str(ct))
print('should be nonce: ' + str(ct[:12]))
original = aesgcm.decrypt(ct[:12], ct[12:], aad)
print('should be data: ' + str(data))
