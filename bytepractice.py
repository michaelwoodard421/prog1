import os
from cryptography.hazmat.primitives import hashes

data = bytes('hello world', 'ascii')
digest = hashes.Hash(hashes.SHA256())
digest.update(data)
hash1 = digest.finalize()
print(hash1)

data2=bytes('hello world', 'ascii')
digest2 = hashes.Hash(hashes.SHA256())
digest2.update(data2)
hash2 = digest2.finalize()
print(hash2)
