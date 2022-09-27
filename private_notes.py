import pickle
import sys
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 

class PrivNotes:

    MAX_NOTE_LEN = 2048;

    #helper functions 
    def print_notes(self):
        print("\nNotes:")
        for title, note in self.kvs.items():
            print("Title: " + str(title) + '\n\tNote: ' + str(note))
        print('\n')

    def hash_title(self, title):
        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(bytes(title, 'ascii'))
        hashed_title =  h.finalize()
        return hashed_title

    def __init__(self, password, data = None, checksum = None):
        """Constructor.
        
        Args:
          password (str) : password for accessing the notes
          data (str) [Optional] : a hex-encoded serialized representation to load
                                  (defaults to None, which initializes an empty notes database)
          checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                      possible rollback attacks (defaults to None, in which
                                      case, no rollback protection is guaranteed)

        Raises:
          ValueError : malformed serialized format
        """
        #consider removing these initializations, unnecessary
        self.kvs = {}
        self.key = b'' 
        self.salt =b''
        self.nonce = b'' 
        self.password = ''

        #initialization case, data and checksum not provided.
        #only generate the salt this one time.
        if not (data or checksum):
            self.salt = os.urandom(16)
            zero_int = 0
            self.nonce = zero_int.to_bytes(16, sys.byteorder)

            #generate key from password
            kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, 
                         iterations = 2000000) 
            og_key = kdf.derive(bytes(password, 'ascii'))
            
            #split og key in half to make separate hmac and enc keys
            self.enc_key = og_key[:int(len(og_key)/2)] 
            self.hmac_key = og_key[int(len(og_key)/2):]
            self.cipher = AESGCM(self.enc_key)

        #reloading notes case, make sure data and checksum are provided
        elif not data: 
            raise ValueError('Checksum provided but no data.')
        elif not checksum: 
            raise ValueError('Data provided but no checksum.')
        else: 
            #convert data to bytes for processing
            data = bytes.fromhex(data)
            checksum = bytes.fromhex(checksum)

            #verify data 
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            calculated_hash = digest.finalize()

            if calculated_hash != checksum:
                raise ValueError('Checksum does not match, serialized data has been tampered with.')

            #splice off salt and nonce from data
            self.salt = data[-32:-16]
            self.nonce = data[-16:]
            data = data[:-32]
            
            #generate key from password
            kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, 
                         iterations = 2000000) 
            og_key = kdf.derive(bytes(password, 'ascii'))

            #split og key in half to make separate hmac and enc keys
            self.enc_key = og_key[:int(len(og_key)/2)] 
            self.hmac_key = og_key[int(len(og_key)/2):]
            self.cipher = AESGCM(self.enc_key)
            
            self.kvs = pickle.loads(data)
        

    def dump(self):
        """Computes a serialized representation of the notes database
           together with a checksum.
        
        Returns: 
          data (str) : a hex-encoded serialized representation of the contents of the notes
                       database (that can be passed to the constructor)
          checksum (str) : a hex-encoded checksum for the data used to protect
                           against rollback attacks (up to 32 characters in length)
        """

        #serialize data 
        serialized_data =  pickle.dumps(self.kvs)
        
        #append salt and nonce to data
        data = serialized_data + self.salt + self.nonce 

        #create checksum (salt and nonce get added so attacker can't change them) 
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        checksum = digest.finalize()

        return data.hex(), checksum.hex()

    def get(self, title):
        """Fetches the note associated with a title.
        
        Args:
          title (str) : the title to fetch
        
        Returns: 
          note (str) : the note associated with the requested title if
                           it exists and otherwise None
        """

        #hash title
        hashed_title = self.hash_title(title)

        #check if title is valid
        if hashed_title not in self.kvs:
            return None

        #nonce at start of ciphertext, message is the rest
        nonce = self.kvs[hashed_title][:16]
        decrypted_note = self.cipher.decrypt(nonce, self.kvs[hashed_title][16:], None).decode('ascii') 
        #unpad
        decrypted_note = decrypted_note.rstrip('\00')
        
        return decrypted_note 

    def set(self, title, note):
        """Associates a note with a title and adds it to the database
           (or updates the associated note if the title is already
           present in the database).
           
           Args:
             title (str) : the title to set
             note (str) : the note associated with the title

           Returns:
             None

           Raises:
             ValueError : if note length exceeds the maximum
        """
        if len(note) > self.MAX_NOTE_LEN:
            raise ValueError('Maximum note length exceeded')

       
        #hash title
        hashed_title = self.hash_title(title)
        
        #pad lengths. zero pad 
        len_diff = self.MAX_NOTE_LEN - len(note) 
        note += "\00"*(len_diff) 
        print(len(note))

        #convert to bytes
        note_bytes = bytes(note, 'ascii')
        
        #increment nonce
        nonce_int = int.from_bytes(self.nonce, sys.byteorder) + 1

        #always should be size 16 bytes
        self.nonce = nonce_int.to_bytes(16, sys.byteorder)

        #encrypt and store message
        ct = self.cipher.encrypt(self.nonce, note_bytes, None)
        self.kvs[hashed_title] = self.nonce + ct

    def remove(self, title):
        """Removes the note for the requested title from the database.
           
           Args:
             title (str) : the title to remove

           Returns:
             success (bool) : True if the title was removed and False if the title was
                              not found
        """
        #hash title
        hashed_title = self.hash_title(title)

        if hashed_title in self.kvs:
            del self.kvs[hashed_title]
            return True

        return False

