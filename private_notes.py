import pickle
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PrivNotes:
    MAX_NOTE_LEN = 2048;

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
        self.kvs = {}
        self.key = b'' 
        self.salt =b''

        #initialization case, data and checksum not provided.
        #only generate the salt this one time.
        if not (data or checksum):
            self.salt = os.urandom(16)
            
            #generate key from password
            kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, 
                         iterations = 2000000) 
            self.key = kdf.derive(bytes(password, 'ascii'))

        #reloading notes case, make sure data and checksum are provided
        elif not data: 
            raise ValueError('Checksum provided but no data.')
        elif not checksum: 
            raise ValueError('Data provided but no checksum.')
        else: 
            #convert data to bytes for processing
            data = bytes.fromhex(data)
            #splice off salt from data
            self.salt = data[-16:]
            data = data[:-16]
            
            #generate key from password
            kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, 
                         iterations = 2000000) 
            self.key = kdf.derive(bytes(password, 'ascii'))

            self.kvs = pickle.loads(data)
        #serialized_data = data
        #checksum_ checksum
        #Verify data 
        #generate salt
        

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
        
        #create checksum 
        digest = hashes.Hash(hashes.SHA256())
        digest.update(serialized_data)
        checksum = digest.finalize()

        #append salt to data
        data = serialized_data + self.salt

        return data.hex(), checksum.hex()

    def get(self, title):
        """Fetches the note associated with a title.
        
        Args:
          title (str) : the title to fetch
        
        Returns: 
          note (str) : the note associated with the requested title if
                           it exists and otherwise None
        """
        if title in self.kvs:
            return self.kvs[title]
        return None

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
    
        self.kvs[title] = note


    def remove(self, title):
        """Removes the note for the requested title from the database.
           
           Args:
             title (str) : the title to remove

           Returns:
             success (bool) : True if the title was removed and False if the title was
                              not found
        """

        if title in self.kvs:
            del self.kvs[title]
            return True

        return False

#helper functions below
    def print_notes(self):
        print("Notes:")
        for item, amount in dct.items():
            print("{} ({})".format(item, amount))

