import os
msg = 'hello world'
#add 5 bytes padding
msg += "\0"*5
msg_bytes = bytes(msg, 'ascii')
print('padded msg: ' + str(msg_bytes))
#unpad
msg = msg.rstrip('\x00')
msg_bytes = bytes(msg, 'ascii')
print('unpadded msg: ' + str(msg_bytes))
