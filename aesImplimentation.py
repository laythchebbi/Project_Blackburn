# Import the Fernet class.
from cryptography.fernet import Fernet

# Use Fernet to generate the key file.
key = Fernet.generate_key()
# Store the file to disk to be accessed for en/de:crypting later.
with open('secret.key', 'wb') as new_key_file:
    new_key_file.write(key)
print(key)

msg = input("Saisie le text pour chiffre")
# Encode this as bytes to feed into the algorithm.
# (Refer to Encoding types above).
msg = msg.encode()

# Instantiate the object with your key.
f = Fernet(key)
# Pass your bytes type message into encrypt.
ciphertext = f.encrypt(msg)
print(ciphertext)