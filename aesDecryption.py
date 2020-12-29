from cryptography.fernet import Fernet
# Load the private key from a file.
with open('secret.key', 'rb') as my_private_key:
    key = my_private_key.read()
# Instantiate Fernet on the recip system.
f = Fernet(key)
ciphertext = input(b"Saisie le cipher ")
# Decrypt the message.
cleartext = f.decrypt(ciphertext)
# Decode the bytes back into a string.
cleartext = cleartext.decode()
print(cleartext)