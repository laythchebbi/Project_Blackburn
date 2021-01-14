import base64
import rsa

def generate_keys():
    (pubkey, privkey) = rsa.newkeys(2048)
    # print(pubkey)
    # write the public key to a file #
    publickey = open('pubkey.key', 'wb')
    publickey.write(pubkey.save_pkcs1('PEM'))
    publickey.close()
    prkey = open('privkey.key', 'wb')
    prkey.write(privkey.save_pkcs1('PEM'))
    prkey.close()
    return pubkey, privkey


# print(generate_keys()[0])


def rsa_encrypt():
    message = input("input the message to encrypt: ").encode()
    with open('pubkey.key', mode='rb') as file:
        keydata = file.read()
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    crypto = rsa.encrypt(message, pubkey)
    print(base64.b64encode(crypto).decode("latin-1") if base64.encode else crypto)
    # print(crypto)
    with open('privkey.key', mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    decrypted = rsa.decrypt(crypto, privkey).decode()
    


def rsa_decrypt():
    message = input("input the message to decrypt: ")
    message = base64.b64decode(message.encode("latin-1"))
    with open('privkey.key', mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    crypto = rsa.decrypt(message, privkey).decode()
    print(crypto)

generate_keys()
rsa_encrypt()
rsa_decrypt()