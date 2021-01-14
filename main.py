import getpass, base64, hashlib, os.path, re, sqlite3
from  cryptography.fernet import Fernet
from  Crypto.Cipher import DES
from elgamal.elgamal import Elgamal
import base64

import rsa
from pathlib import Path
def generate_keys():
    print("Generating keys...")
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
def RSA_Encryption():
    message = input("input the message to encrypt: ").encode()
    with open('pubkey.key', mode='rb') as file:
        keydata = file.read()
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    crypto = rsa.encrypt(message, pubkey)
    print(base64.b64encode(crypto).decode("latin-1") if base64.encode else crypto)
    
    with open('privkey.key', mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    decrypted = rsa.decrypt(crypto, privkey).decode()
    print(decrypted)
def RSA_Decryption():
    message = input("input the message to Decrypt: ")
    message = base64.b64decode(message.encode("latin-1"))
    with open('privkey.key', mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    crypto = rsa.decrypt(message, privkey).decode()
    print(crypto)

def ElGamal_Encryption():
    m = bytes(input("Saisir le texte a chiffre \n"),encoding="utf-8")
    print(m)
    print("Loading keys...")
    pb, pv = Elgamal.newkeys(32)
    print(pb)
    print(type(pv))
    ct = Elgamal.encrypt(m, pb)
    print(ct)
def ElGamal_Decryption():
    ct = input("Saisir le texte a chiffre \n")
    pv = (input("Saisir le cle prive a chiffre \n"))
    dd = Elgamal.decrypt(ct, pv)
    print(dd)
    print()

def pad(text):
    n = len(text) % 8
    return text + (b' ' * n)
def DES_encryption():
    key = b'hello123'
    text1 = b'Python is the Best Language!'
    des = DES.new(key, DES.MODE_ECB)
    padded_text = pad(text1)
    encrypted_text = des.encrypt(padded_text)
    print(base64.b64encode(encrypted_text).decode("latin-1"))
def DES_decryption():
    key = b'hello123'
    des = DES.new(key, DES.MODE_ECB)
    enc = input()
    enc = base64.b64decode(enc.encode("latin-1"))
    print(des.decrypt(enc))
    
    
regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'

def AES_Encryption():
    # Use Fernet to generate the key file.
    key = Fernet.generate_key()
    # Store the file to disk to be accessed for en/de:crypting later.
    with open('secret.key', 'wb') as new_key_file:
        new_key_file.write(key)
    #print(key)

    msg = input("Saisie le text pour chiffre")
    # Encode this as bytes to feed into the algorithm.
    # (Refer to Encoding types above).
    msg = msg.encode()

    # Instantiate the object with your key.
    f = Fernet(key)
    # Pass your bytes type message into encrypt.
    ciphertext = f.encrypt(msg)
    print(ciphertext)

def AES_Decryption():
    # Load the private key from a file.
    with open('secret.key', 'rb') as my_private_key:
        key = my_private_key.read()
    # Instantiate Fernet on the recip system.
    f = Fernet(key)
    ciphertext = bytes(input("Saisie le cipher "), 'utf-8')
    # Decrypt the message.
    cleartext = f.decrypt(ciphertext)
    # Decode the bytes back into a string.
    cleartext = cleartext.decode()
    print(cleartext)

def login():
    print("Interface de login:\n")
    while True:
        email = input("Saisir votre email\n")
        password = getpass.getpass("Saisir mot de passe\n")
        with sqlite3.connect('mydb3.db') as db:
            cursor = db.cursor()
        find_user = "SELECT * FROM users WHERE email = ? AND password = ?"
        cursor.execute(find_user, [email, password])
        result = cursor.fetchall()
        if result:
            for i in result:
                print("welcome " + i[0])
                menu_principal()
                break
        else:
            print("wrong email or password")

def inscrit():
    verif = True
    while verif:
        email = input("Enter you email \n")
        if check(email) == True:
            break
    password = input("Donner un mot de passe\n")

    with sqlite3.connect('mydb3.db') as db:
        cursor = db.cursor()

    cursor.execute('CREATE TABLE IF NOT EXISTS users (email VARCHAR,password VARCHAR)')

    req = ("""
    INSERT INTO users(email,password) values (?,?)
    """)
    cursor.execute(req, [(email), (password)])
    db.commit()


def check(email):
    if (re.search(regex, email)):
        return True
    else:
        print("Invalid Email")
        return False


#print("To use the application you have to enter you email and password :")
#verif = True
#while verif:
#    email = input("Enter you email ")
#    if check(email) == True:
#        break

#password = getpass.getpass()
# print(""" ____    ___                    __      __
# /\  _`\ /\_ \                  /\ \    /\ \
# \ \ \L\ \//\ \      __      ___\ \ \/'\\ \ \____  __  __  _ __    ___
#  \ \  _ <'\ \ \   /'__`\   /'___\ \ , < \ \ '__`\/\ \/\ \/\`'__\/' _ `\
#   \ \ \L\ \\_\ \_/\ \L\.\_/\ \__/\ \ \\`\\ \ \L\ \ \ \_\ \ \ \/ /\ \/\ \
#    \ \____//\____\ \__/.\_\ \____\\ \_\ \_\ \_,__/\ \____/\ \_\ \ \_\ \_\
#     \/___/ \/____/\/__/\/_/\/____/ \/_/\/_/\/___/  \/___/  \/_/  \/_/\/_/""")


def crackDictionaireSha1():
    res = 0
    dict_file = input("Saire le path de la dictionnaire : \n")
    msg = input("donner")

    with open(dict_file, 'r') as filin:
        lignes = filin.readlines()
        for ligne in lignes:
            mots = ligne.split(" ")
            if msg == mots[1]:
                print(mots[0])
                res = 1
                break
    if res == 0:
        print("Failed to crack the file.\n")


def crackDictionaireMD5():
    res = 0
    dict_file = input("Saire le path de la dictionnaire : \n")
    msg = input("donner\n")

    with open(dict_file, 'r') as filin:
        lignes = filin.readlines()
        for ligne in lignes:
            mots = ligne.split(" ")
            if msg == mots[1]:
                print(mots[0])
                res = 1
                break
    if res == 0:
        print("Failed to crack the file.\n")


def crackDictionaireSHA256():
    res = 0
    dict_file = input("Saire le path de la dictionnaire : \n")
    msg = input("donner\n")

    with open(dict_file, 'r') as filin:
        lignes = filin.readlines()
        for ligne in lignes:
            mots = ligne.split(" ")
            if msg == mots[1]:
                print(mots[0])
                res = 1
                break
    if res == 0:
        print("Failed to crack the file.\n")

def crackDictionaireSHA512():
    res = 0
    dict_file = input("Saire le path de la dictionnaire : \n")
    msg = input("donner\n")

    with open(dict_file, 'r') as filin:
        lignes = filin.readlines()
        for ligne in lignes:
            mots = ligne.split(" ")
            if msg == mots[1]:
                print(mots[0])
                res = 1
                break
    if res == 0:
        print("Failed to crack the file.")


def menu_principal():
    print("Welcome")
    print("""
 ____ ____ ____ ____ ____ ____ ____ ____ ____ 
||B |||l |||a |||c |||k |||b |||u |||r |||n ||
||__|||__|||__|||__|||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|
""")
    print("1 - Codage et decodage d'un message")
    print("2 - Hashage d'un message")
    print("3 - Crackage d'un message hashé")
    print("4 - Chiffrement et dechiffrement symetrique d'un message")
    print("5 - Chffrement et dechiffrement asymetrique d'un message")
    print("Q - Quitter")
    global choix
    choix = input()
    if choix == "1":
        print("Codage et decodage d'un message")
        print("1 - Codage")
        print("2 - Decodage")
        print("0 - Return")
        choix = input()
        if choix == "1":
            print("codage")
            print("Coisir le type de codage ")
            print("1 - Codage Base64")
            choix == input()
            if (choix == "1"):
                msg = input("Sasir le texte a coder\n")
                msgbyte = msg.encode('ascii')
                msgCrypte = base64.b64encode(msgbyte)
                print(msgCrypte)
        elif choix == "2":
            print("decodage")
            print("1 - Decodage base64")
            choix = input("Choisir le type de decodage \n")
            if (choix == "1"):
                base64_message = input("Sasir le texte a decoder : \n")
                base64_bytes = base64_message.encode('ascii')
                message_bytes = base64.b64decode(base64_bytes)
                message = message_bytes.decode('ascii')
                print(message)
        elif choix == "0":
            menu_principal()
        else:
            print("Verifier Choix")
    elif choix == "2":
        print("Hashage d'un message")
        print(" Choisir le fonction du Hash")
        print("1 - SHA1")
        print("2 - SHA256")
        print("3 - SHA512")
        print("4 - MD5")
        print("0 - Return")
        choix = input()
        if choix == "1":
            msg = input("Saisir texte : \n")
            msghashe = hashlib.sha1(msg.encode())
            print(msghashe.hexdigest())
        elif choix == "2":
            msg = input("Saisir text \n")
            msghashe = hashlib.sha256(msg.encode())
            print(msghashe.hexdigest())
        elif choix == "3":
            msg = input("Saisir texte \n")
            msghashe = hashlib.sha512(msg.encode())
            print(msghashe.hexdigest())
        elif choix == "4":
            msg = input("Saisir texte \n")
            msghashe = hashlib.md5(msg.encode())
            print(msghashe.hexdigest())
        elif choix == "0":
            menu_principal()
    elif choix == "3":
        print("Crackage d'un message hashé")
        print("1 - SHA1")
        print("2 - SHA256")
        print("3 - SHA512")
        print("4 - MD5")
        print("0 - Return")
        choix = input("Choisire le type Hash \n")
        if choix == "1":
            crackDictionaireSha1()
        elif choix == "2":
            crackDictionaireSHA256()
        elif choix == "3":
            crackDictionaireSHA512()
        elif choix == "4":
            crackDictionaireMD5()
        elif choix == "0":
            menu_principal()
        else:
            print("Verifier le choix")
    elif choix == "4":
        print("Chiffrement et dechiffrement symetrique d'un message")
        print("1 - AES")
        print("2 - DES")
        print("0 - Return")
        choix = input("Saisir votre choix \n")
        if choix == "1":
            print("Chiffrement AES")
            print("1 - Chiffrement")
            print("2 - Dechiffrement")
            print("0 - Return")
            choix = input("Saisir votre choix \n")
            if choix == "1":
                AES_Encryption()
            elif choix == "2":
                AES_Decryption()
            elif choix == "0":
                menu_principal()
            else:
                print("Error")
        elif choix == "2":
            print("Chiffrement DES")
            print("1 - Chiffrement")
            print("2 - Dechiffrement")
            print("0 - Return")
            choix = input("Saisir votre choix")
            if choix == "1":
                DES_encryption()
            elif choix == "2":
                DES_decryption()
            elif choix == "0":
                pass
            else:
                print("Error")
    elif choix == "5":
        print("Chiffrement et dechiffrement asymetrique")
        print("1 - RSA")
        print("2 - ElGamal")
        print("0 - Return")
        choix = input("Saisir votre choix")
        if choix == "1":
            print("RSA")
            print("1 - Chiffrement")
            print("2 - Dechiffrement")
            print("0 - Return")
            choix = input("Saisir votre choix \n")
            if choix == "1":
                generate_keys()
                RSA_Encryption()
            elif choix == "2":
                ElGamal_Decryption()
            elif choix == "0":
                menu_principal()
            else:
                print("Error")
        elif choix == "2":
            print("ElGamal")
            print("1 - Chiffrement")
            print("2 - Dechiffrement")
            print("0 - Return")
            choix = input("Saisir votre choix \n")
            if choix == "1":
                ElGamal_Encryption()
            elif choix == "2":
                ElGamal_Decryption()
            elif choix == "0":
                menu_principal()
            else:
                print("Error")
        elif choix == "0":
            menu_principal()
    elif choix == "Q" or "q":
        exit()
    else:
        print("Verifier le choix svp")
inscrit()
login()
