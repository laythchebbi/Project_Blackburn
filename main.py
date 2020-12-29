import getpass, base64, hashlib, os.path, re, sqlite3
from  cryptography.fernet import Fernet

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'

def AES_Encryption():
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
    while True:
        email = input("Saisir votre email")
        password = getpass.getpass("Saisir mot de passe")
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
        email = input("Enter you email ")
        if check(email) == True:
            break
    password = input("Donner un mot de passe")

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
    dict_file = input("Saire le path de la dictionnaire : ")
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
        print("Failed to crack the file.")


def crackDictionaireMD5():
    res = 0
    dict_file = input("Saire le path de la dictionnaire : ")
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
        print("Failed to crack the file.")


def crackDictionaireSHA256():
    res = 0
    dict_file = input("Saire le path de la dictionnaire : ")
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
        print("Failed to crack the file.")

def crackDictionaireSHA512():
    res = 0
    dict_file = input("Saire le path de la dictionnaire : ")
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
        print("Failed to crack the file.")


def menu_principal():
    print("Welcome")
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
                msg = input("Sasir le txt")
                msgbyte = msg.encode('ascii')
                msgCrypte = base64.b64encode(msgbyte)
                print(msgCrypte)
        elif choix == "2":
            print("decodage")
            print("1 - Decodage base64")
            choix = input("Choisir le type de decodage ")

            if (choix == "1"):
                base64_message = input("Sasir le txate : ")
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
        choix = input()
        if choix == "1":
            msg = input("Saisir taxte")
            msghashe = hashlib.sha1(msg.encode())
            print(msghashe.hexdigest())
        elif choix == "2":
            msg = input("Saisir taxte")
            msghashe = hashlib.sha256(msg.encode())
            print(msghashe.hexdigest())
        elif choix == "3":
            msg = input("Saisir taxte")
            msghashe = hashlib.sha512(msg.encode())
            print(msghashe.hexdigest())
        elif choix == "4":
            msg = input("Saisir taxte")
            msghashe = hashlib.md5(msg.encode())
            print(msghashe.hexdigest())
        print("0 - Return")

    elif choix == "3":
        print("Crackage d'un message hashé")
        print("1 - SHA1")
        print("2 - SHA256")
        print("3 - SHA512")
        print("4 - MD5")
        choix = input("Choisire le type Hash")
        if choix == "1":
            crackDictionaireSha1()
        elif choix == "2":
            crackDictionaireSHA256()
        elif choix == "3":
            crackDictionaireSHA512()
        elif choix == "4":
            crackDictionaireMD5()
        else:
            print("Verifier le choix")
        print("0 - Return")
    elif choix == "4":
        print("Chiffrement et dechiffrement symetrique d'un message")
        print("1 - Saisir le message a chiffré")
        print("2 - Saisir le message chiffré")
        print("0 - Return")
    elif choix == "5":
        print("Chiffrement et dechiffrement asymetrique")
        print("1 - Saisir le message a chiffré")
        print("2 - Saisir le message chiffré")
        print("0 - Return")
    elif choix == "Q" or "q":
        exit()
    else:
        print("Verifier le choix svp")


inscrit()
login()

