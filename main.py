import getpass , base64 , hashlib

print("To use the application you have to enter you email and password :")
email = input("Enter you email ")
password = getpass.getpass()
print(""" ____    ___                    __      __                               
/\  _`\ /\_ \                  /\ \    /\ \                              
\ \ \L\ \//\ \      __      ___\ \ \/'\\ \ \____  __  __  _ __    ___    
 \ \  _ <'\ \ \   /'__`\   /'___\ \ , < \ \ '__`\/\ \/\ \/\`'__\/' _ `\  
  \ \ \L\ \\_\ \_/\ \L\.\_/\ \__/\ \ \\`\\ \ \L\ \ \ \_\ \ \ \/ /\ \/\ \ 
   \ \____//\____\ \__/.\_\ \____\\ \_\ \_\ \_,__/\ \____/\ \_\ \ \_\ \_\
    \/___/ \/____/\/__/\/_/\/____/ \/_/\/_/\/___/  \/___/  \/_/  \/_/\/_/""")
def crackDictionaireSha1():
    dict_file = input("Saire le path de la dictionnaire : ")
    hashed = input("Saisire le Hash : ")
    with open(dict_file) as fileobj:
        for line in fileobj:
            line = line.strip()
            if hashlib.sha1(line.encode()).hexdigest() == hashed:
                print("The passssswoooord is %s") % (line);
                return ""
    print("Failed to crack the hash!")

def crackDictionaireMD5():
    dict_file = input("Saire le path de la dictionnaire : ")
    hashed = input("Saisire le Hash : ")
    with open(dict_file) as fileobj:
        for line in fileobj:
            line = line.strip()
            if hashlib.md5(line).hexdigest() == hashed :
                print("Successfully cracked the hash %s: It's %s" % (hashed, line))
                return ""
    print("Failed to crack the file.")
def crackDictionaireSHA256():
    dict_file = input("Saire le path de la dictionnaire : ")
    hashed = input("Saisire le Hash : ")
    with open(dict_file) as fileobj:
        for line in fileobj:
            line = line.strip()
            if hashlib.sha256(line).hexdigest() == hashed :
                print("Successfully cracked the hash %s: It's %s" % (hashed, line))
                return ""
    print("Failed to crack the file.")
def crackDictionaireSHA512():
    dict_file = input("Saire le path de la dictionnaire : ")
    hashed = input("Saisire le Hash : ")
    with open(dict_file) as fileobj:
        for line in fileobj:
            line = line.strip()
            if hashlib.sha512(line).hexdigest() == hashed :
                print("Successfully cracked the hash %s: It's %s" % (hashed, line))
                return ""
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
            if(choix == "1"):
                msg = input("Sasir le txt")
                msgbyte = msg.encode('ascii')
                msgCrypte = base64.b64encode(msgbyte)
                print(msgCrypte)
        elif choix == "2":
            print("decodage")
            print("1 - Decodage base64")
            choix = input("Choisir le type de decodage ")

            if(choix == "1"):
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

        print("3 - Crackage du Hash")
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


menu_principal()
