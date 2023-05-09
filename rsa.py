from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os

# ======== support functions for part b and d ========
def find_decrypt_key(message, dir="key_pairs/"):
    # iterate through all the keys in the directory
    for file in os.listdir(dir):
        # TODO: what type of key should we filter out?
        if not file.endswith("priv.pem"): 
            continue # skip to the next file
        elif decrypt_message(message, dir + file, "temp.txt"): # if the decryption is successful
            os.remove("temp.txt") # remove the temporary file
            return dir + file # return the private key file name

def find_sign_key(message, signature, dir="key_pairs/"):
    # [IMPLEMENT THIS FUNCTION TO RETURN THE PATH TOWARDS THE PUBLIC KEY]
    # TODO
    for file in os.listdir(dir):
        # TODO: what type of key should we filter out?
        if not file.endswith("pub.pem"): 
            continue # skip to the next file
        elif verify_message(message, signature,dir + file): # if the decryption is successful
            return dir + file # return the private key file name
    return None
# ======== main functions ========
# Generate a public/private key pair using 2048 bits key length
def generate_keys(public_fname="public.pem", private_fname="private.pem"):
    # generate the key pair
    key = RSA.generate(2048)

    # ======= public key =======
    # TODO: extract the public key
    public=key.publickey()
    # TODO: save the public key in a file called public.pem
    f=open(public_fname, 'wb')
    f.write(public.export_key('PEM'))
    # ======= private key =======
    # TODO: extract the private key
    private=key
    # TODO: save the private key in a file called private.pem
    f=open(private_fname, 'wb')
    f.write(private.export_key('PEM'))
    f.close()
# Encrypt a message using a public key
def encrypt_message(message, pub_key_path, out_fname="encrypted.txt"):
    # TODO: open the file to write the encrypted message
    f=open(out_fname,'wb')
    # TODO: encrypt the message with the public RSA key using PKCS1_OAEP
    f_pub=open(pub_key_path, 'rb')
    pub=RSA.import_key(f_pub.read())
    # TODO: write the encrypted message to the file
    c=PKCS1_OAEP.new(pub)
    emessage=c.encrypt(message)
    f.write(emessage)
    # TODO: close the file
    f.close()
    f_pub.close()
    pass # remove this line when you implement the function

# Decrypt a message using a private key
def decrypt_message(message, priv_key_path, out_fname="decrypted.txt"):
    # TODO: open the file to write the decrypted message
    f=open(out_fname,'wb')
    f_pri=open(priv_key_path, 'rb')
    pri=RSA.import_key(f_pri.read())
    # decrypt the message with the private RSA key using PKCS1_OAEP
    c=PKCS1_OAEP.new(pri)
    # and return True if the decryption is successful
    try:
        # TODO: import private key and generate cipher using PKCS1_OAEP
        dmessage=c.decrypt(message)
        # TODO: write the decrypted message to the file
        f.write(dmessage)
        # TODO: close the file
        f.close()
        f_pri.close()
        # return True if decryption is successful
        print("The private key is valid.")
        return True
    
    except ValueError:
        # return False if decryption is unsuccessful
        print("The private key is invalid.")
        return False

# Sign a message using a private key
def sign_message(message, priv_key_path, out_fname="signed_msg.txt"):
    # TODO: open the file to write the signature
    f=open(out_fname,'wb')
    # TODO: import private key
    private_key=RSA.import_key(open(priv_key_path).read())
    # TODO: hash the message with SHA256
    hashv=SHA256.new(message)
    # TODO: sign the message with the private RSA key using pkcs1_15
    signature=pkcs1_15.new(private_key).sign(hashv)
    # TODO: write the signature to the file
    f.write(signature)
    # TODO: close the file
    f.close()
    # remove this line when you implement the function

# Verify a message using a public key
def verify_message(message, signature, public_key_path):
    # TODO: import public key
    public_key=RSA.import_key(open(public_key_path).read())
    # TODO: hash the message with SHA256
    hashv=SHA256.new(message)
    # verify the signature with the public RSA key using pkcs1_15
    try:
        # TODO: verify the signature
        pkcs1_15.new(public_key).verify(hashv, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False


def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('a. Generate public and private keys')
    print('b. Find the right key and decrypt the message in sus.txt')
    print('c. Sign a message and verify it')
    print('d. Find Miss Reveille\'s key pair that she used to sign rev.txt')
    print('q. Quit')
    print('***********************************************\n')

if __name__ == "__main__":
    while True:
        print_menu()
        option = input('Choose a menu option: ')
        if option == "a":
            # part a.1: generate public and private keys
            # TODO
            generate_keys()
            # part a.2: ask a message to be encrypted and encrypt it
            message = input("Enter a message to be encrypted: ")
            message = message.encode()
            public_key_path = "public.pem"
            # TODO: call the encrypt_message function
            encrypt_message(message,public_key_path)
            # part a.3: decrypt that exact message and output it to a file 
            #           called decrypted.txt
            private_key_path = "private.pem"
            encrypted_message = open("encrypted.txt", "rb").read()
            # TODO: call the decrypt_message function
            decrypt_message(encrypted_message,private_key_path)
        elif option == "b":
            # part b: decrypt the message given in sus.txt using one of the keys in key_pairs
            #         and output the decrypted message to a file called sus_decrypted.txt
            #         HINT: use the find_decrypt_key function to your advantage
            message = open("sus.txt", "rb").read()
            # TODO
            private=find_decrypt_key(message)
            if private:
                decrypt_message(message, private, "sus_decrypted.txt")
            else:
                print("no key")

        elif option == "c":
            # part c.1: sign a message using the private key from part a.1
            #           and export the signature to a file called signed_msg.txt
            message = input("Enter a message to be signed: ")
            message = message.encode()
            private_key_path = "private.pem"
            # TODO: call the sign_message function
            sign_message(message, private_key_path)
            # part c.2: verify the signature of the message using 
            #           the public key from part a.1 
            public_key_path = "public.pem"
            signature = open("signed_msg.txt", "rb").read()
            # TODO: call the verify_message function
            verify_message(message, signature, public_key_path)
        elif option == "d":
            # part d: identify the real Reveille's signature
            #         by verifying the signature of the message in 
            #         sus_decrypted.txt
            #         HINT:
            #         - think about how to find the correct key IRL (trial and error)
            #         - you are more than welcome to write a helper function to find the key
            #           and if you do, you can write find_sign_key() function
            #         - whatever method you use, as long as we select this option and get the
            #           correct key, you will get full credit
            message = open("sus_decrypted.txt", "rb").read()
            signature = open("rev.txt", "rb").read()
            public_key_path = find_sign_key(message, signature)
            if public_key_path:
                print("found in : ",public_key_path )
            else:
                print("not found")
            
        elif option == "q":
            break
