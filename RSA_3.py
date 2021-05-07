import rsa
import hashlib
from Crypto.Cipher import AES
import os , base64

def AES_encrypt(msg , secret_key , padding_character):

    cypher = AES.new(secret_key)
    # pad the private_msg
    # because AES encryption requires the length of the msg to be a multiple of 16
    padded_msg = msg + (padding_character * ((16 - len(msg)) % 16))
    encrypted_msg = cypher.encrypt(padded_msg)
    return encrypted_msg


def AES_decrypt(encrypted_msg , secret_key , padding_character):

    cypher = AES.new(secret_key)
    decrypted_msg = cypher.decrypt(encrypted_msg)
    unpadded_msg = decrypted_msg.rstrip(padding_character)
    return unpadded_msg


def function_3(pubkey , privkey):
    f = open("message.txt", "r")
    message = f.read()
    # message = message.encode('utf8')
    encoded_m = message.encode()
    hashed_m = hashlib.sha256(encoded_m)
    digest_m = hashed_m.hexdigest()
    print("Hex Digest: ", digest_m)

    digest_m = digest_m.encode()
    cypher_text = rsa.encrypt(digest_m, pubkey)
    print(cypher_text)

    print("------------------------------------")
    print("Digital Signature : ", cypher_text)
    digest_m = rsa.decrypt(cypher_text, privkey)
    digest_m = digest_m.decode()
    print("Message: ", message)
    print("Hex Digest: ", digest_m)


def function_2(pubkey , privkey):
    AES_key1_lenght = 16
    AES_key2_lenght = 32
    padding_character = "{"

    key_1 = os.urandom(AES_key1_lenght)
    key_2 = os.urandom(AES_key2_lenght)

    print("Key 1: " , key_1)
    print("Key 2: " , key_2)

    encoded_key1 = str(key_1).encode()
    cypher_text_1 = rsa.encrypt(encoded_key1, pubkey)

    encoded_key2 = str(key_2).encode()
    cypher_text_2 = rsa.encrypt(encoded_key2, pubkey)

    print("Encrypted Key 1:", cypher_text_1)
    print("Encrypted Key 2:", cypher_text_2)

    decrypted_text_1 = rsa.decrypt(cypher_text_1 , privkey)
    decrypted_text_2 = rsa.decrypt(cypher_text_2 , privkey)

    print("Decrypted Key 1:",decrypted_text_1)
    print("Decrypted Key 2:", decrypted_text_2)




(pubkey, privkey) = rsa.newkeys(1024)

print(pubkey)
print(privkey)
#function_3(pubkey , privkey)
function_2(pubkey , privkey)
