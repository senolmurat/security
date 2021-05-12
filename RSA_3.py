import rsa
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os, base64
import time


def AES_encrypt(msg, secret_key, mode):
    if mode == "CBC":
        iv = get_random_bytes(AES.block_size)
        cypher = AES.new(secret_key, AES.MODE_CBC, iv)
        # pad the private_msg
        # because AES encryption requires the length of the msg to be a multiple of 16
        padded_msg = pad(msg, AES.block_size)
        encrypted_msg = cypher.encrypt(padded_msg)
        return "", iv + encrypted_msg
    elif mode == "CTR":
        cypher = AES.new(secret_key, AES.MODE_CTR)
        encrypted_msg = cypher.encrypt(msg)
        nonce = cypher.nonce
        return nonce, encrypted_msg


def AES_decrypt(encrypted_msg, secret_key, mode,nonce=None):
    if mode == "CBC":
        cypher = AES.new(secret_key, AES.MODE_CBC, encrypted_msg[:AES.block_size])
        decrypted_msg = cypher.decrypt(encrypted_msg[AES.block_size:])
        unpadded_msg = unpad(decrypted_msg, AES.block_size)
        return unpadded_msg
    elif mode == "CTR":
        cypher = AES.new(secret_key, AES.MODE_CTR, nonce=nonce)
        plaintext = cypher.decrypt(encrypted_msg)
        return plaintext


def function_3(pubkey, privkey):
    print("Q3)-------------------------")
    f = open("message.txt", "r")
    message = f.read()
    # message = message.encode('utf8')
    encoded_m = message.encode()
    # hashed_m = hashlib.sha256(encoded_m)
    # digest_m = hashed_m.hexdigest()
    # print("Hex Digest: ", digest_m)

    digest_m = rsa.compute_hash(encoded_m, 'SHA-256')
    print("HEX Digest: ", digest_m)
    # digest_m = digest_m.encode()
    signature = rsa.sign_hash(digest_m, privkey, 'SHA-256')

    print("------------------------------------")
    print("Digital Signature : ", signature)
    rsa.verify(encoded_m, signature, pubkey)
    # digest_m = digest_m.decode()
    print("Message: ", message)
    print("Hex Digest: ", digest_m)


def function_2(pubkey, privkey):
    print("Q2)-------------------------")
    AES_key1_lenght = 16
    AES_key2_lenght = 32

    key_1 = os.urandom(AES_key1_lenght)
    key_2 = os.urandom(AES_key2_lenght)

    print("Key 1: ", key_1)
    print("Key 2: ", key_2)

    encoded_key1 = str(key_1).encode()
    cypher_text_1 = rsa.encrypt(encoded_key1, pubkey)

    encoded_key2 = str(key_2).encode()
    cypher_text_2 = rsa.encrypt(encoded_key2, pubkey)

    print("Encrypted Key 1:", cypher_text_1)
    print("Encrypted Key 2:", cypher_text_2)

    decrypted_text_1 = rsa.decrypt(cypher_text_1, privkey)
    decrypted_text_2 = rsa.decrypt(cypher_text_2, privkey)

    print("Decrypted Key 1:", decrypted_text_1)
    print("Decrypted Key 2:", decrypted_text_2)

    return key_1, key_2


def function_4(key_1, key_2):
    print("Q4)-------------------------")
    f = open("wallhaven-760704.jpg", "rb")
    img = f.read()
    f.close()

    img = bytearray(img)

    # To measure time that encryption takes
    start_timer = time.perf_counter()
    nonce, ciphertext = AES_encrypt(img, key_2,"CTR")
    end_timer = time.perf_counter()
    total_enc_time = end_timer - start_timer
    print("Time taken for encryption: ", total_enc_time)

    f = open("encrypted_img.jpg", "wb")
    f.write(ciphertext)
    f.close()

    plaintext = AES_decrypt(ciphertext, key_2, "CTR" , nonce=nonce)

    f = open("decrypted_img.jpg", "wb")
    f.write(plaintext)
    f.close()


(pubkey, privkey) = rsa.newkeys(1024)

print(pubkey)
print(privkey)
function_3(pubkey, privkey)
(AES_key1_128, AES_key2_256) = function_2(pubkey, privkey)
function_4(AES_key1_128, AES_key2_256)
