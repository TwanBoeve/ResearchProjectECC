import hashlib
import random
import binascii
import time
import os
import psutil

from tinyec import registry as reg
from Crypto.Cipher import AES


# Function to compress a point into hex
def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]


def ecc_calc_encryption_keys(pubKey, receiverPrivKey):
    sharedECCKey = pubKey * receiverPrivKey
    return sharedECCKey


def ecc_calc_decryption_key(senderPrivKey, receiverPubKey):
    sharedECCKey = receiverPubKey * senderPrivKey
    return sharedECCKey


def point_to_256_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()


def aes_encrypt(plain_text, secretKey):
    cipher = AES.new(secretKey, AES.MODE_GCM)
    encrypted, tag = cipher.encrypt_and_digest(plain_text)
    return encrypted, cipher.nonce, tag


def aes_decrypt(encrypted, nonce, tag, secretKey):
    cipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plain_text = cipher.decrypt_and_verify(encrypted, tag)
    return plain_text


def encrypt(message, sharedKey):
    secretKey = point_to_256_key(sharedKey)
    encrypted, nonce, tag = aes_encrypt(message, secretKey)
    return encrypted, nonce, tag


def decrypt(message, nonce, tag, sharedKey):
    # secret key calculated both in encryption and decryption since this would also happen normally
    secretKey = point_to_256_key(sharedKey)
    plain_text = aes_decrypt(message, nonce, tag, secretKey)
    return plain_text


def main():
    # NOTE: Uses AES-GCM (/AES-256-GCM), write about this in paper!
    # This means that a security level of 256 bits is used, about equal to

    start_time = time.perf_counter()

    curve = reg.get_curve('brainpoolP256r1')
    # Private keys are random int from 0 to n-1
    senderPrivKey = random.randint(0, curve.field.n - 1)
    senderPubKey = senderPrivKey * curve.g
    print("Sender's privKey:", hex(senderPrivKey))
    print("Sender's pubKey:", compress_point(senderPubKey))

    receiverPrivKey = random.randint(0, curve.field.n - 1)
    encryptKey = ecc_calc_encryption_keys(senderPubKey, receiverPrivKey)
    receiverPubKey = receiverPrivKey * curve.g

    print("Receiver's privKey:", hex(receiverPrivKey))
    print("Receiver's pubKey:", compress_point(receiverPubKey))

    # Both sharedKeys should be the same, but both printed since they are calculated in different ways
    print("Sender sharedKey: (decryption key)", compress_point(encryptKey))

    decryptKey = ecc_calc_decryption_key(senderPrivKey, receiverPubKey)
    print("Receiver sharedKey: (encryption key)", compress_point(decryptKey))

    # shared key can be either encryption or decryption key, since they are the same
    sharedKey = encryptKey

    plain_text = b'ECC vs RSA'
    print("\nPlain text:", plain_text.decode('utf-8'))
    encrypted, nonce, tag = encrypt(plain_text, sharedKey)
    print("Encrypted text:", binascii.hexlify(encrypted).decode('utf-8'))

    decrypted = decrypt(encrypted, nonce, tag, sharedKey)
    print("Decrypted text:", decrypted.decode('utf-8'))

    print("\nElapsed time:", time.perf_counter() - start_time, "seconds")


if __name__ == '__main__':
    main()
    print("Memory used: %s MB" % (psutil.Process(os.getpid()).memory_info().rss / 1024 ** 2))

