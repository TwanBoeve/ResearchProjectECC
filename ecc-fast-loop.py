import random
import time
from fastecdsa import keys
from fastecdsa.curve import brainpoolP256r1

start_time = time.perf_counter()

for i in range(1000):
    ecurve = brainpoolP256r1
    privKey, pubKey = keys.gen_keypair(brainpoolP256r1)

    k = random.randint(1, ecurve.q - 1)

    plain_text = b'ECC vs RSA'
    plain_int = int.from_bytes(plain_text, 'big')
    plain_point = ecurve.G * plain_int

    # Cipher point Cm consists of C1 and C2
    c1 = k * ecurve.G
    c2 = plain_point + k * pubKey

    c1_decrypted = privKey * c1

    decrypted = c2 - c1_decrypted

    # Normally the original message can now be found by dividing
    # the decrypted point by point G. Unfortunately, this is not
    # supported by the library used for fast scalar multiplication

    # i = 0
    # i = plain_int - 1000
    # while True:
    #     i += 1
    #     if i*ecurve.G == decrypted:
    #         break
    # print("Decoded plain text:", i.to_bytes(len(plain_text), 'big').decode('utf-8'))
    print("Cycle %s done" % (i + 1))
print("\nElapsed time: %s seconds" % (time.perf_counter() - start_time))
