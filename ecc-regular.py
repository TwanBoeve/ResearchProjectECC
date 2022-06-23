from ecdsa.ecdsa import Private_key, Public_key, generator_brainpoolp256r1, curve_brainpoolp256r1
from ecdsa.ellipticcurve import Point
import random
import time
import os
import psutil
from fastecdsa import keys, curve
from fastecdsa.curve import brainpoolP256r1

ecurve = brainpoolP256r1
privKeyTemp, pubKeyTemp = keys.gen_keypair(brainpoolP256r1)

# Curve brainpoolp256r1 props:
p = int('0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377', base=16)
r = 6277101735386680763835789423176059013767194773182842284081
a = 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9
b = 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6
n = int('0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7', base=16)
Gx = 0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262
Gy = 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997

ecurve = curve_brainpoolp256r1
ecurve_G = Point(ecurve, Gx, Gy)
gen = generator_brainpoolp256r1

start_time = time.perf_counter()

k = random.randint(1, n - 1)
pubKey = Public_key(gen, ecurve_G)
print(pubKey.point)
pubKey.point = Point(ecurve, pubKeyTemp.x, pubKeyTemp.y)
print(pubKey.point)
privKey = Private_key(pubKey, k)

plain_text = b'ECC vs RSA'
plain_int = int.from_bytes(plain_text, 'big')
plain_point = ecurve_G * plain_int
print("\nPlain text:", plain_text.decode('utf-8'))
print("Plain int:", plain_int)
print("Plain point:\n", plain_point)

# Cipher point Cm consists of C1 and C2
c1 = k * ecurve_G
c2 = plain_point + k * pubKey.point
print("\nCipher point:")
print("C1:\n", c1)
print("C2:\n", c2)

c1Array = (str(c1).split(','))
c1Array[0] = c1Array[0][1:]
c1Array[1] = c1Array[1][:len(c1Array[1]) - 1]

c1_decrypted = privKeyTemp * c1
print(c1_decrypted)
#
decrypted = c2 + (-c1_decrypted)
print("\n Decrypted point:\n", decrypted)
print("\nDecrypted point equal to plain text point:", decrypted == plain_point)

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

print("\nElapsed time:", time.perf_counter() - start_time, "seconds")

print("Memory used: %s MB" % (psutil.Process(os.getpid()).memory_info().rss / 1024 ** 2))
