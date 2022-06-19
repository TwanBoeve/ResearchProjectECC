import random
from math import gcd
import time

def encryption(p, q):
    plain_text = 'ECC vs RSA'  # Max length = 2*(bitsize-1) - 1?
    print("\nPlain text:", plain_text)
    plain_text = int.from_bytes(bytes(plain_text, 'utf-8'), 'big')
    n = p*q

    e = get_coprime(p, q, low=True)
    print("\ne (coprime of p and q):", e)

    c = (plain_text**e) % n
    print("\nEncrypted message:", c)

    return [e, c, n]


def decryption(message, privkey, n):
    return hex(pow(message, privkey, n))
    # return hex(pow(message, privkey, n)).rstrip("L")


def extended_euclidean_algorithm(a, b):
    # Extended euclidean algorithm, used to calculate the private key factor d

    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_euclidean_algorithm(b % a, a)
        return g, x - (b // a) * y, y


def get_priv_key(p, q, e):
    # Computes the modular inverse to get the private key

    phi = (p-1)*(q-1)

    g, x, y = extended_euclidean_algorithm(e, phi)

    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % phi


def get_coprime(a, b, low=False):
    phi = (a - 1)*(b - 1)
    e = random.randint(2, phi)

    if low:
        for i in range(3, phi):
            if gcd (i, a) == 1 and gcd(i, b) == 1:
                e = i
                break
    else:
        while gcd(e, a) != 1 or gcd(e, b) != 1:
            e = random.randint(1, phi)

    return e


def random_number(minbit, maxbit):
    return random.randint(10**(minbit-1), 10**(maxbit-1))


def isPrime(n):
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False

    return True


def setup(bitsize):
    lower = 10**(bitsize-2)
    upper = 10**(bitsize-1)
    p = random.randint(lower, upper)
    while not isPrime(p):
        p = random.randint(lower, upper)

    q = random.randint(lower, upper)
    while p == q or not isPrime(q):
        q = random.randint(lower, upper)
    print("Random primes p and q:\n", p, "and", q, "respectively")

    pubkey = encryption(p, q)
    return p, q, pubkey


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    start_time = time.perf_counter()
    bitsize = 16
    (p, q, pubkey) = setup(bitsize)
    e = pubkey[0]
    c = pubkey[1]
    n = pubkey[2]
    while True:
        try:
            priv_key = get_priv_key(p, q, e)
            break
        except Exception:
            print("\n\n\n\n")
            start_time = time.perf_counter()
            (p, q, pubkey) = setup(bitsize)
            e = pubkey[0]
            c = pubkey[1]
            n = pubkey[2]

    print("Decryption key:", priv_key)

    decrypted = decryption(c, priv_key, n)
    print("\nDecrypted text:", bytes.fromhex(decrypted[2:]).decode('utf-8'))

    print("\nElapsed time:", time.perf_counter() - start_time, "seconds")
