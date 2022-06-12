# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import random
from math import gcd


def primesInRange(x, y):
    prime_list = []
    for n in range(x, y):
        isPrime = True

        for num in range(2, n):
            if n % num == 0:
                isPrime = False

        if isPrime:
            prime_list.append(n)

    return prime_list


def encryption(p, q):
    plain_text = 3148512  # Max length = 2*(bitsize-1) - 1?
    n = p*q

    e = get_coprime(p, q)
    print("e", e)

    c = (plain_text**e) % n
    print("C", c)

    return [e, c, n]


def decryption(message, privkey, n):
    return (message**privkey) % n


def get_priv_key(p, q, e):
    m = (p-1)*(q-1)
    for x in range(1, m):
        if (e % m) * (x % m) % m == 1:
            return x
    raise Exception('The modular inverse does not exist.')


def get_coprime(a, b):
    phi = (a - 1)*(b - 1)
    e = random.randint(1, phi)

    while gcd(e, a) != 1 or gcd(e, b) != 1:
        e = random.randint(1, phi)

    return e


def random_number(minbit, maxbit):
    return random.randint(10**(minbit-1), 10**(maxbit-1))


def setup(bitsize):
    primes = primesInRange(10**(bitsize-2), 10**(bitsize-1))
    p = random.choice(primes)
    q = random.choice(primes)
    while p == q:
        q = random.choice(primes)
    print("pq", p, q)
    pubkey = encryption(p, q)
    return [p,q,pubkey]


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    bitsize = 5
    [p, q, pubkey] = setup(bitsize)
    e = pubkey[0]
    c = pubkey[1]
    n = pubkey[2]
    while True:
        try:
            priv_key = get_priv_key(p, q, e)
            break
        except Exception:
            print("\n\n\n\n")
            [p, q, pubkey] = setup(bitsize)
            e = pubkey[0]
            c = pubkey[1]
            n = pubkey[2]

    print("d", priv_key)
    print(decryption(c, priv_key, n))


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
