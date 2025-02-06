import argparse
from random import randrange
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial

X_BIT = 11
N = 16
n = 4
m = 1
n_weights = 100
bound = 1<<X_BIT

def main():
    parser = argparse.ArgumentParser(description='Choose a protocol to test.')
    parser.add_argument('--protocol', choices=['DDH', 'LWE'], required=True, help='The protocol to test (DDH or LWE)')
    args = parser.parse_args()

    if args.protocol == 'DDH':
        print("testing DDH")
        from mife_DDH import FeDamgardMulti
        mife = FeDamgardMulti()
        mk = mife.generate(n, m, X_BIT)
    elif args.protocol == 'LWE':
        print("testing LWE")
        from mife_LWE import FeLWEMulti
        mife = FeLWEMulti()
        mk = mife.generate(n, m, 1, X_BIT, N)
    else:
        print("Invalid protocol selected.")


    x = [[[randrange(-bound, bound) for _ in range(m)] for _ in range(n_weights)] for _ in range(n)]

    result = [sum([x[i][j][0] for i in range(n)]) for j in range(n_weights)]

    sk = mife.keygen([[1 for _ in range(m)] for _ in range(n)], mk)

    encrypted_model_set = []

    for i in range(n):
        print(f"Encrypting model {i}...")
        encrypt_with_key = partial(mife.encrypt, key=mk.get_enc_key(i))
        with ProcessPoolExecutor() as executor:
            encrypted_model_set.append(list(executor.map(encrypt_with_key, x[i])))

    print("Encryption complete.")
    ptx = [mife.decrypt([encrypted_model_set[i][j] for i in range(n)], mk.pp, sk) for j in range(n_weights)]
    print("Decryption complete.")


    if ptx == result:
        print("Correctness test passed.")   
    else:    
        print("Correctness test failed.")


if __name__ == "__main__":
    main()