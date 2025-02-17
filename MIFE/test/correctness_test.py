import argparse
from random import randrange
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial
import os, sys
import numpy as np
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


X_BIT = 11
Y_BIT = 1
N = 64
n = 4
m = 1
n_weights = 100
Q_BIT = 2048 # bit per DDH
bound = 1<<X_BIT

MAX_WORKERS = 30
parallel_flag = True

def main():
    parser = argparse.ArgumentParser(description='Choose a protocol to test.')
    parser.add_argument('--protocol', choices=['DDH', 'DDH_sel', 'LWE', 'LWE_sel'], required=True, help='The protocol to test (DDH or LWE)')
    args = parser.parse_args()

    if args.protocol == 'DDH':
        print("testing DDH")
        from mife_DDH import FeDamgardMulti
        mife = FeDamgardMulti()
        mk = mife.generate(n, m, X_BIT, Q_BIT)
    elif args.protocol == 'DDH_sel':
        print("testing DDH_sel")
        from mife_DDH_sel import FeDamgardMulti
        mife = FeDamgardMulti()
        mk = mife.generate(n, m, X_BIT, Q_BIT)
    elif args.protocol == 'LWE':
        print("testing LWE")
        from mife_LWE import FeLWEMulti
        mife = FeLWEMulti()
        mk = mife.generate(n, m, X_BIT, Y_BIT, N)
    elif args.protocol == 'LWE_sel':
        print("testing LWE selective")
        from mife_LWE_sel import FeLWEMulti
        mife = FeLWEMulti()
        mk = mife.generate(n, m, X_BIT, Y_BIT, N)
        print(mk.pp)
    else:
        print("Invalid protocol selected.")


    x = [[[randrange(-bound,bound) for _ in range(m)] for _ in range(n_weights)] for _ in range(n)]
    # x = [[[1 for _ in range(m)] for _ in range(n_weights)] for _ in range(n)]

    result = [sum([sum([x[i][j][h] for h in range(m)]) for i in range(n)]) for j in range(n_weights)]

    sk = mife.keygen([[1 for _ in range(m)] for _ in range(n)], mk)

    encrypted_model_set = []

    if parallel_flag:
        from MIFE.utilities import parallel_decrypt_vector, parallel_encrypt_vector

        for i in range(n):
            print(f"Encrypting model {i}...")
            encrypted_model_set.append(parallel_encrypt_vector(x[i],MAX_WORKERS,mife,mk.get_enc_key(i)))
            # with ProcessPoolExecutor() as executor:
            #     encrypted_model_set.append(list(executor.map(encrypt_with_key, x[i])))

        print("Encryption complete.")
        ptx = parallel_decrypt_vector(encrypted_model_set,mife,mk.pp,sk,MAX_WORKERS)
        # ptx = [mife.decrypt([encrypted_model_set[i][j] for i in range(n)], mk.pp, sk) for j in range(n_weights)]
        print("Decryption complete.")


        if ptx == result:
            print("Correctness test passed.")   
        else:    
            print(f"Correctness test failed")
            print('errors:\n',abs(np.array(ptx) - np.array(result)))


if __name__ == "__main__":
    main()