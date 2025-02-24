import argparse
from random import randrange
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial

import os, sys

sys.path.append(os.path.abspath(__file__))
# sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from MIFE.utilities import parallel_decrypt_vector, parallel_encrypt_vector, parallel_encrypt_vector_compact

X_BIT = 11
N = 64
n = 4
m = 1
n_weights = 5000
Q_BIT = 2048 # bit per DDH

num_loop = 10


# def wrap(x,f):
#     start = time.time()
#     f(x)
#     end = time.time()
#     print(f"Time taken: {end-start}")


def main():
    parser = argparse.ArgumentParser(description='Choose a protocol to test.')
    parser.add_argument('--protocol', choices=['DDH', 'DDH_sel','LWE', 'LWE_sel'], required=True, help='The protocol to test (DDH or LWE)')
    parser.add_argument('--max_workers', required=True, help='number of workers involved in parallelization')
    args = parser.parse_args()

    max_workers = int(args.max_workers)
    print("num of workers:", max_workers)

    if args.protocol == 'DDH':
        print("testing DDH")
        from mife_DDH import FeDamgardMulti
        mife = FeDamgardMulti()
        mk = mife.generate(n=n, m=m, X_bit=X_BIT, q_bit=Q_BIT)
    elif args.protocol == 'DDH_sel':
        print("testing DDH_sel")
        from mife_DDH_sel import FeDamgardMulti
        mife = FeDamgardMulti()
        mk = mife.generate(n=n, m=m, X_bit=X_BIT, q_bit=Q_BIT)
    elif args.protocol == 'LWE':
        print("testing LWE")
        from mife_LWE import FeLWEMulti
        mife = FeLWEMulti()
        mk = mife.generate(n = n, m = m, X_bit=X_BIT, Y_bit=1, N=N)
    elif args.protocol == 'LWE_sel':
        print("testing LWE_sel")
        from mife_LWE_sel import FeLWEMulti
        mife = FeLWEMulti()
        mk = mife.generate(n = n, m = m, X_bit=X_BIT, Y_bit=1, N=N)
    else:
        print("Invalid protocol selected.")

    print('The public parameters of the MIFE scheme are:')
    print(mk.pp)
    print("Generating random plaintexts of size", n_weights)
    x = [[randrange(1<<X_BIT) for j in range(m)] for i in range(n_weights)]


    # start = time.time()
    # # cs = [encrypt_with_key(ptx) for ptx in x]
    # # cs = list(x.map(encrypt_with_key, x))
    # cs = [encrypt_with_key(ptx) for ptx in x]
    # print(f'generated cs in {time.time()-start}s')
    encrypted_model_set = []

    for i in range(num_loop):
        print('encrypting round', i)
        start = time.time()

        if max_workers == 1:
            a = [mife.encrypt(ptx,key=mk.get_enc_key(0)) for ptx in x]
        else:
           # a = parallel_encrypt_vector_compact(v=x,max_workers=max_workers,mife=mife,key=mk.get_enc_key(0))
           a = parallel_encrypt_vector(v=x,max_workers=max_workers,mife=mife,key=mk.get_enc_key(0))
        end = time.time()
        print(f'generated cs in parallel in {end-start}s')



    # print(a[:20])
    # start = time.time()
    # ptx = mife.decrypt(encrypted_model_set, mk.pp, mife.keygen([[1 for _ in range(m)] for _ in range(n)], mk))
    # print(f'decrypted cs in {time.time()-start}s')


if __name__ == "__main__":
    main() 