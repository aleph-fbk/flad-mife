import argparse
from random import randrange
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

X_BIT = 11
N = 64
n = 4
m = 1
n_weights = 5000
Q_BIT = 2048 # bit per DDH

def wrap(x,f):
    start = time.time()
    f(x)
    end = time.time()
    print(f"Time taken: {end-start}")


def main():
    parser = argparse.ArgumentParser(description='Choose a protocol to test.')
    parser.add_argument('--protocol', choices=['DDH', 'LWE', 'LWE_sel'], required=True, help='The protocol to test (DDH or LWE)')
    args = parser.parse_args()

    if args.protocol == 'DDH':
        print("testing DDH")
        from mife_DDH import FeDamgardMulti
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

    print(mk.pp)
    print("Generating random plaintexts of size", n_weights)
    x = [[randrange(1<<X_BIT) for j in range(m)] for i in range(n_weights)]

    encrypt_with_key = partial(mife.encrypt, key=mk.get_enc_key(0))
 

    # start = time.time()
    # # cs = [encrypt_with_key(ptx) for ptx in x]
    # # cs = list(x.map(encrypt_with_key, x))
    # cs = [encrypt_with_key(ptx) for ptx in x]
    # print(f'generated cs in {time.time()-start}s')

    encrypted_model_set = []

    encrypt_wrapped = partial(wrap, f=encrypt_with_key)
    start = time.time()
    with ProcessPoolExecutor() as executor:
        encrypted_model_set.append(list(executor.map(encrypt_with_key, x)))
    print(f'generated cs in parallel in {time.time()-start}s')

    # start = time.time()
    # ptx = mife.decrypt(encrypted_model_set, mk.pp, mife.keygen([[1 for _ in range(m)] for _ in range(n)], mk))
    # print(f'decrypted cs in {time.time()-start}s')


if __name__ == "__main__":
    main()