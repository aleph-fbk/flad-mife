import argparse
from random import randrange
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial

X_BIT = 11
N = 16
n = 4
m = 1
n_weights = 5000

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


    x = [[randrange(1<<X_BIT) for j in range(m)] for i in range(n_weights)]

    encrypt_with_key = partial(mife.encrypt, key=mk.get_enc_key(0))

    start = time.time()
    cs = [mife.encrypt(ptx, mk.get_enc_key(0)) for ptx in x]
    print(f'generated cs in {time.time()-start}s')

    encrypted_model_set = []

    start = time.time()
    with ProcessPoolExecutor() as executor:
        encrypted_model_set.append(list(executor.map(encrypt_with_key, x)))
    print(f'generated cs in parallel in {time.time()-start}s')


if __name__ == "__main__":
    main()