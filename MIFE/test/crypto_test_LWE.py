#from mife.multi.damgard import FeDamgardMulti
from mife_LWE import FeLWEMulti
from random import randrange
import time
import cProfile
from concurrent.futures import ProcessPoolExecutor
from functools import partial


X_BIT = 11
N = 16
n_weights = 1
n = 1
m = 1
n_tests = 5000

bound = 1<<X_BIT

mife = FeLWEMulti()


key = mife.generate(n, m, Y_bit=1,X_bit=X_BIT, N=N)

print('generated key')

x = [[randrange(bound) for _ in range(m)] for _ in range(n_tests)]
y = [[1 for _ in range(m)] for _ in range(n)]

# print(x[0][0])

sk = mife.keygen(y, key)


print('generated sk')
print(key.pp)
encrypt_with_key = partial(mife.encrypt, key=key.get_enc_key(0))

encrypted_model_set=[]

start = time.time()

cs = [mife.encrypt(ptx, key.get_enc_key(0)) for ptx in x] 

print(f'generated cs in {time.time()-start}s')

start = time.time()
with ProcessPoolExecutor() as executor:
    encrypted_model_set.append(list(executor.map(encrypt_with_key, x)))

print(f'generated cs in {time.time()-start}s')

# ptx = mife.decrypt(encrypted_model_set, key.pp, sk)

# print(ptx)