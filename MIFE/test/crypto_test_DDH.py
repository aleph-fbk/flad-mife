#from mife.multi.damgard import FeDamgardMulti
from mife_DDH import FeDamgardMulti
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from random import randrange

n_weights = 5000
X_bit = 11
bound = 1<<X_bit
n = 3
m = 10
mife = FeDamgardMulti()
generate_param_time = time.time()
key = mife.generate(n, m, X_bit)
generate_param_time = time.time() - generate_param_time

print(f'generated params in {generate_param_time}s')

x = [[randrange(bound) for j in range(m)] for i in range(n_weights)]
y = [[1 for j in range(m)] for i in range(n)]

generate_key_time = time.time()
sk = mife.keygen(y, key)
generate_key_time = time.time() - generate_key_time

print(f'generated key in {generate_key_time}s')

encrypt_with_key = partial(mife.encrypt, key=key.get_enc_key(0))

start = time.time()
cs = [mife.encrypt(ptx,key.get_enc_key(0)) for ptx in x] 
print(f'generated cs in {time.time()-start}s')

encrypted_model_set = []

start = time.time()
with ProcessPoolExecutor() as executor:
    encrypted_model_set.append(list(executor.map(encrypt_with_key, x)))

print(f'generated cs in {time.time()-start}s')