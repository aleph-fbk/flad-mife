#from mife.multi.damgard import FeDamgardMulti
from mife_LWE import FeLWEMulti
import time
from random import randrange
# import numpy as np

n_weights = 5000 # number of weights
n = 1 # number of parties
X_bit = 30 # upper bound on the bit lenght of a weight

key = FeLWEMulti.generate(n, 1, X_bit, 1)
bound = 1 << X_bit

x = [[randrange(0,bound) for _ in range(n_weights)] for _ in range(n)] # private input of the users
y = [1 for i in range(n)]

sk = FeLWEMulti.keygen(y, key)

# print('generated sk')
# print('K =', key.pp.K)
# print('B =', key.pp.B)

start = time.time()
cs = [FeLWEMulti.encrypt(key.pp, x[i], key.get_enc_key(i)) for i in range(n)]

print(f'generated cs in {time.time()-start}s for n_weights = {n_weights}')

ptx = [FeLWEMulti.decrypt(cs, key.pp, sk)]

for i in range(n_weights):
    if ptx[i] != sum(x[i,:]):
        print("Error in the decryption")
        break
