#from mife.multi.damgard import FeDamgardMulti
from mife_LWE import FeLWEMulti
import time

n_weights = 10
n = 3
m = 5000

key = FeLWEMulti.generate(n, m, 30, 1)

print('generated key')

x = [[4 for j in range(m)] for i in range(n)]
y = [[1 for j in range(m)] for i in range(n)]

sk = FeLWEMulti.keygen(y, key)

print('generated sk')
print('K =', key.pp.K)
print('B =', key.pp.B)

start = time.time()
for i in range(1000):
 cs = [FeLWEMulti.encrypt(key.pp, x[i], key.get_enc_key(i)) for i in range(n)]

print(f'generated cs in {time.time()-start}s')

ptx = FeLWEMulti.decrypt(cs, key.pp, sk)

print(ptx)