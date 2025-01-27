#from mife.multi.damgard import FeDamgardMulti
from mife_LWE import FeLWEMulti

n_weights = 10
n = 3
m = 1

key = FeLWEMulti.generate(n, m, 8, 1)

print('generated key')

x = [[4 for j in range(m)] for i in range(n)]
y = [[1 for j in range(m)] for i in range(n)]

sk = FeLWEMulti.keygen(y, key)

print('generated sk')
print('K =', key.pp.K)
print('B =', key.pp.B)
cs = [FeLWEMulti.encrypt(key.pp, x[i], key.get_enc_key(i)) for i in range(n)]

print('generated cs')

ptx = FeLWEMulti.decrypt(cs, key.pp, sk)

print(ptx)