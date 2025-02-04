#from mife.multi.damgard import FeDamgardMulti
from mife_LWE import FeLWEMulti
from random import randrange
import time
from concurrent.futures import ProcessPoolExecutor
from functools import partial

X_BIT = 7
n_weights = 10
n = 3
m = 1
n_tests = 5000

bound = 1<<X_BIT

my_mife_obj = FeLWEMulti()

key = my_mife_obj.generate(n, m, Y_bit=1,X_bit=X_BIT, N=8  )

print('generated key')

x = [[1 for _ in range(m)] for _ in range(n_tests)]
y = [[1 for _ in range(m)] for _ in range(n)]

# print(x[0][0])

sk = my_mife_obj.keygen(y, key)


print('generated sk')
print('K =', key.pp.K)
print('B =', key.pp.B)
encrypt_with_key = partial(my_mife_obj.encrypt, key=key.get_enc_key(0))
start = time.time()
encrypted_model_set=[]
# for i in range(n_tests):
    # if i % 250 == 0:
    #     print(f'completed {i} tests')
    # cs = [my_mife_obj.encrypt(x[0], key.get_enc_key(0))] 

encrypted_model_set = [encrypt_with_key(x[i]) for i in range(len(x))]

print(f'generated cs in {time.time()-start}s')

start = time.time()
with ProcessPoolExecutor() as executor:
    encrypted_model_set.append(list(executor.map(encrypt_with_key, x)))

print(f'generated cs in {time.time()-start}s')

# ptx = my_mife_obj.decrypt(cs, key.pp, sk)

# print(ptx)