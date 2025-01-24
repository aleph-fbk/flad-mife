#from mife.multi.damgard import FeDamgardMulti
from mife_DDH import FeDamgardMulti
import time
import cProfile


# n = 10000
# x = [1 for i in range(n)]
# y = [1 for i in range(n)]
# key = FeDDH.generate(n)
# c = FeDDH.encrypt(x, key)
# sk = FeDDH.keygen(y, key)
# start = time.time()
# m = FeDDH.decrypt(c, key.get_public_key(), sk, (0, 1000))
# end = time.time()
# print(end - start)

# print(m)

start = time.time()
n_weights = 10
n = 3
m = 10

generate_param_time = time.time()
key = FeDamgardMulti.generate(n, m)
generate_param_time = time.time() - generate_param_time

x = [[1 for j in range(m)] for i in range(n)]
y = [[1 for j in range(m)] for i in range(n)]

generate_key_time = time.time()
sk = FeDamgardMulti.keygen(y, key.pp, key)
generate_key_time = time.time() - generate_key_time

# cProfile.run('FeDamgardMulti.encrypt(x[0], key.get_enc_key(0))')
cicle_time = time.time()
for i in range(n_weights):
    cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
    
    #m = FeDamgardMulti.decrypt(cs, key.pp, sk, (0, 20000))

cicle_time = time.time() - cicle_time
end = time.time()
print(generate_key_time,generate_param_time,cicle_time,end - start)
print(m)