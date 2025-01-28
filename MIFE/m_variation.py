#from mife.multi.damgard import FeDamgardMulti
from mife_LWE import FeLWEMulti
import time
from random import randrange
import matplotlib.pyplot as plt

n_weights = 10
n = 1
X_bit = 30
bound = 1 << X_bit
x_ax = []
y_ax = []
count = 0


for m in range(40,89,2):

    key = FeLWEMulti.generate(n, m, X_bit, 1)
    print("##################")
    print(f'm = {m}')
    print('generated key')
    count += 1

    x = [randrange(0,bound) for j in range(m)]
    # y = [1 for j in range(n)]

    # sk = FeLWEMulti.keygen(y, key)

    print('generated sk')

    start = time.time()
    
    cs = FeLWEMulti.encrypt(key.pp, x, key.get_enc_key(0)) 

    t = time.time()-start
    print(f'generated cs in {t}s')

    #ptx = FeLWEMulti.decrypt(cs, key.pp, sk)

    x_ax.append(m)
    y_ax.append(t)

    if count > 1:
        temp = (y_ax[count-1] - y_ax[count-2]) / (x_ax[count-1] - x_ax[count-2])
        print(f't_{count} - t_{count-1} / (m_{count} - m{count-1}) = {temp}')


plt.plot(x_ax, y_ax, 'ro')
plt.show()