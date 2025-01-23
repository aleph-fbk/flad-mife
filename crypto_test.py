from mife.single.selective.ddh import FeDDH
import time


n = 10000
x = [1 for i in range(n)]
y = [1 for i in range(n)]
key = FeDDH.generate(n)
c = FeDDH.encrypt(x, key)
sk = FeDDH.keygen(y, key)
start = time.time()
m = FeDDH.decrypt(c, key.get_public_key(), sk, (0, 1000))
end = time.time()
print(end - start)

print(m)