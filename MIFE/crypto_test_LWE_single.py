from mife.single.lwe import FeLWE

n = 10
x = [1 for i in range(n)]
y = [1 for i in range(n)]
key = FeLWE.generate(n, 4, 4)
c = FeLWE.encrypt(x, key)
sk = FeLWE.keygen(y, key)
m = FeLWE.decrypt(c, key.get_public_key(), sk)

print(m)