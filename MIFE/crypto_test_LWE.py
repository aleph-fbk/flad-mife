#from mife.multi.damgard import FeDamgardMulti
from mife_LWE import FeLWEMulti
from random import randrange
import time
import cProfile
from concurrent.futures import ProcessPoolExecutor
from functools import partial
import pstats
from io import StringIO

X_BIT = 11
N = 16
n_weights = 1
n = 3
m = 1
n_tests = 5000

bound = 1<<X_BIT

my_mife_obj = FeLWEMulti()


key = my_mife_obj.generate(n, m, Y_bit=1,X_bit=X_BIT, N=N)

print('generated key')

x = [[-1 for _ in range(m)] for _ in range(n)]
y = [[1 for _ in range(m)] for _ in range(n)]

# print(x[0][0])

sk = my_mife_obj.keygen(y, key)


print('generated sk')
print('K =', key.pp.K)
print('B =', key.pp.B)
encrypt_with_key = partial(my_mife_obj.encrypt, key=key.get_enc_key(0))

encrypted_model_set=[]
# for i in range(n_tests):
    # if i % 250 == 0:
    #     print(f'completed {i} tests')
    # cs = [my_mife_obj.encrypt(x[0], key.get_enc_key(0))] 
def encrypt_with_key(x, key, encrypted_model_set):
    encrypted_model_set = [my_mife_obj.encrypt(x[i],key.get_enc_key(i)) for i in range(len(x))]

# Profile the function
profiler = cProfile.Profile()
start = time.time()
profiler.enable()
encrypt_with_key(x, key, encrypted_model_set)
profiler.disable()
print(f'generated cs in {time.time()-start}s')

# Capture the output and format precision
output = StringIO()
stats = pstats.Stats(profiler, stream=output)
stats.strip_dirs().sort_stats('cumulative').print_stats()

# Display the result with precision control
lines = output.getvalue().strip().split("\n")
for line in lines:
    parts = line.split()
    # Check if the first part is a valid integer and if the line has enough parts for timing values
    if len(parts) >= 5 and parts[0].isdigit():
        try:
            # Format timing values with more decimals
            ncalls = parts[0]
            tottime = f"{float(parts[1]):.5f}"
            percall_tottime = f"{float(parts[2]):.3f}"
            cumtime = f"{float(parts[3]):.3f}"
            percall_cumtime = f"{float(parts[4]):.3f}"
            function_info = " ".join(parts[5:])
            print(f"{ncalls:>8} {tottime:>12} {percall_tottime:>12} {cumtime:>12} {percall_cumtime:>12} {function_info}")
        except ValueError:
            continue

# start = time.time()
# with ProcessPoolExecutor() as executor:
#     encrypted_model_set.append(list(executor.map(encrypt_with_key, x)))

# print(f'generated cs in {time.time()-start}s')

# ptx = my_mife_obj.decrypt(encrypted_model_set, key.pp, sk)

# print(ptx)