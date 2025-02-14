import math

import random

from secrets import randbelow
from Crypto.Util.number import getPrime
from typing import List
from mife.common import inner_product

from numpy import array as Matrix
from numpy import matmul, dot

# References:
# https://eprint.iacr.org/2017/972.pdf


class _FeLWEMulti_PP:
    def __init__(self, M: int, N: int, X_bit: int, Y_bit: int, p: int, n: int, m: int, q: int, B: float, sigma: float):
        """
        Initialize FeDamgardMulti oublic parameters
        
        :param X_bit: bit bound on user's single weight
        :param Y_bit: bit bound on y
        :param n: Number of parties
        :param m: Dimension of a party's input vector
        :param N: N(lambda) matrix dimension
        :param M: matrix other dimension
        :param p: Bound for final decryption
        :param q: Group size
        :param sigma: parameter in (0,1)
        :param B: q/p
        """
        self.X_bit = X_bit
        self.Y_bit = Y_bit
        self.p = p
        self.N = N
        self.M = M
        self.n = n
        self.m = m
        self.q = q
        self.sigma = sigma
        self.B = B

    def export(self):
        return {
            "X_bit" : self.X_bit,
            "Y_bit" : self.Y_bit,
            "p" : self.p,
            "N" : self.N,
            "M" : self.M,
            "n" : self.n,
            "m" : self.m,
            "B" : self.B,
            "q_bit" : math.log2(self.q),
            "sigma" : self.sigma,
        }

    def __str__(self):
       return f"X_bit = {self.X_bit},\nY_bit = {self.Y_bit},\np = {self.p},\nN = {self.N},\nM = {self.M},\nn = {self.n},\nm = {self.m},\nB_bit = {math.log2(self.B)},\nq_bit = {math.log2(self.q)},\nsigma = {self.sigma}" 
        


class _FeLWEMulti_MPKi:

    def __init__(self, U: Matrix, A: Matrix):
        """
        Initialize FeDamgardMulti master public key

        :param a: [1, random_element]
        :param wa: W * a
        """
        self.U = U
        self.A = A

    def export(self):
        pass


class _FeLWEMulti_MSKi:

    def __init__(self, s: Matrix, u: Matrix):
        """
        Initialize FeDamgardMulti master secret key

        :param w: [[random_element, random_element] for _ in range(m)]]
        """
        self.s = s
        self.u = u

    def export(self):
        pass

class _FeLWEMulti_EncK:
    def __init__(self, pp: _FeLWEMulti_PP, mpk: _FeLWEMulti_MPKi, u: Matrix):
        """
        Initialize FeDamgardMulti encryption key

        :param g: Generator of the group
        :param F: Group to use for the scheme
        :param mpk: Master public key
        """
        self.pp = pp
        self.mpk = mpk
        self.u = u

    def export(self):
        pass



class _FeLWEMulti_MK:
    def __init__(self, pp: _FeLWEMulti_PP,
                 mpk: list[_FeLWEMulti_MPKi], msk: list[_FeLWEMulti_MSKi] = [None]):
        """
        Initialize FeDamgardMulti master key

        :param pp: Public parameters
        :param mpk: Master public key
        :param msk: Master secret key
        """

        self.pp = pp
        self.msk = msk
        self.mpk = mpk

    def get_enc_key(self, index: int):
        """
        Get the encryption key for a client

        :param index: Index of the client
        :return: Encryption key for the client
        """
        if not self.has_private_key:
            raise Exception("The master key has no private key")
        if not (0 <= index < self.pp.n):
            raise Exception(f"Index must be within [0,{self.n})")
        return _FeLWEMulti_EncK(self.pp, self.mpk[index], self.msk[index].u)

    def has_private_key(self) -> bool:
        return self.msk[0] is not None

    def get_public_key(self, index: int):
        return _FeLWEMulti_MK(self.pp, self.mpk[index])
    
    def get_private_key(self, index: int):
        return self.msk[index]

    def export(self):
        return {
            "pp": self.pp.export(),
            "mpk": [self.mpk[i].export() for i in range(self.n)],
            "msk": [self.msk[i].export() for i in range(self.n)] if self.msk[0] is not None else [None]
        }


class _FeLWEMulti_SK:
    def __init__(self, y: List[Matrix], Zy: List[Matrix], z: int):
        """
        Initialize FeDamgardMulti decryption key

        :param y: Function vector
        :param d: [y[i] * w for i in range(n)]
        :param z: <u, y>
        """
        self.y = y
        self.Zy = Zy
        self.z = z

    def export(self):
        pass


class _FeLWEMulti_C:
    def __init__(self, c0: Matrix, c1: Matrix):
        self.c0 = c0
        self.c1 = c1

    def export(self):
        pass


class FeLWEMulti:
    # @staticmethod
    # def sample(sigma1: float, sigma2: float, l: int, m: int):
    #     sys_random = random.SystemRandom()
    #     res = []
    #     half1 = m // 2
    #     half2 = m - half1
    #     for i in range(l):
    #         row1 = [round(sys_random.gauss(0, sigma1)) for _ in range(half1)]
    #         row2 = [round(sys_random.gauss(0, sigma2)) for _ in range(half2)]
    #         row2[i] += 1
    #         res.append(row1 + row2)
    #     return Matrix(res, dtype=object)
    
    @staticmethod
    def generate(n: int, m: int, X_bit: int, Y_bit: int, N: int = None) -> _FeLWEMulti_MK:
        """
        Generate a FeDamgardMulti master key

        :param n: Number of vector positions
        :param m: Dimension of the vector in each input
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :return: FeDamgardMulti master key
        """

        # K = (3*n*m) << (X_bit + Y_bit)

       # p = getPrime(n.bit_length()+m.bit_length()+X_bit+Y_bit+2)
        p = getPrime(n.bit_length()+m.bit_length()+X_bit+Y_bit+2)

        if N is None:
            N = max(m, 64)

        res= (math.sqrt(m) * 2**X_bit +1)* p * 2**Y_bit * math.sqrt(N+m+1) * 8*N
        res = math.sqrt(res)* res
        res = math.ceil(res)
        q = getPrime(res.bit_length())
        # alpha = 1 / (K * K * (N * q.bit_length()) ** 7)
        M = (N + m + 1) * q.bit_length() + 2 * N + 1

        sigma = 1 / (2 * math.sqrt(M * N * 2 * m) * p * (1<<(Y_bit)))
        

        val = math.sqrt(m) * (1<<X_bit) + 1

        val = q/val

        if val <= 2 * math.sqrt(N):
            raise Exception("q too small")

        B = q/p

        pp = _FeLWEMulti_PP(M, N, X_bit, Y_bit, p, n, m ,q, B, sigma)

        msk = []
        mpk = []

        # sigma1 = math.sqrt(N * M.bit_length()) * max(math.sqrt(M), K)
        # sigma2 = math.sqrt((N ** 7) * M * (M.bit_length() ** 5)) * max(M, K * K)

        #print(pp)

        sys_random = random.SystemRandom()
        
        for _ in range(n):
            u = Matrix([randbelow(p) for _ in range(m)])
            #u = Matrix([0 for _ in range(m)])
            A = Matrix([[randbelow(q) for _ in range(N)] for _ in range(M)], dtype=object)
            s = Matrix([[randbelow(q) for _ in range(m)] for _ in range(N)], dtype=object)
            
            E = Matrix([[round(sys_random.gauss(0, sigma)) for _ in range(m)] for _ in range(M)], dtype=object)# Matrix([[randbelow(q) for _ in range(N)] for _ in range(m)], dtype=object)
            #E = Matrix([[0 for _ in range(m)] for _ in range(M)], dtype=object)

            U = (A@s + E) % q

            msk.append(_FeLWEMulti_MSKi(s,u))
            mpk.append(_FeLWEMulti_MPKi(U,A))    

        return _FeLWEMulti_MK(pp, mpk, msk)

    @staticmethod
    def encrypt(x: List[int], key: _FeLWEMulti_EncK) -> _FeLWEMulti_C:
        pp = key.pp
        if len(x) != pp.m:
            raise Exception("Encrypt vector must be of length l")

        # sys_random = random.SystemRandom()
        x = Matrix(x, dtype=object)
        r = Matrix([randbelow(2) for _ in range(pp.M)], dtype=object)
        # e0 = Matrix([round(sys_random.gauss(0, pp.alpha * pp.q)) for _ in range(pp.M)], dtype=object)
        # e1 = Matrix([round(sys_random.gauss(0, pp.alpha * pp.q)) for _ in range(pp.m)], dtype=object)

        c0 = ((key.mpk.A.T @ r)) % pp.q

        ptx = pp.B * ((x + key.u %pp.p))  
        ptx = Matrix([round(elem)  for elem in ptx]) # rounding

        #ptx = Matrix([math.floor(elem) %  pp.q for elem in ptx]) # rounding

        c1 = (key.mpk.U.T @ r) +  ptx % pp.q
        
        return _FeLWEMulti_C(c0, c1)

    @staticmethod
    def decrypt(c: list[_FeLWEMulti_C], pp: _FeLWEMulti_PP, sk: _FeLWEMulti_SK) -> int:

        u = sum([((sk.y[i] @ c[i].c1) - (sk.Zy[i] @ c[i].c0)) % pp.q for i in range(pp.n)]) % pp.q
        u = (u - pp.B*sk.z) %pp.q

    
        '''
        res = abs(u)
        i= 1
        while(True):
            res1 = abs(u - math.floor(pp.B*i))
            if res1 > res:
                return res
            res = res1
            i = i+ 1
        '''
        t = (u / pp.B)
        answer = (t - (-pp.p + 1) + 1)
        if answer > pp.p//2:
            answer -= pp.p
        if answer > pp.p//2:
            return round(answer - pp.p)
        return round(answer)
        '''

        q_half = math.floor(pp.q/2)
        d= u
        if d > q_half:
            d= d- pp.q
        d = d * pp.p
        d = d + q_half
        d = math.floor(d / pp.q)
        return d
         '''

    @staticmethod
    def keygen(y: List[List[int]], key: _FeLWEMulti_MK) -> _FeLWEMulti_SK:
        if len(y[0]) != key.pp.m:
            raise Exception(f"Function vector must be of length {key.pp.m}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        y = [Matrix(y[i], dtype=object) for i in range(key.pp.n)]
        Zy = [(key.msk[i].s @ y[i]) % key.pp.q for i in range(key.pp.n)] 
        z = (sum([((y[i].T @ (key.msk[i].u )))  for i in range(key.pp.n)])) % key.pp.q
        return _FeLWEMulti_SK(y, Zy, z)