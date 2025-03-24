from secrets import randbelow
from typing import List

from mife.data.matrix import Matrix
from mife.common import discrete_log_bound, inner_product, getStrongPrime
from mife.data.group import GroupBase, GroupElem
from mife.data.zmod import Zmod

# References:
# https://eprint.iacr.org/2017/972.pdf


class _FeDamgardMulti_PP:
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase, X_bit: int):
        """
        Initialize FeDamgardMulti oublic parameters
        
        :param g: Generator of the group
        :param n: Number of vector positions
        :param m: Dimension of the vector in each input
        :param F: Group to use for the scheme
        """
        self.g = g
        self.n = n
        self.m = m
        self.F = F
        self.B = (1<<X_bit)*self.m

    def to_group(self, x: int) -> GroupElem:
        return x * self.g

    def export(self):
        return {
            "g": self.g.export(),
            "n": self.n,
            "m": self.m,
            "F": self.F.export(),
        }

    def __str__(self): 
        return f"n = {self.n},\nm = {self.m},\nx_bit = {(self.B).bit_length()},\nq = {self.F.order().bit_length()}" 


class _FeDamgardMulti_MPKi:

    def __init__(self, h: Matrix,):
        """
        Initialize FeDamgardMulti master public key of the single client 
        h is a 1xm matrix
        """
        self.h = h

    def export(self):
        return {
            "h": self.h.export(),
           
        }


class _FeDamgardMulti_MSKi:

    def __init__(self, s: Matrix, u: Matrix):
        """
        Initialize FeDamgardMulti master secret key of the single client

        :param s: it is a 1xm matrix
        :param u: it is a 1xm matrix
        """
        self.s = s
        self.u = u

    def export(self):
        return {
            "s": self.w.export(),
            "u": self.u.export()
        }

class _FeDamgardMulti_EncK:
    def __init__(self, pp: _FeDamgardMulti_PP, mpk: _FeDamgardMulti_MPKi, u: int):
        """
        Initialize FeDamgardMulti encryption key of the single client

        :param g: Generator of the group
        :param F: Group to use for the scheme
        :param mpk: Master public key
        :param u: Some row of the original u matrix
        """
        self.pp = pp
        self.mpk = mpk
        self.u = u

    def export(self):
        return {
            "pp": self.pp.export(),
            "mpk": self.mpk.export(),
            "u": self.u.export()
        }



class _FeDamgardMulti_MK:
    def __init__(self, pp: _FeDamgardMulti_PP,
                 mpk: list[_FeDamgardMulti_MPKi], msk: list[_FeDamgardMulti_MSKi] = [None]):
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
        return _FeDamgardMulti_EncK(self.pp, self.mpk[index], self.msk[index].u)

    def has_private_key(self) -> bool:
        return self.msk[0] is not None

    def get_public_key(self, index: int):
        return _FeDamgardMulti_MK(self.pp, self.mpk[index])
    
    def get_private_key(self, index: int):
        return self.msk[index]

    def export(self):
        return {
            "pp": self.pp.export(),
            "mpk": [self.mpk[i].export() for i in range(self.n)],
            "msk": [self.msk[i].export() for i in range(self.n)] if self.msk[0] is not None else [None]
        }


class _FeDamgardMulti_SK:
    def __init__(self,y: List[List[int]], sy: List[List[int]], z: List[int], LUT:dict):
        """
        Initialize FeDamgardMulti decryption key

        :param y: Function vector
        :param d: [y[i] * w for i in range(n)]
        :param z: <u, y>
        """
        self.y = y
        self.sy = sy
        self.z = z
        self.LUT = LUT

    def export(self):
        return {
            "sy": [[int(i) for i in vec] for vec in self.y],
            "z": self.z
        }

class _FeDamgardMulti_C:
    def __init__(self, c0: GroupElem, c: list[GroupElem]):
        """
        Initialize FeDamgardMulti cipher text

        :param c0:  g^r
        :param c: h^r g^x
        """
        self.c0 = c0
        self.c = c

    def export(self):
        return {
            "t": self.t.export(),
            "c": self.c.export()
        }


class FeDamgardMulti:
    @staticmethod
    def generate(n: int, m: int, X_bit:int, q_bit: int, F: GroupBase = None) -> _FeDamgardMulti_MK:
        """
        Generate a FeDamgardMulti master key

        :param n: Number of vector positions
        :param m: Dimension of the vector in each input
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :return: FeDamgardMulti master key
        """
        if F is None:
            F = Zmod(getStrongPrime(q_bit))
        g = F.generator()
        to_group = lambda x: x * g

        pp = _FeDamgardMulti_PP(g, n, m, F, X_bit)

        mpk = []
        msk = []

        for _ in range(n):
            s = Matrix([ randbelow(F.order()) for _ in range(m)])
            u = Matrix([randbelow(F.order()) for _ in range(m)])

            
            msk.append(_FeDamgardMulti_MSKi(s, u))
            mpk.append(_FeDamgardMulti_MPKi((s).apply_func(to_group)))

        return _FeDamgardMulti_MK(pp, mpk, msk)

    @staticmethod
    def encrypt(x: List[int], key: _FeDamgardMulti_EncK) -> _FeDamgardMulti_C:
        """
        Encrypt a message vector

        :param x: Message vector (Dimension must be m)
        :param key: FeDamgardMulti public key
        :return: FeDamgardMulti cipher text
        """
        x = Matrix(x)
        r = randbelow(key.pp.F.order())

        c0 = key.pp.to_group(r)

        c = (x + key.u).apply_func(key.pp.to_group) +  r * key.mpk.h
        return _FeDamgardMulti_C(c0, list(c))

    @staticmethod
    def decrypt(c: List[_FeDamgardMulti_C], pp: _FeDamgardMulti_PP, sk: _FeDamgardMulti_SK) -> int:
        """
        Decrypt a message vector

        :param c: FeDamgardMulti cipher text
        :param pp: FeDamgardMulti public parameters
        :param sk: FeDamgardMulti decryption key
        :param bound: Bound for the discrete log problem
        :return: Decrypted message vector
        """
        bound = [-pp.B*pp.n,pp.B*pp.n]
        cul = pp.F.identity()
        for i in range(pp.n):
            # [ct^yi]
            yc = inner_product(sk.y[i], c[i].c[:][0], identity=pp.F.identity())
            dt = sk.sy[i] * c[i].c0
            # co^sky
            cul = cul + yc - dt
            
        cul = cul - pp.to_group(sk.z)
        return sk.LUT[cul.__hash__()]
    
    @staticmethod
    def keygen(y: List[List[int]], key: _FeDamgardMulti_MK) -> _FeDamgardMulti_SK:
        """
        Generate a FeDamgardMulti decryption key

        :param y: Function vector (n x m matrix)
        :param key: FeDamgardMulti master key
        :return: FeDamgardMulti decryption key
        """

        LUT = {}
        if len(y) != key.pp.n:
            raise Exception(f"Function vector must be a {key.pp.n} x {key.pp.m} matrix")
        
        d = []  
        z = 0  

        for i in range(key.pp.n):
            if len(y[i]) != key.pp.m:
                raise Exception(f"Function vector must be a {key.pp.n} x {key.pp.m} matrix")
            
            y_i = Matrix(y[i])  
            d.append(y_i.dot(key.msk[i].s))  # Compute <y, msk.s[i]> for each i
            z += y_i.dot(key.msk[i].u)  

        LUT[1] = 0
        bound = key.pp.B*key.pp.n
        
        keyp = key.pp.g
        keyn = -key.pp.g
        for i in range(1,bound+1):
            LUT[keyp.__hash__()] = i 
            LUT[keyn.__hash__()] = -i
            
            keyp += key.pp.g
            keyn -= key.pp.g

        return _FeDamgardMulti_SK(y, d, z, LUT)
