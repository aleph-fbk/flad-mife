from secrets import randbelow
from typing import List

from mife.data.matrix import Matrix
from mife.common import discrete_log_bound, inner_product, getStrongPrime
from mife.data.group import GroupBase, GroupElem
from mife.data.zmod import Zmod

# References:
# https://eprint.iacr.org/2017/972.pdf


class _FeDDHMulti_PP:
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase, X_bit: int):
        """
        Initialize FeDDHMulti oublic parameters
        
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


class _FeDDHMulti_CSKi:

    def __init__(self, h: Matrix,):
        """
        Initialize FeDDHMulti client's encryption key
        
        :param h: it is a nxm matrix
        """

        self.h = h

    def export(self):
        return {
            "h": self.h.export(),
           
        }


class _FeDDHMulti_MSKi:

    def __init__(self, s: Matrix, u: Matrix):
        """
        Initialize each client part of the FeDDHMulti master secret key
        
        :param s: it is a 1xm matrix
        :param u: it is a 1xm matrix
        """
        self.s = s
        self.u = u

    def export(self):
        return {
            "s": self.s.export(),
            "u": self.u.export()
        }

class _FeDDHMulti_EncK:
    def __init__(self, pp: _FeDDHMulti_PP, cski: _FeDDHMulti_CSKi, ui: List[int]):
        """
        Initialize FeDDHMulti encryption key of the single client

        :param pp: Public parameters
        :param cski: Client's secret key
        :param ui: A row of the original u matrix
        """
        self.pp = pp
        self.cski = cski
        self.ui = ui

    def export(self):
        return {
            "pp": self.pp.export(),
            "cski": self.cski.export(),
            "u": self.ui.export()
        }



class _FeDDHMulti_MK:
    def __init__(self, pp: _FeDDHMulti_PP,
                 csk: list[_FeDDHMulti_CSKi], msk: list[_FeDDHMulti_MSKi] = [None]):
        """
        Initialize FeDDHMulti master key

        :param pp: Public parameters
        :param csk: List of all clients' secret keys
        :param msk: Master secret key
        """

        self.pp = pp
        self.msk = msk
        self.csk = csk

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
        return _FeDDHMulti_EncK(self.pp, self.csk[index], self.msk[index].u)

    def has_private_key(self) -> bool:
        return self.msk[0] is not None

    def get_public_key(self, index: int):
        return _FeDDHMulti_MK(self.pp, self.csk[index])
    
    def get_private_key(self, index: int):
        return self.msk[index]

    def export(self):
        return {
            "pp": self.pp.export(),
            "csk": [self.mpk[i].export() for i in range(self.n)],
            "msk": [self.msk[i].export() for i in range(self.n)] if self.msk[0] is not None else [None]
        }


class _FeDDHMulti_SK:
    def __init__(self,y: List[List[int]], d: List[int], z: int, LUT:dict):
        """
        Initialize FeDDHMulti decryption key

        :param y: Function vector
        :param d: [<y[i],s[i]> for i in range(n)]
        :param z: <u, y>
        """
        self.y = y
        self.d = d
        self.z = z
        self.LUT = LUT

    def export(self):
        return {
            "y": [[int(i) for i in vec] for vec in self.y],
            "d": [x.export() for x in self.d],
            "z": self.z,
            "LUT": self.LUT.export()
        }

class _FeDDHMulti_C:
    def __init__(self, c0: GroupElem, c: list[GroupElem]):
        """
        Initialize FeDDHMulti cipher text

        :param c0:  g^r
        :param c: h^r g^x
        """
        self.c0 = c0
        self.c = c

    def export(self):
        return {
            "c0": self.c0.export(),
            "c": self.c.export()
        }


class FeDDHMulti:
    @staticmethod
    def generate(n: int, m: int, X_bit:int, q_bit: int, F: GroupBase = None) -> _FeDDHMulti_MK:
        """
        Generate a FeDDHMulti master key

        :param n: Number of vector positions
        :param m: Dimension of the vector in each input
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :return: FeDDHMulti master key
        """
        if F is None:
            F = Zmod(getStrongPrime(q_bit))
        g = F.generator()
        to_group = lambda x: x * g

        pp = _FeDDHMulti_PP(g, n, m, F, X_bit)

        csk = []
        msk = []

        for _ in range(n):
            s = Matrix([ randbelow(F.order()) for _ in range(m)])
            u = Matrix([randbelow(F.order()) for _ in range(m)])

            
            msk.append(_FeDDHMulti_MSKi(s, u))
            csk.append(_FeDDHMulti_CSKi((s).apply_func(to_group)))

        return _FeDDHMulti_MK(pp, csk, msk)

    @staticmethod
    def encrypt(x: List[int], key: _FeDDHMulti_EncK) -> _FeDDHMulti_C:
        """
        Encrypt a message vector

        :param x: Message vector (Dimension must be m)
        :param key: FeDDHMulti public key
        :return: FeDDHMulti ciphertext
        """
        x = Matrix(x)
        r = randbelow(key.pp.F.order())

        c0 = key.pp.to_group(r)

        c = (x + key.ui).apply_func(key.pp.to_group) +  r * key.cski.h
        return _FeDDHMulti_C(c0, list(c))

    @staticmethod
    def decrypt(c: List[_FeDDHMulti_C], pp: _FeDDHMulti_PP, sk: _FeDDHMulti_SK) -> int:
        """
        Decrypt a message vector

        :param c: FeDDHMulti cipher text
        :param pp: FeDDHMulti public parameters
        :param sk: FeDDHMulti decryption key
        :return: Decrypted message
        """
        #bound = [-pp.B*pp.n,pp.B*pp.n]
        cul = pp.F.identity()
        for i in range(pp.n):
            # [ct^yi]
            yc = inner_product(sk.y[i], c[i].c[:][0], identity=pp.F.identity())
            dt = sk.d[i] * c[i].c0
            # co^sky
            cul = cul + yc - dt
            
        cul = cul - pp.to_group(sk.z)
        return sk.LUT[cul.__hash__()]
    
    @staticmethod
    def keygen(y: List[List[int]], key: _FeDDHMulti_MK) -> _FeDDHMulti_SK:
        """
        Generate a FeDDHMulti decryption key

        :param y: Function vector (n x m matrix)
        :param key: FeDDHMulti master key
        :return: FeDDHMulti decryption key
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

        return _FeDDHMulti_SK(y, d, z, LUT)
