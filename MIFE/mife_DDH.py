from secrets import randbelow
from typing import List, Tuple

from mife.data.matrix import Matrix
from mife.common import discrete_log_bound, inner_product, getStrongPrime
from mife.data.group import GroupBase, GroupElem
from mife.data.zmod import Zmod

# References:
# https://eprint.iacr.org/2017/972.pdf


class _FeDamgardMulti_PP:
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase):
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
        self.to_group = lambda x: x * self.g

    def export(self):
        return {
            "g": self.g.export(),
            "n": self.n,
            "m": self.m,
            "F": self.F.export(),
        }


class _FeDamgardMulti_MPKi:

    def __init__(self, a: Matrix, wa: Matrix):
        """
        Initialize FeDamgardMulti master public key

        :param a: [1, random_element]
        :param wa: W * a
        """
        self.a = a
        self.wa = wa

    def export(self):
        return {
            "a": self.a.export(),
            "wa": self.wa.export()
        }


class _FeDamgardMulti_MSKi:

    def __init__(self, w: Matrix, u: Matrix):
        """
        Initialize FeDamgardMulti master secret key

        :param w: [[random_element, random_element] for _ in range(m)]]
        :param u: [random_element for _ in range(m)]
        """
        self.w = w
        self.u = u

    def export(self):
        return {
            "w": self.w.export(),
            "u": self.u.export()
        }

class _FeDamgardMulti_EncK:
    def __init__(self, pp: _FeDamgardMulti_PP, mpk: _FeDamgardMulti_MPKi, u: Matrix):
        """
        Initialize FeDamgardMulti encryption key

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
    def __init__(self, y: List[List[int]], d: List[Matrix], z: int):
        """
        Initialize FeDamgardMulti decryption key

        :param y: Function vector
        :param d: [y[i] * w for i in range(n)]
        :param z: <u, y>
        """
        self.y = y
        self.d = d
        self.z = z

    def export(self):
        return {
            "y": [[int(i) for i in vec] for vec in self.y],
            "d": [x.export() for x in self.d],
            "z": self.z
        }


class _FeDamgardMulti_C:
    def __init__(self, t: Matrix, c: Matrix):
        """
        Initialize FeDamgardMulti cipher text

        :param t:  r * a
        :param c: [(x[i] + u[i]) * g] + r * wa
        """
        self.t = t
        self.c = c

    def export(self):
        return {
            "t": self.t.export(),
            "c": self.c.export()
        }


class FeDamgardMulti:
    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None) -> _FeDamgardMulti_MK:
        """
        Generate a FeDamgardMulti master key

        :param n: Number of vector positions
        :param m: Dimension of the vector in each input
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :return: FeDamgardMulti master key
        """
        if F is None:
            F = Zmod(getStrongPrime(1024))
        g = F.generator()
        to_group = lambda x: x * g

        pp = _FeDamgardMulti_PP(g, n, m, F)

        mpk = []
        msk = []

        for _ in range(n):
            a_v = Matrix([1, randbelow(F.order())])
            W = Matrix([[randbelow(F.order()), randbelow(F.order())] for _ in range(m)])
            u = Matrix([randbelow(F.order()) for _ in range(m)])

            
            msk.append(_FeDamgardMulti_MSKi(W, u))
            mpk.append(_FeDamgardMulti_MPKi(a_v.apply_func(to_group), (W * a_v.T).apply_func(to_group)))

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

        t = r * key.mpk.a

        c = (x + key.u).apply_func(lambda x: x * key.pp.g) + (r * key.mpk.wa).T

        return _FeDamgardMulti_C(t, c)

    @staticmethod
    def decrypt(c: List[_FeDamgardMulti_C], pp: _FeDamgardMulti_PP, sk: _FeDamgardMulti_SK,
                bound: Tuple[int, int]) -> int:
        """
        Decrypt a message vector

        :param c: FeDamgardMulti cipher text
        :param pp: FeDamgardMulti public parameters
        :param sk: FeDamgardMulti decryption key
        :param bound: Bound for the discrete log problem
        :return: Decrypted message vector
        """
        cul = pp.F.identity()
        for i in range(pp.n):
            # [y_i dot c_i]
            yc = inner_product(sk.y[i], c[i].c[0], identity=pp.F.identity())

            # [d_i dot t_i]
            dt = inner_product(sk.d[i][0], c[i].t[0], identity=pp.F.identity())

            cul = cul + yc - dt

        cul = cul - pp.to_group(sk.z)
        return discrete_log_bound(cul, pp.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], pp: _FeDamgardMulti_PP, msk: list[_FeDamgardMulti_MSKi]) -> _FeDamgardMulti_SK:
        """
        Generate a FeDamgardMulti decryption key

        :param y: Function vector (n x m matrix)
        :param pp: FeDamgardMulti public parameters
        :param msk: FeDamgardMulti master secret key
        :return: FeDamgardMulti decryption key
        """
        if len(y) != pp.n:
            raise Exception(f"Function vector must be a {pp.n} x {pp.m} matrix")
        d = []
        z = 0
        for i in range(pp.n):
            if len(y[i]) != pp.m:
                raise Exception(f"Function vector must be a {pp.n} x {pp.m} matrix")
            y_i = Matrix(y[i])
            d.append(y_i * msk.get_private_key(i).w)
            z += y_i.dot(msk.get_private_key(i).u)

        return _FeDamgardMulti_SK(y, d, z)