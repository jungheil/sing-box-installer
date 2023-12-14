import base64
import getpass
import random
from functools import wraps
from typing import Tuple


def input_args(name: str, type: type, prompt: str, default=None, is_pass: bool = False):
    input_func = getpass.getpass if is_pass else input

    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            if name in kwargs:
                return func(*args, **kwargs)
            if default is None:
                print(prompt + ": ")
                value = type(input_func("> "))
            else:
                print(prompt + f" [{default}]" + ": ")
                value = type(input_func("> ") or default)
            kwargs[name] = value
            return func(*args, **kwargs)

        return inner

    return wrapper


class Registry:
    def __init__(self):
        self._data_dict = {}

    @property
    def data_dict(self):
        return self._data_dict

    def register(self, name: str):
        def wrapper(obj: object):
            self._data_dict[name] = obj
            return obj

        return wrapper

    def get(self, name: str):
        return self._data_dict.get(name)

    def remove(self, name: str):
        return self._data_dict.pop(name, None)


def generate_private_key():
    key = bytes(random.randint(0, 255) for _ in range(32))
    key = bytearray(key)
    key[0] &= 248
    key[31] &= 127
    key[31] |= 64
    return bytes(key)


def curve25519(n):
    b = 256
    q = 2**255 - 19
    P = q
    A = 486662

    def _clamp(n):
        n = bytearray(n)
        n[0] &= 248
        n[31] = (n[31] & 127) | 64
        return n

    def _double(n):
        (xn, zn) = n
        x = (xn**2 - zn**2) ** 2
        z = 4 * xn * zn * (xn**2 + A * xn * zn + zn**2)
        return (x % P, z % P)

    def _add(n, m, d):
        (xn, zn) = n
        (xm, zm) = m
        (xd, zd) = d
        x = 4 * (xm * xn - zm * zn) ** 2 * zd
        z = 4 * (xm * zn - zm * xn) ** 2 * xd
        return (x % P, z % P)

    def _expmod(b, e, m):
        if e == 0:
            return 1
        t = _expmod(b, e // 2, m) ** 2 % m
        if e & 1:
            t = (t * b) % m
        return t

    def _inv(x):
        return _expmod(x, q - 2, q)

    def _bit(h, i):
        return (h[i // 8] >> (i % 8)) & 1

    def _curve25519(n, base=9):
        one = (base, 1)
        two = _double(one)

        def f(m):
            if m == 1:
                return (one, two)
            (pm, pm1) = f(m // 2)
            if m & 1:
                return (_add(pm, pm1, one), _double(pm1))
            return (_double(pm), _add(pm, pm1, one))

        ((x, z), _) = f(n)
        return (x * _inv(z)) % P

    def _decodeint(s):
        return sum(2**i * _bit(s, i) for i in range(0, b))

    def _encodeint(y):
        bits = [(y >> i) & 1 for i in range(b)]
        e = [(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b // 8)]
        return bytes(e)

    n = _clamp(n)

    for fn in (
        _decodeint,
        _curve25519,
        _encodeint,
    ):
        n = fn(n)

    return n


def generate_reality_key() -> Tuple[str, str]:
    private_key = generate_private_key()
    public_key = curve25519(private_key)
    private_key_b64 = base64.urlsafe_b64encode(private_key).decode().rstrip("=")
    public_key_b64 = base64.urlsafe_b64encode(public_key).decode().rstrip("=")
    return private_key_b64, public_key_b64
