#########################################################
# Simple EC-DSA Program On SecP256-R1 Curve.            #
# Written By Muhammad Rajabinasab                       #
#                                                       #
# April 20, 2020                                        #
#########################################################
import random
import hashlib
from egcd import egcd


class Point:
    # since it is a demo program, selected curve is Curve P-256, in order to make calculations faster
    # also to use sha-256 in an easier way
    p = 26959946667150639794667015087019630673557916260026308143510066298881
    a = -3
    b = 18958286285566608000408668544493926415504680968679321075787234672564
    gx = 19277929113566293071110308034699488026831934219452440156649784352033
    gy = 19926808758034470970197974370888749184205991990603949537637343198772
    gn = 26959946667150639794667015087019625940457807714424391721682722368061
    #secp256r1 parameters, ready to use.
    #p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    #a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
    #b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
    #gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
    #gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109
    #gn = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def identity(self):
        ident = Point(Point.p, 0)
        return ident

    def is_on_curve(self):
        if self.x == self.p:
            return True
        y2 = (self.y * self.y) % self.p
        est = ((((((self.x * self.x) % self.p) + self.a) * self.x) % self.p) + self.b) % self.p
        if y2 == est:
            return True
        else:
            return False

    def add_points(self, p1, p2):
        if not p1.is_on_curve():
            raise Exception('Point is Not On Curve')
        if not p2.is_on_curve():
            raise Exception('Point is Not On Curve')
        if p1.x == self.p:
            return p2
        if p2.x == self.p:
            return p1
        if p1.x == p2.x:
            if p1.y == p2.y:
                s = mod_div(((3 * p1.x * p1.x) + self.a), (2*p1.y))
            else:
                return self.identity()
        else:
            s = mod_div((p2.y - p1.y), (p2.x - p1.x))
        v = (p1.y - (s * p1.x) % self.p) % self.p
        x = (s * s - p1.x - p2.x) % self.p
        y = (self.p - (s * x) % self.p - v) % self.p
        result = Point(x, y)
        return result

    def mul_point(self, k, point):
        if not point.is_on_curve():
            raise Exception('Point is Not On Curve')
        if point.x == self.p:
            return point
        if k % Point.gn == 0:
            return point
        kt = bin(k)[2:]
        determine = [int(d) for d in str(kt)]
        j = len(determine)
        res = self.identity()
        for i in range(0, j):
            res = self.add_points(res, res)
            if determine[i] == 1:
                res = self.add_points(res, point)
        return res


def mod_inv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
       raise Exception('No modular inverse')
    return x % m


def mod_div(a, b):
    b_inv = mod_inv(b % Point.p, Point.p)
    return ((a % Point.p) * b_inv) % Point.p


def hex2int(hexs):
    return int("".join(hexs.replace(":", "").split()), 16)


def generate_keypair():
    generator = Point(Point.gx, Point.gy)
    privatekey = random.randrange(1, Point.gn)
    publickey = generator.mul_point(privatekey, generator)
    return publickey, privatekey


def generate_signature(message, priv):
    generator = Point(Point.gx, Point.gy)
    digest = hashlib.sha256()
    digest.update(message)
    digint = hex2int(digest.hexdigest())
    r = 0
    s = 0
    while r == 0 | s == 0:
        k = random.randrange(1, Point.gn)
        kp = generator.mul_point(k, generator)
        r = kp.x % Point.gn
        k_inv = mod_inv(k, Point.gn)
        s = (k_inv*(digint+priv*r)) % Point.gn
    return r, s


def verify_signature(message, pub, r, s):
    generator = Point(Point.gx, Point.gy)
    digest = hashlib.sha256()
    digest.update(message)
    digint = hex2int(digest.hexdigest())
    w = mod_inv(s, Point.gn)
    u1 = (digint*w) % Point.gn
    u2 = (r*w) % Point.gn
    verifier = generator.add_points(generator.mul_point(u1, generator), generator.mul_point(u2, pub))
    v = verifier.x % Point.gn
    if v % Point.gn == r % Point.gn:
        return True
    else:
        return False


# Testing The Code...
print('')
print('Welcome to EC-DSA Test Program Written in Python by Muhammad Rajabinasab')
print('*'.center(80, '*'))
print('')
texts = input("Please Enter The Message You Want to Sign:")
text = str.encode(texts)
print('#'.center(80, '#'))
print('Program is Now Generating a Random Keypair For Testing Purpose...')
public, private = generate_keypair()
print('#'.center(80, '#'))
print('Program is Now Generating a Signature For Your Message...')
rt, st = generate_signature(text, private)
print('#'.center(80, '#'))
print('Testing Program Using Valid Signature...')
if verify_signature(text, public, rt, st):
    print('The Signature is Valid!')
else:
    print('The Signature is Not Valid!')
print('#'.center(80, '#'))
print('Testing Program Using Invalid Signature...')
if verify_signature(text, public, rt+1, st+1):
    print('The Signature is Valid!')
else:
    print('The Signature is Not Valid!')
print('')
print('*'.center(80, '*'))



