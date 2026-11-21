import hashlib


def digest(p):
    return hashlib.md5(p).hexdigest()
