import hashlib

def weak_hash(password):
    # Danger: MD5 is broken and insecure (B303)
    return hashlib.md5(password.encode()).hexdigest()

def insecure_random():
    import random
    # Danger: Standard random is predictable (B311)
    return random.random()
