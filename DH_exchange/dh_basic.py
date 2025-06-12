
from crypto_utils import *

def demo():
    # common parameter 
    p = generate_prime(bits=512)
    g = 2  # The generator can be fixed to a small integer (e.g., 2 or 5) 

    print("=== common parameter ===")
    print("p =", p)
    print("g =", g)

    # Alice
    a_private = generate_private_key(p)
    a_public = generate_public_key(g, a_private, p)

    # Bob
    b_private = generate_private_key(p)
    b_public = generate_public_key(g, b_private, p)

    # shared key calculation 
    a_secret = compute_shared_secret(b_public, a_private, p)
    b_secret = compute_shared_secret(a_public, b_private, p)

    print("\n=== public key exchange (PKE) ===")
    print("Alice Public:", a_public)
    print("Bob Public:  ", b_public)

    print("\n=== shared key ===")
    print("Alice Shared Secret:", a_secret)
    print("Bob Shared Secret:  ", b_secret)

    assert a_secret == b_secret, "Shared key inconsistencies"
    print("\n The key exchange is successful, both sides share the same key")

if __name__ == "__main__":
    demo()
