from crypto_utils import *

# === Diffie-Hellman Implementation of Asymmetric Signatures (using ECDSA) ===

def signed_dh_demo():
    print("=== Diffie-Hellman with authentication (using ECDSA signatures) ===\n")

    # common parameter
    p = generate_prime(512)
    g = 2
    print(f"[parameter] p = {p}\n[parameter] g = {g}\n")

    # Use ECDSA key signing
    alice_priv_key, alice_pub_key = generate_ecdsa_keypair()
    bob_priv_key, bob_pub_key = generate_ecdsa_keypair()

    print("Alice generated ECDSA key pair")
    print("    Public key type:", type(alice_pub_key))
    print(" Bob generated ECDSA key pair")
    print("    Public key type:", type(bob_pub_key))
    print()

    # Alice generates and signs the DH public key
    a_priv = generate_private_key(p)
    a_pub = generate_public_key(g, a_priv, p)
    a_pub_bytes = str(a_pub).encode()
    a_signature = ecdsa_sign(a_pub_bytes, alice_priv_key)  # Using ECDSA Signatures

    print("Alice signs her DH public key:")
    print("    public key value:", a_pub)
    print("    signature value:", a_signature.hex()[:64], "...(an omission)")
    print()

    # Bob generates and signs the DH public key
    b_priv = generate_private_key(p)
    b_pub = generate_public_key(g, b_priv, p)
    b_pub_bytes = str(b_pub).encode()
    b_signature = ecdsa_sign(b_pub_bytes, bob_priv_key)  # Using ECDSA Signatures

    print("Bob signs his DH public key:")
    print("    public key value:", b_pub)
    print("    signature value:", b_signature.hex()[:64], "...(an omission)")
    print()

    # Alice verifies Bob's signature.
    print("Alice verifies Bob's signature....")
    if ecdsa_verify(b_pub_bytes, b_signature, bob_pub_key):  # Authentication with ECDSA
        print("Alice verifies Bob's signature successfully.\n")
    else:
        raise ValueError("Alice failed to verify Bob's signature.")

    # Bob verifies Alice's signature.
    print("Bob verifies Alice's signature....")
    if ecdsa_verify(a_pub_bytes, a_signature, alice_pub_key):  # Authentication with ECDSA
        print("Bob verifies Alice's signature successfully.\n")
    else:
        raise ValueError("Bob failed to verify Alice's signature.")

    # Both parties compute the shared key
    a_secret = compute_shared_secret(b_pub, a_priv, p)
    b_secret = compute_shared_secret(a_pub, b_priv, p)

    print("🔑 Alice Shared Secret:", a_secret)
    print("🔑 Bob Shared Secret:  ", b_secret)

    assert a_secret == b_secret
    print("\nThe keys are identical and ECDSA authentication is successful.")

if __name__ == "__main__":
    signed_dh_demo()
