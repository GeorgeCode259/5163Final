from crypto_utils import *

def dh_mitm_simulation():
    print("=== Simulated Man-in-the-Middle Attack (MITM) ===")

    # common parameter 
    p = generate_prime(512)
    g = 2

    # Alice and Bob each generate a DH private key and a public key.
    alice_priv = generate_private_key(p)
    alice_pub = generate_public_key(g, alice_priv, p)
    bob_priv = generate_private_key(p)
    bob_pub = generate_public_key(g, bob_priv, p)

    # Attacker（Eve）generate spoofed DH key pairs
    eve_priv = generate_private_key(p)
    fake_pub = generate_public_key(g, eve_priv, p)

    print("\n--- Scenario 1: No Signature Verification, Eve Replaces Public Key ---")
    print("Eve replaces the public key Alice sent to Bob with her own fake_pub.")
    # The shared key Bob computes is actually a shared key with Eve.
    bob_shared = compute_shared_secret(fake_pub, bob_priv, p)

    print("Eve replaces the public key Bob sent to Alice with her own fake_pub.")
    alice_shared = compute_shared_secret(fake_pub, alice_priv, p)

    print("Alice thought it was the key to Bob.:", alice_shared)
    print("Bob thought it was the key to Alice :", bob_shared)
    print("Both actually share the key with Eve (MITM success)")
    print("Eve has a shared key with each party to decrypt the communication")


if __name__ == "__main__":
    dh_mitm_simulation()
