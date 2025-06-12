from crypto_utils import *

# Emulating a server database with a dictionary
SERVER_DB = {}

def password_to_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)

# ----------------------------
# Registration phase (client + server)
# ----------------------------
def client_register(username: str, password: str):
    print(f"\n[Registered] User {username}")
    # Client - 1. Derived key k
    salt = secrets.token_bytes(16)
    k    = password_to_key(password, salt)

    # Client - 2. Generate DH key pairs
    p       = generate_prime(512)
    g       = 2
    dh_priv = generate_private_key(p)
    dh_pub  = generate_public_key(g, dh_priv, p)

    # Client - 3. Calculate dh_priv_bytes and envelope
    dh_priv_bytes = dh_priv.to_bytes((dh_priv.bit_length() + 7) // 8, 'big')
    envelope      = hmac_sha256(k, dh_priv_bytes)

    # Server - 4. store only salt, envelope, dh_pub, p, g
    SERVER_DB[username] = {
        'salt': salt,
        'envelope': envelope,
        'dh_pub': dh_pub,
        'p': p,
        'g': g
    }
    print("Registration complete (server only stores salt/envelope/dh_pub/p/g)")

    # The client retains dh_priv_bytes locally for validation at subsequent logins
    return dh_priv_bytes

# ----------------------------
# Log in and perform PAKE + Key Confirmation
# ----------------------------
def client_login(username: str, password: str, dh_priv_bytes: bytes):
    print(f"\n[login] user {username} start authentication")
    rec = SERVER_DB.get(username)
    if not rec:
        print("The user does not exist")
        return

    # Client - 1. derivation k'
    salt     = rec['salt']
    envelope = rec['envelope']
    p        = rec['p']
    g        = rec['g']

    k_prime = password_to_key(password, salt)

    # Client - 2. local authentication envelope
    if hmac_sha256(k_prime, dh_priv_bytes) != envelope:
        print("Password verification failed")
        return
    print("Password authentication passed (local HMAC checksum)")

    # Client - 3. generates its own DH key pair
    my_priv = generate_private_key(p)
    my_pub  = generate_public_key(g, my_priv, p)

    # Client - 4. sends DH public key to server and performs server phase processing
    resp = server_phase(username, my_pub)
    if not resp:
        return
    their_pub = resp  # The server returns the counterpart's DH public key

    # Client - 5. Calculate the shared key and derive the session key
    shared      = pow(their_pub, my_priv, p)
    session_key = derive_key(shared)
    print("Session Key derivation OK:", session_key.hex())

    # Client - 6. Key Confirmation Step 1: Send KC1
    kc1 = hmac_sha256(session_key, b"KC1")
    print("Client sends KC1:", kc1.hex())
    kc2 = server_key_confirmation(username, kc1)
    if kc2 is None:
        print(" Key Confirmation failed.")
        return

    # Client - 7. Validates the KC2 sent by the server.
    expected_kc2 = hmac_sha256(session_key, b"KC2")
    print("Authentication server KC2:", expected_kc2.hex())
    if kc2 != expected_kc2:
        print("Server KC2 Authentication Failure")
    else:
        print("Key Confirmation succeeded. Communication established successfully.")

# ----------------------------
# Server-side processing functions (simulation)
# ----------------------------
def server_phase(username: str, client_pub: int):
    rec = SERVER_DB[username]
    p   = rec['p']
    g   = rec['g']

    # Server - 1. generates its own DH key pair
    my_priv = generate_private_key(p)
    my_pub  = generate_public_key(g, my_priv, p)
    print("The server generates the DH public key and returns")

    # Stores the temporary private key and client public key for subsequent Key Confirmation.
    rec['tmp_priv'] = my_priv
    rec['cli_pub']  = client_pub

    return my_pub

# ----------------------------
# Server Side Key Confirmation
# ----------------------------
def server_key_confirmation(username: str, kc1_client: bytes):
    rec = SERVER_DB[username]
    p        = rec['p']
    srv_priv = rec['tmp_priv']
    cli_pub  = rec['cli_pub']

    # The server computes the shared secret itself and derives the session key
    shared          = pow(cli_pub, srv_priv, p)
    session_key_srv = derive_key(shared)

    # Verify the client's KC1
    expected_kc1 = hmac_sha256(session_key_srv, b"KC1")
    if kc1_client != expected_kc1:
        print("Server: KC1 Authentication Failed")
        return None
    print("Server: KC1 Authentication Successed")

    # Generate and return KC2
    kc2 = hmac_sha256(session_key_srv, b"KC2")
    print("Server sends KC2:", kc2.hex())
    return kc2

# ----------------------------
# Demo
# ----------------------------
if __name__ == "__main__":
    uname = "alice"
    pwd   = "correcthorsebattery"

    # Registration: client reserved dh_priv_bytes
    dh_priv_bytes = client_register(uname, pwd)

    # Login (correct password)
    client_login(uname, pwd, dh_priv_bytes)

    # Login (wrong password)
    print("\n=== Wrong password attempts ===")
    client_login(uname, "wrongpassword123", dh_priv_bytes)
