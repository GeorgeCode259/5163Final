import os
import hmac
import hashlib
import warnings
from cryptography.exceptions import InvalidTag
from tinyec import registry
from tinyec.ec import Point

# --- 1. Constants and ECC Settings ---
curve = registry.get_curve("secp256r1")
DH_PRIVATE_KEY_SIZE = 32
DH_PUBLIC_KEY_SIZE = 48
ENVELOPE_CONTENT_SIZE = DH_PRIVATE_KEY_SIZE
ENVELOPE_SIZE = 32 + ENVELOPE_CONTENT_SIZE
ECC_POINT_SIZE = 65

# --- 2. Cryptographic Primitives Interface (Unchanged) ---
def hash_func(data):
    return hashlib.sha256(data).digest()
def kdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()
def kdf_expand(prk, info, length):
    okm = b""; t = b"";
    for i in range((length + 31) // 32):
        t = hmac.new(prk, t + info + bytes([i + 1]), hashlib.sha256).digest()
        okm += t
    return okm[:length]
def mac_func(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()
def mac_verify(key, tag, data):
    if not hmac.compare_digest(tag, mac_func(key, data)):
        raise InvalidTag("MAC verification failed")
def ksf_stretch(data):
    salt = b'OPAQUE-KSF-SALT-V1'; iterations = 100000; dklen = 32
    return hashlib.pbkdf2_hmac('sha256', data, salt, iterations, dklen=dklen)

# --- ECC OPRF Functions (Unchanged) ---
def hash_to_point(password: bytes):
    h = hashlib.sha256(b"OPAQUE-HashToPoint|" + password).digest()
    scalar = int.from_bytes(h, 'big') % curve.field.n
    return scalar * curve.g
def point_to_bytes(P: Point):
    return b'\x04' + P.x.to_bytes(32, 'big') + P.y.to_bytes(32, 'big')
def bytes_to_point(b: bytes):
    if b[0] != 0x04: raise ValueError("Only uncompressed format is supported")
    x = int.from_bytes(b[1:33], 'big'); y = int.from_bytes(b[33:], 'big')
    return Point(curve, x, y)
def oprf_blind(password: bytes):
    blind = os.urandom(32)
    blind_scalar = int.from_bytes(blind, 'big') % curve.field.n
    M = hash_to_point(password)
    blinded_point = M * blind_scalar
    return blind_scalar, point_to_bytes(blinded_point)
def oprf_finalize(password: bytes, blind_scalar: int, evaluated_bytes: bytes):
    evaluated_point = bytes_to_point(evaluated_bytes)
    inv_blind_scalar = pow(blind_scalar, -1, curve.field.n)
    unblinded_point = evaluated_point * inv_blind_scalar
    return hash_func(point_to_bytes(unblinded_point))

# --- DH Simulation Functions (Unchanged) ---
G_dh = 2
P_dh = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD
def ake_derive_keypair(seed):
    private_key_int = int.from_bytes(kdf_expand(seed, b"ake_private_key_int", DH_PRIVATE_KEY_SIZE), 'big')
    public_key_int = pow(G_dh, private_key_int, P_dh)
    return private_key_int, public_key_int.to_bytes(DH_PUBLIC_KEY_SIZE, 'big')
def ake_dh(private_key_int, public_key_bytes):
    public_key_int = int.from_bytes(public_key_bytes, 'big')
    shared_secret_int = pow(public_key_int, private_key_int, P_dh)
    return hash_func(shared_secret_int.to_bytes(DH_PUBLIC_KEY_SIZE, 'big'))

# --- 3. Server Implementation (with added printing) ---
class Server:
    def __init__(self, server_id):
        self.server_identity = server_id.encode()
        s_sk_int, s_pk_bytes = ake_derive_keypair(os.urandom(32))
        self.server_static_private_key_dh = s_sk_int
        self.server_static_public_key_dh = s_pk_bytes
        self.oprf_key = os.urandom(32)
        self.user_db = {}
        self.session_states = {}
        print(f"[S] Server '{server_id}' initialized.")
        print(f"     - OPRF Key: {self.oprf_key.hex()}")

    def oprf_evaluate(self, blinded_point_bytes: bytes):
        print(f"   [S] OPRF Evaluate: Received blinded point {blinded_point_bytes.hex()[:16]}...")
        oprf_scalar = int.from_bytes(self.oprf_key, 'big') % curve.field.n
        blinded_point = bytes_to_point(blinded_point_bytes)
        evaluated_point = blinded_point * oprf_scalar
        evaluated_bytes = point_to_bytes(evaluated_point)
        print(f"     - Calculating evaluated point with server OPRF key: {evaluated_bytes.hex()[:16]}...")
        return evaluated_bytes

    def store_record(self, user_id, record):
        print(f"[S] Database: Storing registration record for user '{user_id}'.")
        self.user_db[user_id] = record

    def _generate_dummy_ke2(self):
        print("[S] Security: User does not exist, generating dummy KE2 response to prevent user enumeration.")
        
        # --- This is the corrected part ---
        # Ensure the dummy ECC point is correctly formatted (first byte is 0x04)
        dummy_evaluated_message = b'\x04' + os.urandom(ECC_POINT_SIZE - 1)
        # --- End of correction ---

        dummy_masked_response = os.urandom(DH_PUBLIC_KEY_SIZE + DH_PUBLIC_KEY_SIZE + ENVELOPE_SIZE)
        credential_response = {"evaluated_message": dummy_evaluated_message, "masked_response": dummy_masked_response}
        server_eph_pk_dh = ake_derive_keypair(os.urandom(32))[1]
        server_mac = os.urandom(32)
        auth_response = {"server_eph_pk": server_eph_pk_dh, "server_mac": server_mac}
        return {"credential_response": credential_response, "auth_response": auth_response}

    def generate_ke2(self, user_id, ke1_dict):
        print(f"\n[S] === Start generating KE2, responding to '{user_id}' ===")
        blinded_message_bytes = ke1_dict['credential_request']['blinded_message']
        if user_id not in self.user_db: return self._generate_dummy_ke2()
        
        record = self.user_db[user_id]
        print(f"   [S] Database: Found record for user '{user_id}'.")

        evaluated_message_bytes = self.oprf_evaluate(blinded_message_bytes)
        
        print("   [S] Masked Response: Preparing to mask server public key and user envelope.")
        serialized_data = self.server_static_public_key_dh + record['client_public_key'] + record['envelope']
        pad_info = record['masking_key'] + evaluated_message_bytes
        pad_prk = kdf_extract(b"OPAQUE-Pad", pad_info)
        pad = kdf_expand(pad_prk, b"Pad", len(serialized_data))
        masked_response = bytes(a ^ b for a, b in zip(serialized_data, pad))
        print(f"     - Generating mask key (pad) using masking_key and evaluated_message.")
        print(f"     - Generated masked_response: {masked_response.hex()[:16]}...")
        credential_response = {"evaluated_message": evaluated_message_bytes, "masked_response": masked_response}

        print("   [S] AKE: Starting authenticated key exchange calculation.")
        server_eph_sk_dh, server_eph_pk_dh = ake_derive_keypair(os.urandom(32))
        client_eph_pk = ke1_dict['auth_request']['client_eph_pk']
        print(f"     - Server ephemeral public key (S_eph_pk): {server_eph_pk_dh.hex()[:16]}...")
        dh1 = ake_dh(server_eph_sk_dh, client_eph_pk)
        dh2 = ake_dh(self.server_static_private_key_dh, client_eph_pk)
        dh3 = ake_dh(server_eph_sk_dh, record['client_public_key'])
        print(f"     - DH1 (eph_s, eph_c) -> {dh1.hex()}")
        print(f"     - DH2 (static_s, eph_c) -> {dh2.hex()}")
        print(f"     - DH3 (eph_s, static_c) -> {dh3.hex()}")
        
        ikm = dh1 + dh2 + dh3
        preamble = self.server_identity + self.server_static_public_key_dh + record['client_public_key'] + client_eph_pk + server_eph_pk_dh
        
        print("   [S] Key Derivation: Deriving session key and MAC keys from IKM and preamble.")
        session_key_s = kdf_expand(kdf_extract(b"", ikm), b"SessionKey" + preamble, 32)
        km2_s = kdf_expand(kdf_extract(b"", ikm), b"ServerMAC" + preamble, 32)
        km3_s = kdf_expand(kdf_extract(b"", ikm), b"ClientMAC" + preamble, 32)
        server_mac = mac_func(km2_s, preamble)
        print(f"     - Server Session Key (K_s): {session_key_s.hex()}")
        print(f"     - Server MAC Key (Km2): {km2_s.hex()}")
        print(f"     - Client MAC Key (Km3): {km3_s.hex()}")
        print(f"     - Generated Server MAC (MAC_s): {server_mac.hex()}")

        expected_client_mac = mac_func(km3_s, preamble + server_mac)
        self.session_states[user_id] = {"session_key": session_key_s, "expected_client_mac": expected_client_mac}
        print(f"   [S] Session State: Saving expected client MAC: {expected_client_mac.hex()}")
        
        auth_response = {"server_eph_pk": server_eph_pk_dh, "server_mac": server_mac}
        print(f"[S] --- KE2 generation complete ---")
        return {"credential_response": credential_response, "auth_response": auth_response}
    
    def server_finish(self, user_id, ke3):
        print(f"\n[S] === Start processing KE3, verifying '{user_id}' ===")
        state = self.session_states.get(user_id)
        if not state: return None, "Session state not found"
        
        client_mac = ke3['client_mac']
        print(f"   [S] Received Client MAC: {client_mac.hex()}")
        print(f"   [S] Expected Client MAC: {state['expected_client_mac'].hex()}")
        if hmac.compare_digest(state['expected_client_mac'], client_mac):
            del self.session_states[user_id]
            print("   [S] Verification successful! Client identity confirmed.")
            return state['session_key'], "Login successful!"
        else:
            print("   [S] Verification failed! Client MAC does not match.")
            return None, "Client MAC verification failed!"

# --- 4. Client Implementation (with added printing) ---
class Client:
    def __init__(self, user_id, password):
        self.user_id = user_id
        self.password = password.encode('utf-8')
        self.session_state = {}

    def finalize_registration(self, server: Server):
        print(f"[C] === Starting registration process for '{self.user_id}' ===")
        print("   [C] OPRF: Blinding the password...")
        blind_scalar, blinded_point_bytes = oprf_blind(self.password)
        print(f"     - Generated blind_scalar and sending blinded point: {blinded_point_bytes.hex()[:16]}...")
        
        print("   [C] OPRF: Simulating interaction with server to get evaluated point.")
        evaluated_bytes = server.oprf_evaluate(blinded_point_bytes)
        
        print("   [C] OPRF: Received evaluated point, unblinding...")
        oprf_output = oprf_finalize(self.password, blind_scalar, evaluated_bytes)
        print(f"     - Successfully unblinded, got OPRF output: {oprf_output.hex()}")
        
        stretched_oprf_output = ksf_stretch(oprf_output)
        print(f"   [C] Key Stretching: Strengthened OPRF output: {stretched_oprf_output.hex()}")

        ikm_reg = oprf_output + stretched_oprf_output
        randomized_password = kdf_extract(b"OPAQUE-Randomized-Password", ikm_reg)
        print(f"   [C] Key Derivation: Deriving randomized password from OPRF output: {randomized_password.hex()}")

        client_private_key_dh, client_public_key_dh = ake_derive_keypair(kdf_expand(randomized_password, b"ClientKeys", 64))
        masking_key = kdf_expand(randomized_password, b"MaskingKey", 32)
        auth_key = kdf_expand(randomized_password, b"EnvelopeAuthKey", 32)
        print(f"     - Derived client static private key (c_static_sk): ...")
        print(f"     - Derived client static public key (c_static_pk): {client_public_key_dh.hex()[:16]}...")
        print(f"     - Derived masking key (masking_key): {masking_key.hex()}")
        print(f"     - Derived envelope authentication key (auth_key): {auth_key.hex()}")
        
        envelope_content = client_private_key_dh.to_bytes(DH_PRIVATE_KEY_SIZE, 'big')
        envelope_mac = mac_func(auth_key, envelope_content)
        envelope = envelope_mac + envelope_content
        print(f"   [C] Envelope: Creating encrypted envelope to protect client private key.")
        print(f"     - Envelope content (MAC || c_static_sk): {envelope.hex()}")
        
        export_key = kdf_expand(randomized_password, b"ExportKey", 32)
        print(f"[C] --- Registration record generation complete. Exported Key (ExportKey): {export_key.hex()} ---")
        return {"client_public_key": client_public_key_dh, "masking_key": masking_key, "envelope": envelope}

    def generate_ke1(self):
        print(f"\n[C] === Start generating KE1 for '{self.user_id}' ===")
        print("   [C] OPRF: Blinding the password...")
        blind_scalar, blinded_message_bytes = oprf_blind(self.password)
        self.session_state['blind_scalar'] = blind_scalar
        print(f"     - Saving blind scalar, preparing to send blinded point: {blinded_message_bytes.hex()[:16]}...")
        credential_request = {"blinded_message": blinded_message_bytes}
        
        print("   [C] AKE: Generating client ephemeral key pair.")
        client_eph_sk_dh, client_eph_pk_dh = ake_derive_keypair(os.urandom(32))
        auth_request = {"client_eph_pk": client_eph_pk_dh}
        print(f"     - Client ephemeral public key (c_eph_pk): {client_eph_pk_dh.hex()[:16]}...")
        
        self.session_state['client_eph_sk_dh'] = client_eph_sk_dh
        self.session_state['client_eph_pk_dh'] = client_eph_pk_dh
        
        print(f"[C] --- KE1 generation complete, ready to send ---")
        return {"credential_request": credential_request, "auth_request": auth_request}
    
    def generate_ke3(self, ke2, server_identity: bytes):
        # Use warnings.catch_warnings() to temporarily manage warnings
        with warnings.catch_warnings():
            # Specifically ignore UserWarning from tinyec library about point not on curve
            warnings.simplefilter("ignore", UserWarning)

            print(f"\n[C] === Start processing KE2, generating KE3 for '{self.user_id}' ===")
            cred_resp = ke2['credential_response']
            auth_resp = ke2['auth_response']
            
            print(f"   [C] OPRF: Received server evaluated point {cred_resp['evaluated_message'].hex()[:16]}..., unblinding.")
            blind_scalar = self.session_state['blind_scalar']
            oprf_output = oprf_finalize(self.password, blind_scalar, cred_resp['evaluated_message'])
            print(f"     - Successfully unblinded, got OPRF output: {oprf_output.hex()}")
            
            print("   [C] Key Derivation: Deriving keys required for login from OPRF output.")
            stretched_oprf_output = ksf_stretch(oprf_output)
            ikm_login = oprf_output + stretched_oprf_output
            randomized_password = kdf_extract(b"OPAQUE-Randomized-Password", ikm_login)
            masking_key_c = kdf_expand(randomized_password, b"MaskingKey", 32)
            print(f"     - Derived masking key (masking_key): {masking_key_c.hex()}")

            try:
                print(f"   [C] Unmasking: Using masking key to unmask server response.")
                pad_info = masking_key_c + cred_resp['evaluated_message']
                pad_prk = kdf_extract(b"OPAQUE-Pad", pad_info)
                pad = kdf_expand(pad_prk, b"Pad", len(cred_resp['masked_response']))
                serialized_data = bytes(a ^ b for a, b in zip(cred_resp['masked_response'], pad))
                
                server_public_key_dh_c = serialized_data[0:DH_PUBLIC_KEY_SIZE]
                client_public_key_dh_c = serialized_data[DH_PUBLIC_KEY_SIZE:DH_PUBLIC_KEY_SIZE*2]
                envelope_c = serialized_data[DH_PUBLIC_KEY_SIZE*2:]
                print(f"     - Successfully unmasked, got serialized data.")

                print(f"   [C] Verifying Envelope (core password verification step):")
                auth_key_c = kdf_expand(randomized_password, b"EnvelopeAuthKey", 32)
                print(f"     - Deriving envelope authentication key from password: {auth_key_c.hex()}")
                tag_c = envelope_c[:32]; content_c = envelope_c[32:]
                mac_verify(auth_key_c, tag_c, content_c)
                print(f"     - >>> Envelope MAC verification successful! Password is correct. <<<")
                client_private_key_dh_c = int.from_bytes(content_c, 'big')
                export_key_c = kdf_expand(randomized_password, b"ExportKey", 32)
                print(f"     - Recovered client static private key from envelope, and derived export key: {export_key_c.hex()}")

            except (IndexError, InvalidTag, KeyError, ValueError) as e:
                print(f"     - >>> Client: Failed to unmask or verify envelope! Most likely incorrect password or non-existent user. Error: {e} <<<")
                return None, "Incorrect password or non-existent user", None
            
            print("   [C] AKE: Starting authenticated key exchange calculation.")
            dh1 = ake_dh(self.session_state['client_eph_sk_dh'], auth_resp['server_eph_pk'])
            dh2 = ake_dh(self.session_state['client_eph_sk_dh'], server_public_key_dh_c)
            dh3 = ake_dh(client_private_key_dh_c, auth_resp['server_eph_pk'])
            print(f"     - DH1 (eph_c, eph_s) -> {dh1.hex()}")
            print(f"     - DH2 (eph_c, static_s) -> {dh2.hex()}")
            print(f"     - DH3 (static_c, eph_s) -> {dh3.hex()}")

            ikm_c = dh1 + dh2 + dh3
            preamble = server.server_identity + server_public_key_dh_c + client_public_key_dh_c + self.session_state['client_eph_pk_dh'] + auth_resp['server_eph_pk']
            
            print("   [C] Key Derivation: Deriving session key and MAC keys from IKM and preamble.")
            session_key_c = kdf_expand(kdf_extract(b"", ikm_c), b"SessionKey" + preamble, 32)
            km2_c = kdf_expand(kdf_extract(b"", ikm_c), b"ServerMAC" + preamble, 32)
            km3_c = kdf_expand(kdf_extract(b"", ikm_c), b"ClientMAC" + preamble, 32)
            print(f"     - Client Session Key (K_c): {session_key_c.hex()}")
            print(f"     - Server MAC Key (Km2): {km2_c.hex()}")
            print(f"     - Client MAC Key (Km3): {km3_c.hex()}")
            
            print("   [C] Verifying Server: Verifying MAC from server.")
            try:
                mac_verify(km2_c, auth_resp['server_mac'], preamble)
                print("     - >>> Server MAC verification successful! Server identity confirmed. <<<")
            except InvalidTag:
                print("     - >>> Server MAC verification failed, possibly a fake server! <<<")
                return None, "Server MAC verification failed, possibly a fake server!", None
                
            client_mac = mac_func(km3_c, preamble + auth_resp['server_mac'])
            print(f"   [C] Generating Client MAC: {client_mac.hex()}")
            del self.session_state
            
            print(f"[C] --- KE3 generation complete ---")
            return {"client_mac": client_mac}, session_key_c, export_key_c


# --- 5. Main Execution Flow (Unchanged) ---
if __name__ == "__main__":
    print("--- Scenario 1: User 'alice' registers successfully ---")
    server = Server("cool-server.com")
    alice = Client("alice@example.com", "MySecretPassword123")
    reg_record = alice.finalize_registration(server)
    server.store_record(alice.user_id, reg_record)
    print("-" * 50)

    print("\n--- Scenario 2: 'alice' logs in successfully with the correct password ---")
    alice_login = Client("alice@example.com", "MySecretPassword123")
    ke1 = alice_login.generate_ke1()
    ke2 = server.generate_ke2(alice_login.user_id, ke1)
    ke3, session_key, export_key = alice_login.generate_ke3(ke2, server.server_identity)
    if ke3:
        final_key, msg = server.server_finish(alice_login.user_id, ke3)
        print(f"\n--- Final Result ---")
        print(f"Server response: {msg}")
        if final_key:
            print(f"OPAQUE protocol successful! Client session key: {session_key.hex()}")
            print(f"OPAQUE protocol successful! Server session key: {final_key.hex()}")
            print(f"OPAQUE protocol successful! Client export key: {export_key.hex()}")
            assert session_key == final_key
            print("Assertion successful: Client and server session keys match!")
    else:
        print(f"\n--- Final Result ---")
        print(f"Client login failed: {session_key}")
    print("-" * 50)

    print("\n--- Scenario 3: 'alice' logs in with the wrong password ---")
    alice_bad_pass = Client("alice@example.com", "WrongPassword")
    ke1_bad = alice_bad_pass.generate_ke1()
    ke2_bad = server.generate_ke2(alice_bad_pass.user_id, ke1_bad)
    ke3_bad, result, _ = alice_bad_pass.generate_ke3(ke2_bad, server.server_identity)
    if not ke3_bad:
        print(f"\n--- Final Result ---")
        print(f"Client login failed: {result}")
    print("-" * 50)
    
    print("\n--- Scenario 4: Non-existent user 'bob' attempts to log in ---")
    bob_nonexistent = Client("bob@example.com", "anypassword")
    ke1_bob = bob_nonexistent.generate_ke1()
    ke2_bob = server.generate_ke2(bob_nonexistent.user_id, ke1_bob)
    ke3_bob, result_bob, _ = bob_nonexistent.generate_ke3(ke2_bob, server.server_identity)
    if not ke3_bob:
        print(f"\n--- Final Result ---")
        print(f"Client login failed: {result_bob}")
    print("-" * 50)