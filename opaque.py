import os
import hmac
import hashlib
from cryptography.exceptions import InvalidTag

# --- 1. cryptography

def hash_func(data):
    return hashlib.sha256(data).digest()

def kdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def kdf_expand(prk, info, length):
    okm = b""
    t = b""
    for i in range((length + 31) // 32):
        t = hmac.new(prk, t + info + bytes([i + 1]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def mac_func(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def mac_verify(key, tag, data):
    if not hmac.compare_digest(tag, mac_func(key, data)):
        raise InvalidTag("MAC Validation failed")

def ksf_stretch(data):
    stretched = data
    for _ in range(100):
        stretched = hash_func(stretched)
    return stretched

def oprf_blind(password):
    blind = os.urandom(32)
    blinded_element = hash_func(password + blind)
    return blinded_element, blind

def oprf_evaluate(oprf_key, blinded_element):
    return hash_func(oprf_key + blinded_element)

def oprf_finalize(blind, evaluated_element):
    return hash_func(blind + evaluated_element)

def ake_derive_keypair(seed):
    private_key = kdf_expand(seed, b"ake_private_key", 32)
    public_key = hash_func(private_key)
    return private_key, public_key

def ake_dh(private_key, public_key):
    return hash_func(private_key + public_key)

class ProtocolError(Exception):
    pass

# --- 2. service ---

class Server:
    def __init__(self, server_id):
        self.server_identity = server_id.encode()
        self.server_static_private_key, self.server_static_public_key = ake_derive_keypair(os.urandom(32))
        self.oprf_seed = os.urandom(32)
        self.user_db = {}
        self.session_states = {}

    def _derive_oprf_key(self, user_id):
        return kdf_expand(self.oprf_seed, user_id.encode(), 32)

    def create_registration_response(self, user_id, blinded_message):
        oprf_key = self._derive_oprf_key(user_id)
        return oprf_evaluate(oprf_key, blinded_message)

    def store_record(self, user_id, record):
        print(f"Server: Storage client: {user_id} RegistrationRecord。")
        self.user_db[user_id] = record

    def _generate_dummy_ke2(self, ke1):
        print("Server: Client record not found, generate forged response to prevent enumeration.")
        dummy_oprf_key = self._derive_oprf_key("dummy")
        evaluated_message = oprf_evaluate(dummy_oprf_key, ke1['credential_request']['blinded_message'])
        dummy_masked_response = os.urandom(32 + 32 + 32) # pk_s + pk_c + envelope
        credential_response = {"evaluated_message": evaluated_message, "masked_response": dummy_masked_response}
        server_eph_pk = ake_derive_keypair(os.urandom(32))[1]
        server_mac = os.urandom(32)
        auth_response = {"server_eph_pk": server_eph_pk, "server_mac": server_mac}
        return {"credential_response": credential_response, "auth_response": auth_response}

    def generate_ke2(self, user_id, ke1):
        if user_id not in self.user_db:
            return self._generate_dummy_ke2(ke1)

        record = self.user_db[user_id]
        oprf_key = self._derive_oprf_key(user_id)
        
        evaluated_message = oprf_evaluate(oprf_key, ke1['credential_request']['blinded_message'])
        
        serialized_data = self.server_static_public_key + record['client_public_key'] + record['envelope']
        
        pad_info = record['masking_key'] + evaluated_message
        pad_prk = kdf_extract(b"OPAQUE-Pad", pad_info)
        pad = kdf_expand(pad_prk, b"Pad", len(serialized_data))
        masked_response = bytes(a ^ b for a, b in zip(serialized_data, pad))

        credential_response = {"evaluated_message": evaluated_message, "masked_response": masked_response}

        server_eph_sk, server_eph_pk = ake_derive_keypair(os.urandom(32))
        
        dh1 = ake_dh(server_eph_sk, ke1['auth_request']['client_eph_pk'])
        dh2 = ake_dh(self.server_static_private_key, ke1['auth_request']['client_eph_pk'])
        dh3 = ake_dh(server_eph_sk, record['client_public_key'])
        
        ikm = dh1 + dh2 + dh3
        preamble = self.server_identity + self.server_static_public_key + record['client_public_key'] + ke1['auth_request']['client_eph_pk'] + server_eph_pk
        
        session_key_s = kdf_expand(kdf_extract(b"", ikm), b"SessionKey" + preamble, 32)
        km2_s = kdf_expand(kdf_extract(b"", ikm), b"ServerMAC" + preamble, 32)
        km3_s = kdf_expand(kdf_extract(b"", ikm), b"ClientMAC" + preamble, 32)
        
        server_mac = mac_func(km2_s, preamble)

        self.session_states[user_id] = {"session_key": session_key_s, "expected_client_mac": mac_func(km3_s, preamble + server_mac)}
        
        auth_response = {"server_eph_pk": server_eph_pk, "server_mac": server_mac}
        return {"credential_response": credential_response, "auth_response": auth_response}

    def server_finish(self, user_id, ke3):
        state = self.session_states.get(user_id)
        if not state: return None, "Session status not found"
        try:
            mac_verify(b"", state['expected_client_mac'], ke3['client_mac'])
            del self.session_states[user_id]
            return state['session_key'], "Login successful!"
        except InvalidTag:
            return None, "Client MAC verification failed!"

# --- 3. client implementation ---

class Client:
    def __init__(self, user_id, password):
        self.user_id = user_id
        self.password = password.encode('utf-8')
        self.session_state = {}

    def create_registration_request(self):
        blinded_element, blind = oprf_blind(self.password)
        self.session_state['blind'] = blind
        return {"blinded_message": blinded_element}

    def finalize_registration(self, evaluated_message):
        oprf_output = oprf_finalize(self.session_state['blind'], evaluated_message)
        stretched_oprf_output = ksf_stretch(oprf_output)
        
        ikm = oprf_output + stretched_oprf_output
        randomized_password = kdf_extract(b"OPAQUE-Randomized-Password", ikm)
        
        client_private_key, client_public_key = ake_derive_keypair(kdf_expand(randomized_password, b"ClientKeys", 64))
        masking_key = kdf_expand(randomized_password, b"MaskingKey", 32)
        export_key = kdf_expand(randomized_password, b"ExportKey", 32)
        

        auth_key = kdf_expand(randomized_password, b"EnvelopeAuthKey", 32)
        envelope_content = client_private_key
        envelope_mac = mac_func(auth_key, envelope_content)
        envelope = envelope_mac + envelope_content # 32 byte MAC+32 byte private key

        
        del self.session_state['blind']
        print(f"Client {self.user_id} registration completed. Export key (registrating): {export_key.hex()}")
        return {"client_public_key": client_public_key, "masking_key": masking_key, "envelope": envelope}

    def generate_ke1(self):
        blinded_element, blind = oprf_blind(self.password)
        credential_request = {"blinded_message": blinded_element}
        client_eph_sk, client_eph_pk = ake_derive_keypair(os.urandom(32))
        auth_request = {"client_eph_pk": client_eph_pk}
        self.session_state = {'blind': blind, 'client_eph_sk': client_eph_sk, 'client_eph_pk': client_eph_pk}
        return {"credential_request": credential_request, "auth_request": auth_request}
    
    def generate_ke3(self, ke2, server_identity):
        cred_resp = ke2['credential_response']
        auth_resp = ke2['auth_response']
        
        oprf_output = oprf_finalize(self.session_state['blind'], cred_resp['evaluated_message'])
        stretched_oprf_output = ksf_stretch(oprf_output)
        ikm = oprf_output + stretched_oprf_output
        randomized_password = kdf_extract(b"OPAQUE-Randomized-Password", ikm)
        masking_key_c = kdf_expand(randomized_password, b"MaskingKey", 32)

        try:
            pad_info = masking_key_c + cred_resp['evaluated_message']
            pad_prk = kdf_extract(b"OPAQUE-Pad", pad_info)
            pad = kdf_expand(pad_prk, b"Pad", len(cred_resp['masked_response']))
            
            serialized_data = bytes(a ^ b for a, b in zip(cred_resp['masked_response'], pad))
            
            # Desialization: The first 32 bytes are the server public key, the next 32 bytes are the client public key, and finally the envelope
            server_public_key_c = serialized_data[0:32]
            client_public_key_c = serialized_data[32:64]
            envelope_c = serialized_data[64:]
            
            # Verify envelope
            auth_key_c = kdf_expand(randomized_password, b"EnvelopeAuthKey", 32)
            tag_c = envelope_c[:32]
            content_c = envelope_c[32:]
            mac_verify(auth_key_c, tag_c, content_c)
            
            # Restore private key and export key
            client_private_key_c = content_c
            export_key_c = kdf_expand(randomized_password, b"ExportKey", 32)

        except (IndexError, InvalidTag) as e:
            print(f"Client: Envelope recovery failed! {e}")
            return None, "Password error or user does not exist", None

        dh1 = ake_dh(self.session_state['client_eph_sk'], auth_resp['server_eph_pk'])
        dh2 = ake_dh(self.session_state['client_eph_sk'], server_public_key_c)
        dh3 = ake_dh(client_private_key_c, auth_resp['server_eph_pk'])
        
        ikm_c = dh1 + dh2 + dh3
        preamble = server_identity + server_public_key_c + client_public_key_c + self.session_state['client_eph_pk'] + auth_resp['server_eph_pk']
        
        session_key_c = kdf_expand(kdf_extract(b"", ikm_c), b"SessionKey" + preamble, 32)
        km2_c = kdf_expand(kdf_extract(b"", ikm_c), b"ServerMAC" + preamble, 32)
        km3_c = kdf_expand(kdf_extract(b"", ikm_c), b"ClientMAC" + preamble, 32)
        
        try:
            mac_verify(km2_c, auth_resp['server_mac'], preamble)
        except InvalidTag:
            return None, "Server MAC verification failed, it may be a fake server!", None
            
        client_mac = mac_func(km3_c, preamble + auth_resp['server_mac'])
        
        del self.session_state
        
        return {"client_mac": client_mac}, session_key_c, export_key_c

# --- 4. Main execution process ---

if __name__ == "__main__":
    # --- Scenario 1: Successful registration ---
    print("--- Scenario 1: User 'license' successfully registered ---")
    server = Server("cool-server.com")
    alice = Client("alice@example.com", "MySecretPassword123")
    reg_req = alice.create_registration_request()
    evaluated_msg = server.create_registration_response(alice.user_id, reg_req['blinded_message'])
    reg_record = alice.finalize_registration(evaluated_msg)
    server.store_record(alice.user_id, reg_record)
    print("-" * 40)




    # --- Scenario 2: Successful login ---
    print("\n--- Scenario 2: 'Alice' successfully logged in with the correct password ---")
    alice_login = Client("alice@example.com", "MySecretPassword123")
    ke1 = alice_login.generate_ke1()
    ke2 = server.generate_ke2(alice_login.user_id, ke1)
    ke3, session_key, export_key = alice_login.generate_ke3(ke2, server.server_identity)
    if ke3:
        print("Client: KE3 generated successfully, sending ..")
        final_key, msg = server.server_finish(alice_login.user_id, ke3)
        print(f"server response: {msg}")
        if final_key:
            print(f"OPAQUE protocol successful! Client session key: {session_key.hex()}")
            print(f"OPAQUE protocol successful! Server session key: {final_key.hex()}")
            assert session_key == final_key
    else:
        print(f"Client login failed: {session_key}")
    print("-" * 40)




    # --- Scenario 3: Login with incorrect password ---
    print("\n--- Scenario 3: 'Alice' logged in with the wrong password ---")
    alice_bad_pass = Client("alice@example.com", "WrongPassword")
    ke1_bad = alice_bad_pass.generate_ke1()
    ke2_bad = server.generate_ke2(alice_bad_pass.user_id, ke1_bad)
    ke3_bad, result, _ = alice_bad_pass.generate_ke3(ke2_bad, server.server_identity)
    if not ke3_bad:
        print(f"Client login failed: {result}")
    print("-" * 40)




    # --- Scenario 4: Login of non-existent users ---
    print("\n--- Scenario 4: The non-existent user 'bob' attempts to log in ---")
    bob_nonexistent = Client("bob@example.com", "anypassword")
    ke1_bob = bob_nonexistent.generate_ke1()
    ke2_bob = server.generate_ke2(bob_nonexistent.user_id, ke1_bob)
    ke3_bob, result_bob, _ = bob_nonexistent.generate_ke3(ke2_bob, server.server_identity)
    if not ke3_bob:
        print(f"Client login failed: {result_bob}")
    print("-" * 40)