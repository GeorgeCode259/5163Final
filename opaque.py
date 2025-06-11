import os
import hmac
import hashlib
import random
import math 
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa

# --- 1. 定义常量 ---
DH_PRIVATE_KEY_SIZE = 32
DH_PUBLIC_KEY_SIZE = 48
ENVELOPE_CONTENT_SIZE = DH_PRIVATE_KEY_SIZE
ENVELOPE_SIZE = 32 + ENVELOPE_CONTENT_SIZE

RSA_KEY_SIZE_BITS = 1024
RSA_MODULUS_SIZE_BYTES = RSA_KEY_SIZE_BITS // 8

# --- 2. 密码学原语接口 ---
def hash_func(data):
    """
    计算给定数据的 SHA-256 哈希值。

    这是一个基础的密码学构建模块，用于将任意长度的数据映射为固定长度（32字节）的摘要。
    哈希函数是单向的，意味着从哈希结果很难反推出原始数据。

    :param data: 需要计算哈希的字节串 (bytes)。
    :return: 32字节的哈希摘要 (bytes)。
    """
    return hashlib.sha256(data).digest()

def kdf_extract(salt, ikm):
    """
    执行 HKDF（基于HMAC的密钥派生函数）的第一步：提取 (Extract)。

    此步骤将一个可能非均匀的、有偏差的输入密钥材料（IKM）和一个盐（salt）混合，
    并“提取”出一个密码学上强壮的、固定长度的伪随机密钥（PRK）。
    它扮演着“随机性提纯器”的角色。

    :param salt: 一个可选的、非秘密的随机值。用于增强安全性。
    :param ikm: 输入密钥材料 (Input Keying Material)，例如从DH交换得到的共享秘密。
    :return: 32字节的伪随机密钥 (PRK) (bytes)。
    """
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def kdf_expand(prk, info, length):
    """
    执行 HKDF 的第二步：扩展 (Expand)。

    此步骤获取从 `kdf_extract` 得到的伪随机密钥（PRK），并将其扩展成一个或多个指定长度的密钥。
    'info' 参数是关键，它能确保为不同目的派生的密钥是完全不同的（例如，一个用于加密，一个用于认证），这被称为“域分离”。

    :param prk: 从提取步骤得到的伪随机密钥 (bytes)。
    :param info: 可选的上下文和应用特定信息 (bytes)，用于区分不同的派生密钥。
    :param length: 期望输出的密钥长度（字节数）。
    :return: 指定长度的输出密钥材料 (OKM) (bytes)。
    """
    okm = b""; t = b"";
    for i in range((length + 31) // 32):
        t = hmac.new(prk, t + info + bytes([i + 1]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def mac_func(key, data):
    """
    计算消息认证码 (MAC - Message Authentication Code)。

    使用 HMAC-SHA256 算法，根据给定的密钥（key）为一段数据（data）生成一个认证标签（tag）。
    这个标签可以被用来同时验证数据的完整性（未被篡改）和来源真实性（由持有密钥者生成）。

    :param key: 用于计算MAC的秘密密钥 (bytes)。
    :param data: 需要认证的数据 (bytes)。
    :return: 32字节的MAC标签 (bytes)。
    """
    return hmac.new(key, data, hashlib.sha256).digest()

def mac_verify(key, tag, data):
    """
    验证一个消息认证码（MAC）是否有效。

    它会重新计算数据的MAC，并使用 `hmac.compare_digest` 与提供的标签（tag）进行安全的、
    时间恒定的比较。这样做可以防止通过测量计算时间差异来破解密钥的时序攻击（Timing Attack）。

    :param key: 用于验证的秘密密钥 (bytes)。
    :param tag: 需要被验证的MAC标签 (bytes)。
    :param data: 被认证的原始数据 (bytes)。
    :raises InvalidTag: 如果标签无效或不匹配，则抛出此异常。
    """
    if not hmac.compare_digest(tag, mac_func(key, data)):
        raise InvalidTag("MAC 验证失败")

def ksf_stretch(data):
    """
    一个使用 PBKDF2-HMAC-SHA256 的标准密钥拉伸函数 (KSF)。

    此函数通过大量的迭代计算（如此处的100,000次），人为地增加计算一个值的成本。
    这主要用于增强密码的安全性，使得针对密码的离线字典攻击或暴力破解攻击在计算上变得更加昂贵和耗时。

    :param data: 需要被“拉伸”的输入数据 (bytes)，在OPAQUE中是oprf_output。
    :return: 经过拉伸处理后的32字节数据 (bytes)。
    """
    salt = b'OPAQUE-KSF-SALT-V1'
    iterations = 100000
    dklen = 32
    return hashlib.pbkdf2_hmac('sha256', data, salt, iterations, dklen=dklen)

def modInverse(a, m):
    """计算 a 在模 m 下的乘法逆元。"""
    m0, y, x = m, 0, 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        y, x = x - q * y, y
    if x < 0: x += m0
    return x

# --- OPRF 函数修改为基于 RSA 盲签名原理 ---

def oprf_blind(password, server_rsa_e, server_rsa_N):
    """
    客户端：使用 RSA 盲签名原理进行致盲。
    将密码（处理后）与一个随机致盲因子 r 结合，发送给服务器。
    :param password: 用户的原始密码 (bytes)。
    :param server_rsa_e: 服务器 RSA 公钥的指数 e (int)。
    :param server_rsa_N: 服务器 RSA 公钥的模数 N (int)。
    :return: 一个元组 (blinded_message_int, original_message_int, r_blinding_factor)
             blinded_message_int: 发送给服务器的致盲后的整数。
             original_message_int: 密码处理后的整数形式，客户端保存。
             r_blinding_factor: 客户端保存的致盲因子r。
    """
    hashed_password = hash_func(password)
    original_message_int = int.from_bytes(hashed_password, 'big')
    if original_message_int >= server_rsa_N:
        original_message_int %= server_rsa_N
    
    r_blinding_factor = 0
    while True:
        r_bytes = os.urandom(RSA_MODULUS_SIZE_BYTES - 1)
        r_blinding_factor = int.from_bytes(r_bytes, 'big')
        if r_blinding_factor > 1 and math.gcd(r_blinding_factor, server_rsa_N) == 1:
            break
    
    r_pow_e = pow(r_blinding_factor, server_rsa_e, server_rsa_N)
    blinded_message_int = (original_message_int * r_pow_e) % server_rsa_N
    # print(f"客户端 oprf_blind: m={original_message_int}, r={r_blinding_factor}, m'={blinded_message_int}")
    return blinded_message_int, original_message_int, r_blinding_factor

def oprf_finalize(original_message_int, r_blinding_factor, server_rsa_N, signed_blinded_m_int_from_server):
    """
    客户端：“解盲”服务器返回的签名，得到一个确定性的值，并哈希作为OPRF输出。
    :param original_message_int: 客户端保存的密码处理后的整数 m。
    :param r_blinding_factor: 客户端保存的致盲因子 r。
    :param server_rsa_N: 服务器 RSA 公钥的模数 N。
    :param signed_blinded_m_int_from_server: 从服务器收到的“签名”后的整数 s'。
    :return: 最终的、与会话无关的 OPRF 输出 (32字节的哈希值)。
    """
    r_inv = modInverse(r_blinding_factor, server_rsa_N)
    unblinded_signature_int = (signed_blinded_m_int_from_server * r_inv) % server_rsa_N
    oprf_output_raw_bytes = unblinded_signature_int.to_bytes(RSA_MODULUS_SIZE_BYTES, 'big')
    final_oprf_output = hash_func(oprf_output_raw_bytes)
    # print(f"客户端 oprf_finalize: s'={signed_blinded_m_int_from_server}, r_inv={r_inv}, s(m^d)={unblinded_signature_int}, final_out={final_oprf_output.hex()}")
    return final_oprf_output

# --- Diffie-Hellman 模拟函数 (保持不变) ---
G_dh = 2
P_dh = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD

def ake_derive_keypair(seed):
    """使用整数运算模拟 DH 密钥对生成（私钥为整数，公钥为字节串）。"""
    private_key_int = int.from_bytes(kdf_expand(seed, b"ake_private_key_int", DH_PRIVATE_KEY_SIZE), 'big')
    public_key_int = pow(G_dh, private_key_int, P_dh)
    return private_key_int, public_key_int.to_bytes(DH_PUBLIC_KEY_SIZE, 'big')

def ake_dh(private_key_int, public_key_bytes):
    """使用整数运算模拟 DH 共享秘密计算，返回哈希后的共享秘密。"""
    public_key_int = int.from_bytes(public_key_bytes, 'big')
    shared_secret_int = pow(public_key_int, private_key_int, P_dh)
    return hash_func(shared_secret_int.to_bytes(DH_PUBLIC_KEY_SIZE, 'big'))

class ProtocolError(Exception):
    pass

# --- 3. 服务器实现 ---
class Server:
    def __init__(self, server_id):
        """
        服务器初始化。
        生成 OPAQUE AKE 所需的长期静态DH密钥对。
        生成 RSA 密钥对，用于 OPRF-like 的盲签名操作。
        初始化用户数据库和会话状态存储。
        """
        self.server_identity = server_id.encode()
        s_sk_int, s_pk_bytes = ake_derive_keypair(os.urandom(32))
        self.server_static_private_key_dh = s_sk_int
        self.server_static_public_key_dh = s_pk_bytes
        
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=RSA_KEY_SIZE_BITS
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.rsa_d = self.rsa_private_key.private_numbers().d
        self.rsa_e = self.rsa_public_key.public_numbers().e
        self.rsa_N = self.rsa_public_key.public_numbers().n
        
        self.user_db = {}
        self.session_states = {}

    def oprf_evaluate(self, blinded_message_int_from_client):
        """
        服务器：执行 OPRF "评估"步骤（RSA盲签名中的签名操作）。
        服务器使用其 RSA 私钥对客户端发送的致盲消息进行签名。
        服务器完全不知道原始消息是什么。
        :param blinded_message_int_from_client: 从客户端收到的致盲后的整数。
        :return: 服务器“签名”后的结果 (int)。
        """
        signed_blinded_m_int = pow(blinded_message_int_from_client, self.rsa_d, self.rsa_N)
        return signed_blinded_m_int

    def store_record(self, user_id, record):
        """服务器：存储客户端的注册记录到数据库。"""
        print(f"服务器: 存储客户端 {user_id} 的 RegistrationRecord。")
        self.user_db[user_id] = record

    def _generate_dummy_ke2(self): 
        """服务器：为不存在的用户生成伪造的KE2响应，以防止用户枚举。"""
        print("服务器: 客户端记录未找到，生成伪造响应以防枚举。")
        dummy_evaluated_message_int = random.randint(0, self.rsa_N - 1)
        dummy_evaluated_message = dummy_evaluated_message_int.to_bytes(RSA_MODULUS_SIZE_BYTES, 'big')
        dummy_masked_response = os.urandom(DH_PUBLIC_KEY_SIZE + DH_PUBLIC_KEY_SIZE + ENVELOPE_SIZE)
        credential_response = {"evaluated_message": dummy_evaluated_message, "masked_response": dummy_masked_response}
        server_eph_pk_dh = ake_derive_keypair(os.urandom(32))[1]
        server_mac = os.urandom(32)
        auth_response = {"server_eph_pk": server_eph_pk_dh, "server_mac": server_mac}
        return {"credential_response": credential_response, "auth_response": auth_response}

    def generate_ke2(self, user_id, ke1_dict):
        """
        服务器：生成登录流程的第二条消息 KE2。
        包含对客户端 OPRF 请求的响应 (evaluated_message)，
        遮盖后的用户记录 (masked_response)，以及服务器的 AKE 材料。
        :param user_id: 尝试登录的用户名。
        :param ke1_dict: 客户端发送的 KE1 消息字典。
        :return: KE2 消息字典。
        """
        ke1_blinded_message_int = ke1_dict['credential_request']['blinded_message_int'] # 从 ke1_dict 中提取 blinded_message_int
        
        if user_id not in self.user_db:
            return self._generate_dummy_ke2() # _generate_dummy_ke2 不使用ke1的内容

        record = self.user_db[user_id]
        
        signed_blinded_m_int = self.oprf_evaluate(ke1_blinded_message_int)
        evaluated_message_bytes = signed_blinded_m_int.to_bytes(RSA_MODULUS_SIZE_BYTES, 'big')
        
        serialized_data = self.server_static_public_key_dh + record['client_public_key'] + record['envelope']
        pad_info = record['masking_key'] + evaluated_message_bytes
        pad_prk = kdf_extract(b"OPAQUE-Pad", pad_info)
        pad = kdf_expand(pad_prk, b"Pad", len(serialized_data))
        masked_response = bytes(a ^ b for a, b in zip(serialized_data, pad))
        credential_response = {"evaluated_message": evaluated_message_bytes, "masked_response": masked_response}

        server_eph_sk_dh, server_eph_pk_dh = ake_derive_keypair(os.urandom(32))
        
        client_eph_pk = ke1_dict['auth_request']['client_eph_pk']
        dh1 = ake_dh(server_eph_sk_dh, client_eph_pk)
        dh2 = ake_dh(self.server_static_private_key_dh, client_eph_pk)
        dh3 = ake_dh(server_eph_sk_dh, record['client_public_key'])
        
        ikm = dh1 + dh2 + dh3
        preamble = self.server_identity + self.server_static_public_key_dh + record['client_public_key'] + client_eph_pk + server_eph_pk_dh
        
        session_key_s = kdf_expand(kdf_extract(b"", ikm), b"SessionKey" + preamble, 32)
        km2_s = kdf_expand(kdf_extract(b"", ikm), b"ServerMAC" + preamble, 32)
        km3_s = kdf_expand(kdf_extract(b"", ikm), b"ClientMAC" + preamble, 32)
        server_mac = mac_func(km2_s, preamble)
        self.session_states[user_id] = {"session_key": session_key_s, "expected_client_mac": mac_func(km3_s, preamble + server_mac)}
        auth_response = {"server_eph_pk": server_eph_pk_dh, "server_mac": server_mac}
        return {"credential_response": credential_response, "auth_response": auth_response}
    
    def server_finish(self, user_id, ke3):
        """
        服务器：处理客户端的 KE3 消息，完成最终验证。
        :param user_id: 客户端用户名。
        :param ke3: 客户端发送的 KE3 消息字典。
        :return: (会话密钥, 状态消息) 或 (None, 错误消息)。
        """
        state = self.session_states.get(user_id)
        if not state: return None, "会话状态未找到"
        if hmac.compare_digest(state['expected_client_mac'], ke3['client_mac']):
            del self.session_states[user_id]
            return state['session_key'], "登录成功!"
        else:
            return None, "客户端MAC验证失败!"

# --- 4. 客户端实现 ---
class Client:
    def __init__(self, user_id, password):
        """
        客户端初始化。
        :param user_id: 用户名。
        :param password: 用户密码。
        """
        self.user_id = user_id
        self.password = password.encode('utf-8')
        self.session_state = {}

    def finalize_registration(self, server_rsa_e, server_rsa_N):
        """
        客户端：完成注册流程。
        包括执行 OPRF 致盲、模拟与服务器的 OPRF 评估交互、解盲得到 OPRF 输出，
        然后派生各种密钥并创建 RegistrationRecord。
        :param server_rsa_e: 服务器的 RSA 公钥指数 e。
        :param server_rsa_N: 服务器的 RSA 公钥模数 N。
        :return: RegistrationRecord 字典。
        """
        blinded_m_int, original_m_int, r_factor = oprf_blind(self.password, server_rsa_e, server_rsa_N)
        signed_blinded_m_int = server.oprf_evaluate(blinded_m_int)
        oprf_output = oprf_finalize(original_m_int, r_factor, server_rsa_N, signed_blinded_m_int)
        
        stretched_oprf_output = ksf_stretch(oprf_output)
        ikm_reg = oprf_output + stretched_oprf_output
        randomized_password = kdf_extract(b"OPAQUE-Randomized-Password", ikm_reg)
        
        client_private_key_dh, client_public_key_dh = ake_derive_keypair(kdf_expand(randomized_password, b"ClientKeys", 64))
        masking_key = kdf_expand(randomized_password, b"MaskingKey", 32)
        export_key = kdf_expand(randomized_password, b"ExportKey", 32)
        auth_key = kdf_expand(randomized_password, b"EnvelopeAuthKey", 32)
        envelope_content = client_private_key_dh.to_bytes(DH_PRIVATE_KEY_SIZE, 'big')
        envelope_mac = mac_func(auth_key, envelope_content)
        envelope = envelope_mac + envelope_content
        
        print(f"客户端 {self.user_id} 注册完成。导出的密钥 (注册时): {export_key.hex()}")
        return {"client_public_key": client_public_key_dh, "masking_key": masking_key, "envelope": envelope}

    def generate_ke1(self, server_rsa_e, server_rsa_N):
        """
        客户端：生成登录流程的第一条消息 KE1。
        包含 OPRF 的致盲消息和客户端的 AKE 临时公钥。
        :param server_rsa_e: 服务器的 RSA 公钥指数 e。
        :param server_rsa_N: 服务器的 RSA 公钥模数 N。
        :return: KE1 消息字典。
        """
        blinded_m_int, original_m_int, r_factor = oprf_blind(self.password, server_rsa_e, server_rsa_N)
        self.session_state['original_m_int'] = original_m_int
        self.session_state['r_factor'] = r_factor
        
        credential_request = {"blinded_message_int": blinded_m_int}
        
        client_eph_sk_dh, client_eph_pk_dh = ake_derive_keypair(os.urandom(32))
        auth_request = {"client_eph_pk": client_eph_pk_dh}
        
        self.session_state['client_eph_sk_dh'] = client_eph_sk_dh
        self.session_state['client_eph_pk_dh'] = client_eph_pk_dh
        
        return {"credential_request": credential_request, "auth_request": auth_request}
    
    def generate_ke3(self, ke2, server_identity, server_rsa_N):
        """
        客户端：处理服务器的 KE2 消息，并生成最终的 KE3 消息。
        包括 OPRF 解盲、Envelope 恢复与验证、AKE 计算、服务器验证和客户端自身认证。
        :param ke2: 服务器发送的 KE2 消息字典。
        :param server_identity: 服务器的身份标识 (bytes)。
        :param server_rsa_N: 服务器的 RSA 公钥模数 N。
        :return: (KE3 消息字典, 会话密钥, 导出密钥) 或 (None, 错误信息, None)。
        """
        cred_resp = ke2['credential_response']
        auth_resp = ke2['auth_response']
        
        original_m_int = self.session_state['original_m_int']
        r_factor = self.session_state['r_factor']
        
        signed_blinded_m_int_from_server = int.from_bytes(cred_resp['evaluated_message'], 'big')
        oprf_output = oprf_finalize(original_m_int, r_factor, server_rsa_N, signed_blinded_m_int_from_server)
        
        stretched_oprf_output = ksf_stretch(oprf_output)
        ikm_login = oprf_output + stretched_oprf_output
        randomized_password = kdf_extract(b"OPAQUE-Randomized-Password", ikm_login)
        masking_key_c = kdf_expand(randomized_password, b"MaskingKey", 32)

        try:
            pad_info = masking_key_c + cred_resp['evaluated_message']
            pad_prk = kdf_extract(b"OPAQUE-Pad", pad_info)
            pad = kdf_expand(pad_prk, b"Pad", len(cred_resp['masked_response']))
            serialized_data = bytes(a ^ b for a, b in zip(cred_resp['masked_response'], pad))
            server_public_key_dh_c = serialized_data[0:DH_PUBLIC_KEY_SIZE]
            client_public_key_dh_c = serialized_data[DH_PUBLIC_KEY_SIZE:DH_PUBLIC_KEY_SIZE*2]
            envelope_c = serialized_data[DH_PUBLIC_KEY_SIZE*2:]
            auth_key_c = kdf_expand(randomized_password, b"EnvelopeAuthKey", 32)
            tag_c = envelope_c[:32]; content_c = envelope_c[32:]
            mac_verify(auth_key_c, tag_c, content_c)
            client_private_key_dh_c = int.from_bytes(content_c, 'big')
            export_key_c = kdf_expand(randomized_password, b"ExportKey", 32)
        except (IndexError, InvalidTag, KeyError) as e:
            print(f"客户端: Envelope恢复失败! {e}")
            return None, "密码错误或用户不存在", None
        
        dh1 = ake_dh(self.session_state['client_eph_sk_dh'], auth_resp['server_eph_pk'])
        dh2 = ake_dh(self.session_state['client_eph_sk_dh'], server_public_key_dh_c)
        dh3 = ake_dh(client_private_key_dh_c, auth_resp['server_eph_pk'])
        ikm_c = dh1 + dh2 + dh3
        
        preamble = server.server_identity + server_public_key_dh_c + client_public_key_dh_c + self.session_state['client_eph_pk_dh'] + auth_resp['server_eph_pk']
        
        session_key_c = kdf_expand(kdf_extract(b"", ikm_c), b"SessionKey" + preamble, 32)
        km2_c = kdf_expand(kdf_extract(b"", ikm_c), b"ServerMAC" + preamble, 32)
        km3_c = kdf_expand(kdf_extract(b"", ikm_c), b"ClientMAC" + preamble, 32)
        
        try:
            mac_verify(km2_c, auth_resp['server_mac'], preamble)
        except InvalidTag:
            return None, "服务器MAC验证失败，可能是假冒服务器!", None
            
        client_mac = mac_func(km3_c, preamble + auth_resp['server_mac'])
        del self.session_state
        
        return {"client_mac": client_mac}, session_key_c, export_key_c

# --- 5. 主执行流程 ---
if __name__ == "__main__":
    print("--- 场景1: 用户 'alice' 成功注册 ---")
    server = Server("cool-server.com")
    alice = Client("alice@example.com", "MySecretPassword123")
    
    reg_record = alice.finalize_registration(server.rsa_e, server.rsa_N)
    server.store_record(alice.user_id, reg_record)
    
    print("-" * 40)

    print("\n--- 场景2: 'alice' 使用正确密码成功登录 ---")
    alice_login = Client("alice@example.com", "MySecretPassword123")
    
    ke1 = alice_login.generate_ke1(server.rsa_e, server.rsa_N)
    # <<< 修改：传递完整的 ke1 字典给 server.generate_ke2 >>>
    ke2 = server.generate_ke2(alice_login.user_id, ke1)
    ke3, session_key, export_key = alice_login.generate_ke3(ke2, server.server_identity, server.rsa_N)
    
    if ke3:
        print("客户端: KE3 生成成功，正在发送...")
        final_key, msg = server.server_finish(alice_login.user_id, ke3)
        print(f"服务器响应: {msg}")
        if final_key:
            print(f"OPAQUE协议成功! 客户端会话密钥: {session_key.hex()}")
            print(f"OPAQUE协议成功! 服务器会话密钥: {final_key.hex()}")
            assert session_key == final_key
    else:
        print(f"客户端登录失败: {session_key}")
        
    print("-" * 40)

    print("\n--- 场景3: 'alice' 使用错误密码登录 ---")
    alice_bad_pass = Client("alice@example.com", "WrongPassword")
    
    ke1_bad = alice_bad_pass.generate_ke1(server.rsa_e, server.rsa_N)
    # <<< 修改：传递完整的 ke1_bad 字典给 server.generate_ke2 >>>
    ke2_bad = server.generate_ke2(alice_bad_pass.user_id, ke1_bad)
    ke3_bad, result, _ = alice_bad_pass.generate_ke3(ke2_bad, server.server_identity, server.rsa_N)
    
    if not ke3_bad:
        print(f"客户端登录失败: {result}")
        
    print("-" * 40)
    
    print("\n--- 场景4: 不存在的用户 'bob' 尝试登录 ---")
    bob_nonexistent = Client("bob@example.com", "anypassword")
    
    ke1_bob = bob_nonexistent.generate_ke1(server.rsa_e, server.rsa_N)
    # <<< 修改：传递完整的 ke1_bob 字典给 server.generate_ke2 >>>
    ke2_bob = server.generate_ke2(bob_nonexistent.user_id, ke1_bob)
    ke3_bob, result_bob, _ = bob_nonexistent.generate_ke3(ke2_bob, server.server_identity, server.rsa_N)
    
    if not ke3_bob:
        print(f"客户端登录失败: {result_bob}")
        
    print("-" * 40)
