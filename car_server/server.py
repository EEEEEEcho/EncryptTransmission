import zlib
import socket
import struct
import json
from car_server import redis_server
import rsa
import hashlib
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import uuid


class Server:

    def __init__(self):
        self.server_version = "TLSv1.2"
        self.sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 重用地址端口
        self.sock_server.bind(('127.0.0.1', 8088))
        self.sock_server.listen(1)  # 开始监听，1代表在允许有一个连接排队，更多的新连接连进来时就会被拒绝
        self.server, client_addr = self.sock_server.accept()
        self.client_randnum1 = None  # process_client_hello中获得
        self.server_randnum = None  # gen_server_hello中获得
        self.client_randnum2 = None  #
        # 初始化服务端支持的加密套件
        self.server_cipher_suites = [
            'TLS_ECDHE_RSA_WITH_AES_128_ECB_SHA256'
        ]
        self.server_compression_suites = [
            "zlib"
        ]
        # 初始化缓存
        self.redis_server = redis_server.RedisServer()
        # 服务端公钥私钥生成
        self.public_key, self.private_key = rsa.newkeys(1024)

    def process_client_hello(self, client_hello_data):
        """
        处理client_hello,获取车端发来的随机数，验证是否为短握手，协商加密套件
        :param client_hello_data:
        :return:
        """
        self.client_randnum1 = client_hello_data['Random']
        if self.server_version not in client_hello_data['Version']:
            return None
        # 判断是否为短握手
        if self.redis_server.check_sessionID(client_hello_data['SessionID']):
            return {
                "Quick Shake Hand": True
            }
        # 协商加密套件
        server_cipher_suite = self.get_method_suites(self.server_cipher_suites, client_hello_data['Cipher Suites'])
        server_compression_method = self.get_method_suites(self.server_compression_suites,
                                                           client_hello_data['Compression Methods'])
        if server_cipher_suite == None or server_compression_method == None:
            return None
        consultation_results = {
            "Version": self.server_version,
            "Cipher Suite": server_cipher_suite,
            "Compression Method": server_compression_method
        }
        return consultation_results

    def get_method_suites(self, server_suites, client_suites):
        """服务端确定加密套件或压缩算法"""
        for server_suite in server_suites:
            for client_suite in client_suites:
                # print(list(dict(client_chiper_suite).keys())[0])
                if server_suite == list(dict(client_suite).keys())[0]:
                    return server_suite
                else:
                    return None

    def recv_pre_master_key(self):
        pre_master_key_header = self.server.recv(4)
        pre_master_key_length = struct.unpack('i', pre_master_key_header)[0]
        pre_master_key = self.server.recv(pre_master_key_length)
        return pre_master_key

    def transfer_encrypt(self, message):
        key = self.key[-17:-1].encode("utf-8")
        mode = AES.MODE_ECB
        message = self.add_to_16(message)
        crypto = AES.new(key, mode)
        cipher_text = crypto.encrypt(message)
        # print(cipher_text)
        return b2a_hex(cipher_text).decode()

    def transfer_decrypt(self, message):
        key = self.key[-17:-1].encode("utf-8")
        mode = AES.MODE_ECB
        cryptor = AES.new(key, mode)
        plain_text = cryptor.decrypt(a2b_hex(message.encode()))
        return bytes.decode(plain_text).rstrip('\0')

    def add_to_16(self, text):
        if len(text.encode('utf-8')) % 16:
            add = 16 - (len(text.encode('utf-8')) % 16)
        else:
            add = 0
        text = text + ('\0' * add)
        return text.encode('utf-8')

    def pack_data(self, json_data):
        # 封装为json
        data_signal = json.dumps(json_data)
        # 编码
        data_signal_bytes = data_signal.encode("utf-8")
        # 求长度
        data_signal_length = struct.pack('i', len(data_signal_bytes))
        return data_signal_length, data_signal_bytes

    def dec_pre_master_key(self, pre_master_key):
        self.client_randnum2 = rsa.decrypt(pre_master_key, self.private_key).decode()

    def make_hash(self, message):
        if isinstance(message, dict):
            return hashlib.sha256(json.dumps(message).encode()).hexdigest()
        elif isinstance(message, str):
            return hashlib.sha256(message.encode()).hexdigest()

    def send_message(self, message):
        try:
            message_length, message_bytes = self.pack_data(message)
            self.server.send(message_length)
            self.server.send(message_bytes)
            return True
        except:
            return False

    def recv_message(self):
        header = self.server.recv(4)
        length = struct.unpack('i', header)[0]
        data = json.loads(self.server.recv(length))
        return data

    def calculate_key(self):
        self.key = str(self.client_randnum1) + str(self.server_randnum) + str(self.client_randnum2)
        print("计算的传输密钥")
        print(self.key)
        return self.key

    def verify_trans_key(self, encrypted_handshake_message_json, client_hello_json):
        """
        验证客户端的client_hello信号经摘要然后传输加密的结果
        先解密，然后对本地保留的client_hello进行摘要，与解密后的摘要对比
        :param encrypted_handshake_message_json:
        :param client_hello_json:
        :return:
        """
        client_hello_hash_encrypt = encrypted_handshake_message_json['HandShake Protocol']
        client_hello_hash_decrypt = self.transfer_decrypt(client_hello_hash_encrypt)
        print("解密后车端发送的摘要值",client_hello_hash_decrypt)
        recv_client_hello = self.make_hash(client_hello_json)
        print("云端本地计算的client hello的摘要值",recv_client_hello)
        if client_hello_hash_decrypt != recv_client_hello:
            return False
        return True

    def gen_session_id(self):
        return {
            "sessionID": str(uuid.uuid4())
        }

    def zip_send(self, message):
        try:
            message_length, message_bytes = self.pack_data(message)
            message_bytes = zlib.compress(message_bytes)
            self.server.send(bytes(len(message_bytes)))
            self.server.send(message_bytes)
            return True
        except:
            return False

    def zip_recv(self):
        header = self.server.recv(4)
        length = struct.unpack('i', header)[0]
        data = json.loads(zlib.decompress(self.server.recv(length)))
        return data
