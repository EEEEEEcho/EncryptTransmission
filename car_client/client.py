from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import hashlib
import socket
import struct
import json
import rsa
from car_client import common_util
import time
import zlib


class Client:

    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aim_domain = "127.0.0.1"
        self.aim_port = 8088
        self.client.connect((self.aim_domain, self.aim_port))
        self.client_randnum1 = None
        self.server_randnum = None
        self.client_randnum2 = None

        self.ca_domain_list = [
            "www.baidu.com",
            "www.sina.com"
        ]

        self.server_public_key = None

    def pack_data(self, json_data):
        # 封装为json
        data_signal = json.dumps(json_data)
        # 编码
        data_signal_bytes = data_signal.encode("utf-8")
        # 求长度
        data_signal_length = struct.pack('i', len(data_signal_bytes))
        return data_signal_length, data_signal_bytes

    def process_server_hello(self, server_hello_json, ca_json, server_hello_done_json):
        """
        处理服务端发来的server_hello,查看服务端确定的加密套件
        客户端验证证书的合法性，如果验证通过才会进行后续通信，否则根据错误情况不同做出提示和操作，合法性验证包括如下：
        证书链的可信性
        证书是否吊销 revocation，有两类方式离线 CRL 与在线 OCSP，不同的客户端行为会不同;
        有效期 expiry date，证书是否在有效时间范围;
        域名 domain，核查证书域名是否与当前的访问域名匹配，匹配规则后续分析;

        至此客户端和服务端都拥有了两个随机数（Random1+ Random2），这两个随机数会在后续生成对称秘钥时用到。
        :param server_hello_json:
        :param ca_json:
        :param server_hello_done_json:
        :return:
        """
        choose_cipher_suite = server_hello_json['Cipher Suite']
        choose_compression_method = server_hello_json['Compression Method']
        self.server_randnum = server_hello_json['Random']
        ca_domain = ca_json['Ca Domain']
        ca_is_revocation = ca_json['Ca Is Revocation']
        ca_expiry_date = ca_json['Ca Expiry Date']
        self.server_public_key = rsa.PublicKey.load_pkcs1(ca_json['Public Key'].encode())
        self.client_randnum2 = common_util.CommonUtil().gen_random()
        flg = True
        if ca_domain not in self.ca_domain_list or ca_is_revocation:
            flg = False
        time_array = time.strptime(ca_expiry_date, "%Y-%m-%d %H:%M:%S")
        timestamp = int(time.mktime(time_array))
        now_time = int(time.time())
        if now_time > timestamp or server_hello_done_json['Server Hello Done'] != 'OK':
            flg = False
        return flg

    def gen_pre_master_key(self):
        """
        生成预主密钥，该预主密钥时
        合法性验证通过之后，客户端计算产生随机数字 Pre-master，并用证书公钥加密，发送给服务器;
        :return:
        """
        cr = str(self.client_randnum2).encode()
        pre_master_key = rsa.encrypt(cr, self.server_public_key)
        return pre_master_key

    def send_pre_master_key(self, pre_master_key):
        pre_master_key_length = struct.pack('i', len(pre_master_key))
        self.client.send(pre_master_key_length)
        self.client.send(pre_master_key)

    def calculate_key(self):
        self.key = str(self.client_randnum1) + str(self.server_randnum) + str(self.client_randnum2)
        return self.key

    def verify_trans_key(self, encrypted_handshake_message_json, server_hello_json):
        """
        验证服务端的server_hello信号经摘要然后传输加密的结果
        先解密，然后对本地保留的server_hello进行摘要，与解密后的摘要对比
        :param encrypted_handshake_message_json:
        :param server_hello_json:
        :return:
        """
        server_hello_hash_encrypt = encrypted_handshake_message_json['HandShake Protocol']
        server_hello_hash_decrypt = self.transfer_decrypt(server_hello_hash_encrypt)
        print("解密后云端发送的摘要值",server_hello_hash_decrypt)
        recv_server_hello = self.make_hash(server_hello_json)
        print("车端计算的client hello的摘要值", recv_server_hello)
        if server_hello_hash_decrypt != recv_server_hello:
            return False
        return True

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
        # print(bytes.decode(plain_text).rstrip('\0'))
        return bytes.decode(plain_text).rstrip('\0')

    def make_hash(self, message):
        if isinstance(message, dict):
            return hashlib.sha256(json.dumps(message).encode()).hexdigest()
        elif isinstance(message, str):
            return hashlib.sha256(message.encode()).hexdigest()

    def add_to_16(self, text):
        if len(text.encode('utf-8')) % 16:
            add = 16 - (len(text.encode('utf-8')) % 16)
        else:
            add = 0
        text = text + ('\0' * add)
        return text.encode('utf-8')

    def send_message(self, message):
        try:
            message_length, message_bytes = self.pack_data(message)
            self.client.send(message_length)
            self.client.send(message_bytes)
            return True
        except:
            return False

    def recv_message(self):
        header = self.client.recv(4)
        length = struct.unpack('i', header)[0]
        data = json.loads(self.client.recv(length))
        return data

    def create_car_info(self):
        car_info = {
            "name": "Lamborghini",
            "position": {
                "x": 106.8,
                "y": 78.5
            },
            "Time": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return car_info

    def zip_send(self, message):
        try:
            message_length, message_bytes = self.pack_data(message)
            message_bytes = zlib.compress(message_bytes)
            self.client.send(bytes(len(message_bytes)))
            self.client.send(message_bytes)
            return True
        except:
            return False

    def zip_recv(self):
        header = self.client.recv(4)
        length = struct.unpack('i', header)[0]
        data = json.loads(zlib.decompress(self.client.recv(length)))
        return data
