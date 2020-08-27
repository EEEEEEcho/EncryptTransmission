from car_server import common_util
import json
import time


class MakeHandShake:

    def gen_server_hello(self, consultation_results, server):
        """
        生成车端握手信号
        根据所协商的信息，选择使用的协议版本 version，选择的加密套件 cipher suite，
        选择的压缩算法 compression method、随机数 server_random 等，其中随机数用于后续的密钥协商;
        :param consultation_results:
        :param server:
        :return:
        """
        server.server_randnum = common_util.CommonUtil().gen_random()
        server_hello_signal = {
            "HandShake Protocol": "Server Hello",
            "Length": None,
            "Version": consultation_results['Version'],
            "Random": server.server_randnum,
            "SessionID length": 0,
            "Cipher Suite": consultation_results['Cipher Suite'],
            "Compression Method": consultation_results['Compression Method'],
            "Extension Length": 48,
            "Extension": "Hello world"
        }
        return server_hello_signal

    def gen_quick_hello(self, consultation_results):
        return consultation_results

    def gen_ca(self, server):
        """
        服务器端配置对应的证书链，用于身份验证与密钥交换;
        :param server:
        :return:
        """
        return {
            "Certificate": "Hello World",
            "Ca Domain": "www.baidu.com",
            "Ca Is Revocation": False,
            "Ca Expiry Date": "2020-10-01 00:00:00",
            "Public Key": server.public_key.save_pkcs1().decode()
        }

    def gen_server_hello_done(self):
        """
        生成server_hello_done信号
        通知客户端 server_hello 信息发送结束;
        :return:
        """
        return {
            "Server Hello Done": "OK"
        }

    def gen_change_cipher_spec(self):
        """
        服务端通知客户端后面再发送的消息都会使用加密，也是一条事件消息。
        :return:
        """
        return {
            "Change Cipher Spec": "Message"
        }

    def gen_encrypted_handshake_message(self, server_hello, server):
        """
        这一步对应的是 Server Finish 消息，服务端也会将握手过程的消息生成摘要再用秘钥加密，这是服务端发出的第一条加密消息。
        客户端接收后会用秘钥解密，能解出来说明协商的秘钥是一致的。
        :param server_hello:
        :param server:
        :return:
        """
        hash_server_hello = server.make_hash(server_hello)
        encrypt_server_hello = server.transfer_encrypt(hash_server_hello)
        encrypted_handshake_message = {
            "HandShake Protocol": encrypt_server_hello
        }
        return encrypted_handshake_message
