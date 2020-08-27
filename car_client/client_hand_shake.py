from car_client import common_util

class MakeHandShake:

    def gen_client_hello(self, car_client, sessionID):
        """
        构造握手信号的函数
        包括支持的最高TSL协议版本version，从低到高依次 SSLv2 SSLv3 TLSv1 TLSv1.1 TLSv1.2，当前基本不再使用低于 TLSv1 的版本;
        客户端支持的加密套件 cipher suites 列表，包括
        密钥交换算法 KeyExchange(密钥协商)、对称加密算法 Enc (信息加密)和信息摘要 Mac(完整性校验);
        支持的压缩算法 compression methods 列表，用于后续的信息压缩传输;
        随机数 client_random1，用于后续的密钥的生成;
        扩展字段 extensions，支持协议与算法的相关参数以及其它辅助信息等，
        :param car_client: 车端对象，在生成随机数时，将随机数返回给车端 
        :param sessionID: 会话的ID
        :return: 构造的握手信号字典
        """""
        # 所支持的协议版本
        support_version = ["SSLv2", "SSLv3", "TSLv1", "TLSv1.1", "TLSv1.2"]
        # 随机数通过构造的工具类来生成
        random_num = common_util.CommonUtil().gen_random()
        car_client.client_randnum1 = random_num
        # 获取sessionID,采用的是python自带的uuid
        session_id = sessionID
        # sessionID的长度
        if session_id is None:
            session_id_len = 0
        else:
            session_id_len = session_id.__sizeof__()
        # 加密套件，这里先只用两个,其中每一个列表又包含套件名字和优先级
        cipher_suites = [
            {"TLS_ECDHE_RSA_WITH_AES_128_ECB_SHA256": 8},
            {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 2}
        ]
        # 加密套件长度
        cipher_suits_len = cipher_suites.__sizeof__()
        # 压缩算法 同理包括算法名和优先级
        comperssion_methods = [
            {'zlib': 10}
        ]
        # 压缩算法长度
        comperssion_methods_len = comperssion_methods.__sizeof__()
        # 扩展内容
        extension = {
            'car_server-name': 'echo',
            'car_server-ip': '127.0.0.1'
        }
        # 扩展内容长度
        extension_len = extension.__sizeof__()
        # 握手信号
        hand_shake_signal = {
            "HandShake Protocol": "Client Hello",
            "Length": None,
            "Version": support_version,
            "Random": random_num,
            "SessionID Length": session_id_len,
            "SessionID": session_id,
            "Cipher Suites Length": cipher_suits_len,
            "Cipher Suites": cipher_suites,
            'Compression Methods Length': comperssion_methods_len,
            'Compression Methods': comperssion_methods,
            'Extension Length': extension_len,
            'Extension': extension
        }
        return hand_shake_signal

    def gen_change_cipher_spec(self):
        """
        生成Change Cipher Spec
        :return:
        """
        return {
            "Change Cipher Spec": "Message"
        }

    def gen_encrypted_handshake_message(self, client_hello, client):
        """
        这一步对应的是 Client Finish 消息，客户端将前面的握手消息生成摘要再用协商好的秘钥加密，
        这是客户端发出的第一条加密消息。服务端接收后会用秘钥解密，
        能解出来说明前面协商出来的秘钥是一致的。
        :param client_hello:
        :param client:
        :return:
        """
        hash_client_hello = client.make_hash(client_hello)
        print("client hello摘要后的值", hash_client_hello)
        encrypt_client_hello = client.transfer_encrypt(hash_client_hello)
        print("client hello摘要并加密后的值", encrypt_client_hello)
        encrypted_handshake_message = {
            "HandShake Protocol": encrypt_client_hello
        }
        return encrypted_handshake_message
