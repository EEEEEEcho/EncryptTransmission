from car_client import client
from car_client import client_hand_shake
import json


class ClientSession:

    def __init__(self):
        # 本次会话的SessionID
        self.sessionID = None
        # 创建车端对象
        self.car_client = client.Client()
        # 创建握手信号生成对象
        self.car_client_handshake = client_hand_shake.MakeHandShake()

    def first_shake_hand(self):
        """
        会话发起首次握手
        :return: True 握手成功
        """

        # 发送握手信号
        """
        握手第一步是客户端向服务端发送 Client Hello 消息，
        这个消息里包含了一个客户端生成的随机数 Random1、
        客户端支持的加密套件（Support Ciphers）和 SSL Version 等信息
        """
        client_hello = self.car_client_handshake.gen_client_hello(self.car_client, self.sessionID)
        self.car_client.send_message(client_hello)

        # 接收服务端server_hello信号
        server_hello = self.car_client.recv_message()
        print("**接收到的云端server_hello信息**")
        self.show_detail(server_hello)
        # 如果是快速握手，执行快速握手
        if len(server_hello) < 2:
            return self.quick_hand_shake(client_hello, server_hello)

        # 接收服务端ca证书
        ca = self.car_client.recv_message()
        print("**接收到的云端证书信息**")
        self.show_detail(ca)

        # 接收服务端server_hello_done
        server_hello_done = self.car_client.recv_message()
        print("**接收到的云端hello_done信息**")
        self.show_detail(server_hello_done)

        # 处理服务端所发送过来的server_hello信号，从而确定使用的加密套件
        """ 
        客户端收到服务端传来的证书后，先从 CA 验证该证书的合法性，验证通过后取出证书中的服务端公钥，
        """
        process_result = self.car_client.process_server_hello(server_hello, ca, server_hello_done)
        if not process_result:
            # 如果验证不通过，则结束会话
            print("验证失败.")
            return

        # 生成预主密钥
        """
        生成一个随机数 Random3，再用服务端公钥非对称加密 Random3 生成 PreMaster Key。
        """
        pre_master_key = self.car_client.gen_pre_master_key()
        print("**生成的预主密钥**")
        print(pre_master_key)

        # 发送预主密钥
        """
        将这个 key 传给服务端，服务端再用自己的私钥解出这个 PreMaster Key 得到客户端生成的 Random3.
        """
        self.car_client.send_pre_master_key(pre_master_key)

        # 计算传输密钥
        """
        至此，客户端和服务端都拥有 Random1 + Random2 + Random3，两边再根据同样的算法就可以生成一份秘钥，
        握手结束后数据都是使用这个秘钥进行对称加密。
        """
        key = self.car_client.calculate_key()
        print("车端计算的传输密钥")
        print(key)

        self.quick_hand_shake(client_hello, server_hello)

        sessionID_dict = self.car_client.recv_message()
        print("**接收到的车端的sessionID")
        print(sessionID_dict)
        self.sessionID = sessionID_dict['sessionID']
        print("握手完成！")
        return True

    def quick_hand_shake(self, client_hello, server_hello):
        # 发送change_cipher
        """
        客户端通知服务端后面再发送的消息都会使用前面协商出来的秘钥加密了，是一条事件消息。
        """
        change_cipher = self.car_client_handshake.gen_change_cipher_spec()
        print("*发送的车端change_cipher信息*")
        print(change_cipher)
        self.car_client.send_message(change_cipher)

        # 发送encrypted_handshake_message
        """
        对应的是 Client Finish 消息，客户端将前面的握手消息生成摘要再用协商好的秘钥加密，
        这是客户端发出的第一条加密消息。服务端接收后会用秘钥解密，
        能解出来说明前面协商出来的秘钥是一致的。
        """
        encrypted_handshake_message = self.car_client_handshake.gen_encrypted_handshake_message(client_hello,
                                                                                                self.car_client)
        print("*发送的车端encrypted_handshake_message*")
        print(encrypted_handshake_message)
        self.car_client.send_message(encrypted_handshake_message)

        # 接收服务端发来的change cipher
        server_change_cipher_json = self.car_client.recv_message()
        print("**接收到的云端change_cipher信息**")
        print(server_change_cipher_json)

        # 接收服务端的Encrypted Handshake Message
        encrypted_handshake_message_json = self.car_client.recv_message()
        print("**接收到的云端encrypted_handshake信息**")
        print(encrypted_handshake_message_json)

        # 验证
        flg = self.car_client.verify_trans_key(encrypted_handshake_message_json, server_hello)
        if not flg:
            return False
        return True

    def sendMessage(self):
        while True:
            input_str = input("If you want to crate car information?")
            if input_str == "y":
                car_info = self.car_client.create_car_info()
                encrypted_car_info = self.car_client.transfer_encrypt(json.dumps(car_info))
                hash_car_info = self.car_client.make_hash(encrypted_car_info)
                encryted_message = {
                    "encrypted_message": encrypted_car_info,
                    "hash_message": hash_car_info
                }
                self.car_client.send_message(encryted_message)
            else:
                message = input("It seems like you just want to chat.")
                encrypted_str = self.car_client.transfer_encrypt(message)
                hash_message = self.car_client.make_hash(encrypted_str)
                encrypted_str_message = {
                    "encrypted_message": encrypted_str,
                    "hash_message": hash_message
                }
                self.car_client.send_message(encrypted_str_message)
                if message == "q":
                    break
            ret = self.car_client.recv_message()
            true_message = self.car_client.transfer_decrypt(ret['encrypted_str'])
            print("收到的明文" + true_message)
            hash_message = ret["hash_message"]
            if hash_message == self.car_client.make_hash(ret['encrypted_str']):
                print("消息完整")

    def show_detail(self, json_str):
        for key, value in json_str.items():
            print(str(key) + " : " + str(value))


if __name__ == '__main__':
    c = ClientSession()
    while True:
        flg = c.first_shake_hand()
        if flg:
            c.sendMessage()
