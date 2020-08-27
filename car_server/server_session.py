from car_server import server
from car_server import server_hand_shake


class ServerSession:

    def __init__(self):
        # 本次会话的SessionID
        self.sessionID = None
        # 创建云端对象
        self.server = server.Server()
        # 创建握手信号生成对象
        self.server_handshake = server_hand_shake.MakeHandShake()

    def first_hand_shake(self):
        """
        首次握手
        """
        # 接收车端握手信号
        client_hello = self.server.recv_message()
        print("**接收到的车端client_hello信息**")
        print(client_hello)

        # 商议结果
        consultation_results = self.server.process_client_hello(client_hello)
        print("**商议结果**")
        print(consultation_results)
        # 商议结果为空，则结束会话
        if consultation_results is None:
            return False
        # 商议结果为快速握手，则执行快速握手
        """
        如果客户端和服务器之间曾经建立了连接，服务器会在握手成功后返回 session ID，并保存对应的通信参数在服务器中;
        如果客户端再次需要和该服务器建立连接，则在 client_hello 中 session ID 中携带记录的信息，发送给服务器;
        服务器根据收到的 session ID 检索缓存记录，如果没有检索到货缓存过期，则按照正常的握手过程进行;
        如果检索到对应的缓存记录，则返回 change_cipher_spec 与 encrypted_handshake_message 信息，两个信息作用类似，
        encrypted_handshake_message 是到当前的通信参数与 master_secret的hash 值;
        如果客户端能够验证通过服务器加密数据，则客户端同样发送 change_cipher_spec 与 encrypted_handshake_message 信息;
        服务器验证数据通过，则握手建立成功，开始进行正常的加密数据通信。
        """
        if len(consultation_results) < 2:
            quick_hello = self.server_handshake.gen_quick_hello(consultation_results)
            # print(quick_hello)
            self.server.send_message(quick_hello)
            return self.quick_shake_hand(client_hello, quick_hello)

        # 发送车端握手信号
        server_hello = self.server_handshake.gen_server_hello(consultation_results, self.server)
        self.server.send_message(server_hello)

        # 发送ca
        ca = self.server_handshake.gen_ca(self.server)
        self.server.send_message(ca)

        # 发送server_hello_done
        server_hello_done = self.server_handshake.gen_server_hello_done()
        self.server.send_message(server_hello_done)

        # 接收预主密钥
        """
        云端解密这个预主密钥，就可以获得随机数。
        """
        pre_master_key = self.server.recv_pre_master_key()
        print("**接收到的预主密钥信息**")
        print(pre_master_key)

        # 解密预主密钥获得随机数,至此客户端也接收到了三个随机数
        self.server.dec_pre_master_key(pre_master_key)
        # 计算传输密钥
        key = self.server.calculate_key()
        print("**云端计算的传输密钥**")
        print(key)

        self.quick_shake_hand(client_hello, server_hello)

        self.sessionID_dict = self.server.gen_session_id()
        print("发送的sessionID")
        print(self.sessionID_dict)
        self.sessionID = self.sessionID_dict['sessionID']
        self.server.redis_server.add_sessionID(self.sessionID)
        self.server.send_message(self.sessionID_dict)
        print("握手完成！")
        return True

    def quick_shake_hand(self, client_hello, quick_hello):
        # 接收客户端change_cipher
        client_change_cipher = self.server.recv_message()
        print("**接收到的车端chagee_cipher信息**")
        print(client_change_cipher)

        # 接收客户端encrypted_handshake
        client_encrypted_handshake = self.server.recv_message()
        print("**接收到的车端encrypted_handshake信息**")
        print(client_encrypted_handshake)
        # 验证
        flg = self.server.verify_trans_key(client_encrypted_handshake, client_hello)
        # 验证失败，则结束握手
        if not flg:
            return False

        # 发送change cipher spec
        """
        服务端通知客户端后面再发送的消息都会使用加密，也是一条事件消息。
        """
        server_change_cipher = self.server_handshake.gen_change_cipher_spec()
        print("*发送的车端change cipher消息*")
        print(server_change_cipher)
        self.server.send_message(server_change_cipher)

        # 发送Encrypted Handshake Message
        """
        这一步对应的是 Server Finish 消息，服务端也会将握手过程的消息生成摘要再用秘钥加密
        ，这是服务端发出的第一条加密消息。客户端接收后会用秘钥解密，能解出来说明协商的秘钥是一致的。
        """
        encrypted_handshake_message = self.server_handshake.gen_encrypted_handshake_message(quick_hello, self.server)
        print("*发送的车端encrypted handshake message*")
        print(encrypted_handshake_message)
        self.server.send_message(encrypted_handshake_message)
        return True

    def send_message(self):
        while True:
            message = self.server.recv_message()
            true_message = self.server.transfer_decrypt(message['encrypted_message'])
            print("收到的明文:" + true_message)
            if self.server.make_hash(message['encrypted_message']) == message['hash_message']:
                print("消息完整")
            if true_message == "q":
                break
            r_msg = input("It seems like you want to say something>>")
            if r_msg == "q":
                break
            encrypted_str = self.server.transfer_encrypt(r_msg)
            hash_message = self.server.make_hash(encrypted_str)
            encrypted_str_message = {
                "encrypted_str": encrypted_str,
                "hash_message": hash_message
            }
            self.server.send_message(encrypted_str_message)


if __name__ == '__main__':
    s = ServerSession()
    while True:
        flg = s.first_hand_shake()
        if flg:
            s.send_message()
