import time
import psutil
import random


class CommonUtil:

    def gen_random(self):
        """以时间戳、进程ID以及当前内存状况作为熵源构造随机数"""
        # 时间戳
        t = int(time.time())
        pid_list = []
        for pro in psutil.process_iter():
            try:
                pinfo = pro.as_dict(attrs=['pid'])
                pid_list.append(pinfo['pid'])
            except psutil.NoSuchProcess:
                continue
        # 随机进程ID
        process_id = random.choice(pid_list)
        # 内存可用状况
        mem_available = psutil.virtual_memory().available
        # 抑或操作之后生成随机数
        return int((t ^ mem_available) / process_id)

    def gen_secret_key(self):
        pass


if __name__ == '__main__':
    common = CommonUtil()
    # common.gen_random()
    print(common.gen_random())
