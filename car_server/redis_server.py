import redis


class RedisServer:

    def __init__(self):
        self.host = "localhost"
        self.port = 6379
        self.pool = redis.ConnectionPool(host=self.host, port=self.port)
        self.rds = redis.Redis(connection_pool=self.pool)
        self.rds.sadd("sessionIDs", "")

    def add_sessionID(self, sessionID):
        self.rds.sadd("sessionIDs", sessionID)
        return True

    def check_sessionID(self, sessionID):
        if sessionID is not None and self.rds.sismember("sessionIDs", sessionID):
            return True
        return False
