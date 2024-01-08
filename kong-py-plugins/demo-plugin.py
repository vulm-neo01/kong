import os

import kong_pdk.pdk.kong as kong
import redis
# from redis.cluster import RedisCluster as Redis

Schema = (
    {"message": {"type": "string"}},
)
version = '0.1.0'
priority = 1


def example_access_phase(kong: kong.kong):
    kong.log.debug("Hello!")
    data = redis_string()

    if not data:
        kong.response.exit(500, "Error")
    kong.log.debug(str(data))
    kong.response.exit(200, f"Data: {str(data)}")


def redis_string():
    redis_host = 'redis'
    redis_port = 6379
    # r = redis.StrictRedis(host=redis_host, port=redis_port, decode_responses=True)
    r = redis.Redis(host=redis_host, port=redis_port)
    mes = r.get("helllo")
    return mes


class Plugin(object):
    def __init__(self, config):
        self.config = config

    def access(self, kong: kong.kong):
        example_access_phase(kong)


if __name__ == "__main__":
    from kong_pdk.cli import start_dedicated_server

    start_dedicated_server("py-hello", Plugin, version, priority)
