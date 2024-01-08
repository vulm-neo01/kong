import os

import kong_pdk.pdk.kong as kong
import re
import datetime
import jwt
import redis
from redis.cluster import RedisCluster, ClusterNode

Schema = (
    {
        "zone_id": {
            "description": "Zone identification",
            "type": "string",
            "default": "1",
        }
    },
    {
        "network_type": {
            "description": "Network type default defined here: Viettel, Vina, Mobifone,...",
            "type": "string",
            "default": "0",  # Wifi
        },
    },
    {
        "lang_list": {
            "description": "Language can using",
            "type": "array",
            "elements": {
                "type": "string",
            },
            "default": ["vi", "en"],
        },
    },
    {
        "verified_ips": {
            "description": "List of IPs that from Viettel network",
            "type": "array",
            "elements": {
                "type": "string",
            },
            "default": [
                "10.1.1.1",
                "10.1.0.0/16",
                "10.2.0.0/16",
                "10.3.0.0/16",
                "10.4.0.0/16",
                "10.5.0.0/16",
                "10.6.0.0/16",
                "10.7.0.0/16",
                "10.8.0.0/16",
                "10.9.0.0/16",
                "10.10.0.0/16",
                "10.11.0.0/16",
                "10.12.0.0/16",
            ],
        }
    },
    {
        "redis_host": {
            "description": "A string representing a host name, such as example.com.",
            "type": "string",
            "default": "localhost",  # Wifi
        },
    },
    {
        "redis_port": {
            "type": "integer",
            "description": "An integer representing a port number between 0 and 65535, inclusive.",
            "default": 6379,
        },
    },
    # {
    #     "redis_password": {
    #         "description": "When using the `redis` policy, this property specifies the password to connect to the "
    #                        "Redis server.",
    #         "type": "string",
    #         "len_min": 0,
    #         "referenceable": True,
    #     },
    # },
    # {
    #     "redis_username": {
    #         "description": "When using the `redis` policy, this property specifies the username to connect to the "
    #                        "Redis server when ACL authentication is desired.",
    #         "type": "string",
    #         "referenceable": True,
    #     },
    # },
    # {
    #     "redis_ssl": {
    #         "description": "When using the `redis` policy, this property specifies if SSL is used to connect to the "
    #                        "Redis server.",
    #         "type": "boolean",
    #         "required": True,
    #         "default": False,
    #     },
    # },
    # {
    #     "redis_ssl_verify": {
    #         "description": "When using the `redis` policy with `redis_ssl` set to `true`, this property specifies it "
    #                        "server SSL certificate is validated. Note that you need to configure the "
    #                        "lua_ssl_trusted_certificate to specify the CA (or server) certificate used by your Redis "
    #                        "server. You may also need to configure lua_ssl_verify_depth accordingly.",
    #         "type": "boolean",
    #         "required": True,
    #         "default": False,
    #     },
    # },
    # {
    #     "redis_server_name": {
    #         "type": "string",
    #         "description": "A string representing an SNI (server name indication) value for TLS."
    #     },
    # },
    {
        "redis_timeout": {
            "description": "When using the `redis` policy, this property specifies the timeout in milliseconds of any "
                           "command submitted to the Redis server.",
            "type": "number",
            "default": 2000,
        },
    },
    {
        "redis_database": {
            "description": "When using the `redis` policy, this property specifies the Redis database to use.",
            "type": "integer",
            "default": 0,
        },
    }
)
version = '0.1.0'
priority = 100


def retrieve_token(kong: kong.kong, request):
    # Get the request headers
    headers = request.get_headers()
    authorization_header = headers.get("authorization")

    kong.log.debug(authorization_header)

    # Check if any headers are present
    if not headers:
        kong.response.exit(401, "Authorization header is empty")

    # Check if Authorization header exists
    if not authorization_header:
        kong.response.exit(401, "Authorization header is missing")

    # Extract the token using regex (assuming "Bearer" scheme)
    match = re.search(r"\s*[Bb]earer\s+(.+)", str(authorization_header))

    kong.log.debug(match)

    # No match found
    if not match:
        kong.log.err("Invalid header authorization format")
        return None

    # Extract the token from the match group
    token = match.group(1)
    kong.log.debug(f"Token: {token}")

    # Không hiểu tại sao lại có thêm vào ký tự vào cuối token nên phải bỏ đi
    return token.split("']")[0]


def get_matching_lang(lang, lang_list, default):
    # Validate input
    if lang and lang_list:
        # Loop through the language list for a match
        first = lang[0]
        for value in lang_list:
            if first.lower() == str(value).lower():
                return value

    return default


class Plugin(object):
    def __init__(self, config):
        self.config = config
        self.zone_id = config["zone_id"]
        self.network_type = config["network_type"]
        self.lang_list = config["lang_list"]
        self.zone_id = config["zone_id"]
        self.network_type = config["network_type"]
        self.verified_ips = config["verified_ips"]
        self.redis_host = config["redis_host"]
        self.redis_port = config["redis_port"]
        # self.redis_password = config["redis_password"]
        # self.redis_username = config["redis_username"]
        # self.redis_ssl = config["redis_ssl"]
        # self.redis_ssl_verify = config["redis_ssl_verify"]
        # self.redis_server_name = config["redis_server_name"]
        self.redis_timeout = config["redis_timeout"]
        self.redis_database = config["redis_database"]

    def access(self, kong: kong.kong):
        token = retrieve_token(kong, kong.request)

        if not token:
            kong.response.exit(500, "jwt-auth -- Error when retrieving token")
        kong.log.debug(f"Token received:{token}")

        # Define default language and get lang list from header, then check for a match
        def_lang = "vi"
        headers = kong.request.get_headers()
        requested_lang = headers.get("lang")

        lang = get_matching_lang(requested_lang, self.lang_list, def_lang)
        kong.log.debug(lang)

        # Get IP of user and set network type
        requested_ip = kong.client.get_forwarded_ip()
        kong.log.debug(f"Requested IP: {requested_ip}")
        network_type = "0"
        if self.network_type:
            network_type = self.network_type
        for ip in self.verified_ips:
            kong.log.debug(f"Check Ip: {ip}")
            if ip == requested_ip:
                network_type = '1'  # Viettel
                break
        kong.log.debug(f"Network Type: {network_type}")

        # Set zoneId
        zone_id = "1"
        if self.zone_id:
            zone_id = self.zone_id
            kong.log.debug(f"Zone Id: {zone_id}")

        # Validate token if present
        if token:
            jwt_claims = None
            try:
                # Decode the token without a secret key and define algorithms list
                decoded_token = jwt.decode(token, algorithms=["HS256"])  # Set secret of jwt token is null
                kong.log.debug(decoded_token)

                # Access the claims (payload) of the token
                jwt_claims = decoded_token

            except jwt.ExpiredSignatureError as e:
                kong.log.err(e)
                kong.response.exit(401, "jwt-auth - Token has expired")

            except jwt.InvalidSignatureError as e:
                kong.log.err(e)
                kong.response.exit(401, "jwt-auth - Invalid Signature Error")

            except jwt.InvalidTokenError as e:
                kong.log.err(e)
                kong.response.exit(401, "jwt-auth - Invalid token")

            if not jwt_claims:
                kong.response.exit(500, "jwt-auth - Token was found, but failed to decoded")
            kong.log.debug(jwt_claims)

            # Check token is expired
            # exp_claim = jwt_claims.get("exp")
            # current_time = datetime.datetime.utcnow().timestamp()
            #
            # if exp_claim:
            #     kong.log.debug(current_time)
            #     kong.log.debug(exp_claim)
            #     if exp_claim < current_time:
            #         kong.response.exit(401, "jwt-auth - Token has expired")
            #     else:
            #         kong.log.debug("Token has not expired!")
            # else:
            #     kong.log.debug("JWT token is missing the 'exp' claim")

            # Get dvi code from claims of token and then use Redis to check whether device blocked
            dvi = jwt_claims.get("dvi")
            user_id = jwt_claims.get("userId", "")
            profile_id = jwt_claims.get("profileId", "")
            gname = jwt_claims.get("gname", "")
            content_filter = jwt_claims.get("contentFilter", "100")

            if not dvi:
                kong.log.err("Cant find device code!")
                kong.response.exit(500, "jwt-auth - Cant find device code from token")

            # Connect to redis cluster to get dvi code
            redis_host = self.redis_host
            redis_port = self.redis_port
            redis_db = self.redis_database
            redis_timeout = self.redis_timeout

            # Connect to Redis
            # Connect to the Redis cluster using RedisCluster client
            # startup_node = [ClusterNode('redis-cluster', 7000)]
            # r = RedisCluster(startup_nodes=startup_node)

            r = ""
            redis_data = ""
            try:
                # rc = RedisCluster(host=redis_host, port=redis_port)

                r = redis.StrictRedis(host=redis_host, port=redis_port, decode_responses=True)
                redis_data = r.get("DEVICE_BLOCKED:" + dvi)
            except ConnectionRefusedError as e:
                kong.log.err(e)
                kong.response.exit(500, "jwt-auth - ConnectionRefusedError")

            except ConnectionError as e:
                kong.log.err(e)
                kong.response.exit(500, "jwt-auth - ConnectionError")

            except redis.exceptions.RedisClusterException as e:
                kong.log.err(e)
                kong.response.exit(500, "jwt-auth - RedisClusterException")

            kong.log.debug("Connect to Redis Cluster successfully!")
            kong.log.debug(r)

            # kong.log.debug(f"RedisCluster: {r.get_nodes()}")
            # redis_data = ""
            # try:
            #     redis_data = r.get("DEVICE_BLOCKED:"+ dvi)
            # except redis.exceptions.ConnectionError as e:
            #     kong.log.err(e)
            #     kong.response.exit(500, "jwt-auth - redis.exceptions.ConnectionError")

            if redis_data:
                kong.log.debug("Hello: " + redis_data)
                kong.response.exit(403, "jwt-auth - Device is blocked")
            kong.log.debug("Device is not blocked")

            kong.response.set_header("Zone-id", zone_id)
            kong.response.set_header("User-Id", user_id)
            kong.response.set_header("Profile-Id", profile_id)
            kong.response.set_header("Content-Filter", content_filter)
            kong.response.set_header("Gname", gname)
            kong.response.set_header("dvi", dvi)
            kong.response.set_header("Network-type", network_type)
            kong.response.set_header("X-Forwarded-Request-IP", kong.client.get_forwarded_ip())
            kong.response.set_header("X-Request-IP", kong.client.get_ip())
            kong.response.set_header("Language", lang)
        else:
            kong.response.exit(500, "jwt-auth -- Can't find token")


if __name__ == "__main__":
    from kong_pdk.cli import start_dedicated_server

    start_dedicated_server("jwt-auth", Plugin, version, priority)
