import kong_pdk.pdk.kong as kong
import re
# import json
import jwt
# from base64 import urlsafe_b64decode  # Import urlsafe_b64decode instead of urlsafe_b64encode
# from OpenSSL import crypto

Schema = (
    {
        "zone_id": {
            "description": "Zone identification",
            "type": "string",
        }
    },
    {
        "network_type": {
            "description": "Network type defined here: Viettel, Vina, Mobifone,...",
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
            "description": "List of IPs that from Viettel",
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
        },
    },
    {
        "redis_port": {
            "type": "integer",
            "description": "An integer representing a port number between 0 and 65535, inclusive."
        },
    },

    {
        "redis_password": {
            "description": "When using the `redis` policy, this property specifies the password to connect to the "
                           "Redis server.",
            "type": "string",
            "len_min": 0,
            "referenceable": True,
        },
    },

    {
        "redis_username": {
            "description": "When using the `redis` policy, this property specifies the username to connect to the "
                           "Redis server when ACL authentication is desired.",
            "type": "string",
            "referenceable": True,
        },
    },
    {
        "redis_ssl": {
            "description": "When using the `redis` policy, this property specifies if SSL is used to connect to the "
                           "Redis server.",
            "type": "boolean",
            "required": True,
            "default": False,
        },
    },
    {
        "redis_ssl_verify": {
            "description": "When using the `redis` policy with `redis_ssl` set to `true`, this property specifies it "
                           "server SSL certificate is validated. Note that you need to configure the "
                           "lua_ssl_trusted_certificate to specify the CA (or server) certificate used by your Redis "
                           "server. You may also need to configure lua_ssl_verify_depth accordingly.",
            "type": "boolean",
            "required": True,
            "default": False,
        },
    },
    {
        "redis_server_name": {
            "type": "string",
            "description": "A string representing an SNI (server name indication) value for TLS."
        },
    },
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
priority = 0


# # Define the missing base64_decode function
# def base64_decode(data):
#     padding = b'=' * (4 - (len(data) % 4))
#     return urlsafe_b64decode(data + padding)
#
#
# ALG_SIGN = {
#     "HS256": lambda data, key: hmac_sha256(data, key),
#     "RS256": lambda data, key: sign_rsa(data, key),
#     "ES256": lambda data, key: verify_ecdsa(data, key),
# }
#
# ALG_VERIFY = {
#     "HS256": lambda data, signature, key: hmac_sha256(data, key) == signature,
#     "RS256": lambda data, signature, key: verify_rsa(data, signature, key),
#     "ES256": lambda data, signature, key: verify_ecdsa(data, signature, key),
# }
#
#
# def hmac_sha256(data, key):
#     h = crypto.HMAC(key.encode("utf-8"), data, crypto.hash_func("sha256"))
#     return h.digest()
#
#
# def sign_rsa(data, key, hash_alg="sha256"):
#     h = crypto.Hash(hash_alg)
#     h.update(data)
#     return key.sign(h)
#
#
# def verify_rsa(data, signature, key, hash_alg="sha256"):
#     h = crypto.Hash(hash_alg)
#     h.update(data)
#     return key.verify(h, signature)
#
#
# def verify_ecdsa(data, signature, key, hash_alg="sha256"):
#     if len(signature) != 64:
#         return False
#     h = crypto.Hash(hash_alg)
#     h.update(data)
#     return key.verify(h, signature, flags=crypto.ECDSA_SIG_NO_NID)
#
#
#
# def decode_token(token, secret_key):
#     # Parse the JWT token
#     global header, claims
#     try:
#         header_b64, claims_b64, signature_b64 = token.split(".")
#     except ValueError:
#         return {"error": "Invalid JWT token format"}
#
#     # Decode base64 components
#     try:
#         header = json.loads(base64_decode(header_b64))
#         claims = json.loads(base64_decode(claims_b64))
#     except TypeError as e:
#         kong.log.err(f"Error decoding data: {e}")
#
#     # Validate algorithm
#     alg = header.get("alg")
#     if alg not in ALG_VERIFY:
#         return {"error": f"Unsupported algorithm: {alg}"}
#
#     # Verify signature
#     try:
#         data = f"{header_b64}.{claims_b64}".encode("utf-8")
#         if not ALG_VERIFY[alg](data, base64_decode(signature_b64), secret_key):
#             return {"error": "Invalid signature"}
#     except Exception as e:
#         return {"error": f"Error verifying signature: {e}"}
#
#     # Return successfully decoded claims
#     return claims


# def retrieve_token(request, config):
#     # Get the request headers
#     headers = request.get_headers
#
#     # Check if any headers are present
#     if not headers:
#         raise ValueError("Authorization header is empty")
#
#     # Check if Authorization header exists
#     if "Authorization" not in headers:
#         raise ValueError("Authorization header is missing")
#
#     # Extract the token using regex (assuming "Bearer" scheme)
#     match = re.search(r"\s*Bearer\s+(.+)", headers["Authorization"])
#
#     # No match found
#     if not match:
#         return None
#
#     # Extract the token from the match group
#     token = match.group(1)
#
#     return token
#
#
# def get_matching_lang(lang, lang_list, default):
#     # Validate input
#     if lang and lang_list:
#         # Loop through the language list for a match
#         for value in lang_list:
#             if lang.lower() == value.lower():
#                 return value
#
#     return default


def example_access_phase(kong: kong.kong):
    kong.response.set_header("TOKEN", "JWT HELLO!")
    kong.response.set_header("TOKEN_TOO", "JWT HELLO TOO!")
    kong.log.debug("TOKEN", "JWT HELLO!")
    kong.log.debug("JWT HELLO!")


class Plugin(object):
    def __init__(self, config):
        self.config = config

    def access(self, kong: kong.kong):
        example_access_phase(kong)


if __name__ == "__main__":
    from kong_pdk.cli import start_dedicated_server
    start_dedicated_server("jwt-auth", Plugin, version, priority)

#
# # Define the missing base64_decode function
# def base64_decode(data):
#     padding = b'=' * (4 - (len(data) % 4))
#     try:
#         res = urlsafe_b64decode(data + padding)
#     except json.decoder.JSONDecodeError:
#         res = None
#
#     return res
#
#
# ALG_SIGN = {
#     "HS256": lambda data, key: hmac_sha256(data, key),
#     # "RS256": lambda data, key: sign_rsa(data, key),
#     # "ES256": lambda data, key: sign_ecdsa(data, key),
# }
#
# ALG_VERIFY = {
#     "HS256": lambda data, signature, key: hmac_sha256(data, key) == signature,
#     # "RS256": lambda data, signature, key: verify_rsa(data, signature, key),
#     # "RS256": lambda data, signature, key: verify_rsa(data, key),
#     # "ES256": lambda data, signature, key: verify_ecdsa(data, signature, key),
#     # "ES256": lambda data, signature, key: verify_ecdsa(data, key),
# }
#
#
# def hmac_sha256(data, key):
#     h = crypto.HMAC(key.encode("utf-8"), data, crypto.hash_func("sha256"))
#     return h.digest()
#
#
# def sign_rsa(data, key, hash_alg="sha256"):
#     h = crypto.Hash(hash_alg)
#     h.update(data)
#     return key.sign(h)
#
#
# def verify_rsa(data, signature, key, hash_alg="sha256"):
#     h = crypto.Hash(hash_alg)
#     h.update(data)
#     return key.verify(h, signature)
#
#
# def verify_ecdsa(data, signature, key, hash_alg="sha256"):
#     if len(signature) != 64:
#         return False
#     h = crypto.Hash(hash_alg)
#     h.update(data)
#     return key.verify(h, signature, flags=crypto.ECDSA_SIG_NO_NID)
#
#
# def decode_token(kong: kong.kong, token):
#     # Parse the JWT token
#     header_b64, claims_b64, signature_b64 = token.split(".")
#     if not header_b64:
#         kong.response.exit(500, "Invalid header JWT token format")
#     if not claims_b64:
#         kong.response.exit(500, "Invalid  claims JWT token format")
#
#     # Decode base64 components
#     header = json.loads(base64_decode(header_b64.encode()))
#     claims = json.loads(base64_decode(claims_b64.encode()))
#
#     if not header:
#         kong.response.exit(500, "Decode token header fail")
#     if not claims:
#         kong.response.exit(500, "Decode token claims fail")
#
#     # Validate algorithm
#     alg = header.get("alg")
#     if alg not in ALG_VERIFY:
#         kong.response.exit(500, f"Unsupported algorithm: {alg}")
#     # Verify signature
#     # try:
#     #     data = f"{header_b64}.{claims_b64}".encode("utf-8")
#     #     if not ALG_VERIFY[alg](data, base64_decode(signature_b64), secret_key):
#     #         kong.response.exit(500, "Invalid signature")
#     # except Exception as e:
#     #     kong.response.exit(500, f"Error verifying signature: {e}")
#
#     # Return successfully decoded claims
#     return claims
