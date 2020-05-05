import base64
from hashlib import sha256
import hmac
import json
import time

def base64urlencode(arg):
    stripped = arg.split("=")[0]
    filtered = stripped.replace("+", "-").replace("/", "_")
    return filtered

def base64urldecode(arg):
    filtered = arg.replace("-", "+").replace("_", "/")
    padded = filtered + "=" * ((len(filtered) * -1) % 4)
    return padded

def JWT_encode(sub, u_username, u_uuid, exp, key, isurlsafe=True):
    head = base64.b64encode('{alg": "HS256","typ": "JWT"}'.encode())# 钦定的头
    u_time = int(time.time()*1000)
    data = {
        'sub': 'user token',
        'iss': sub,
        'aud': u_username,
        'uuid': u_uuid,
        'iat': u_time,
        'exp': u_time + exp * 1000
    }
    _payload = json.dumps(data)
    payload = base64.b64encode(_payload.encode())
    msg = f'{head.decode()}.{payload.decode()}'.encode()
    sig = base64.b64encode(hmac.new(key.encode(), msg, digestmod=sha256).digest())
    if isurlsafe:
        head = base64urlencode(head.decode())
        payload = base64urlencode(payload.decode())
        sig = base64urlencode(sig.decode())
        return f'{head}.{payload}.{sig}'
    else:
        return f'{head.decode()}.{payload.decode()}.{sig.decode()}'

def JWT_decode(token, key, isurlsafe=True):
    msg = token.split('.')
    u_time = int(time.time() * 1000)
    if isurlsafe:
        head = base64.b64decode(base64urldecode(msg[0])).decode()
        _payload = base64.b64decode(base64urldecode(msg[1])).decode()
    else:
        head = base64.b64decode(msg[0]).decode()
        _payload = base64.b64decode(msg[1]).decode()
    _msg = f'{base64.b64encode(head.encode()).decode()}.{base64.b64encode(_payload.encode()).decode()}'.encode()
    sig = base64.b64encode(hmac.new(key.encode(), _msg, digestmod=sha256).digest()).decode()
    _sig = base64urldecode(msg[2])
    payload = json.loads(_payload)
    if _sig == sig:
        if 'exp' in payload:
            if payload['exp'] >= u_time:
                return True, payload
            else:
                return False, '过期令牌'
        else:
            return False, '无效令牌'
    else:
        return False, '冒牌货'


if __name__ == '__main__':
    token = JWT_encode('','1111','1111',1,'asdasdasd')
    time.sleep(0)
    print(JWT_decode(token, 'asdasdasd'))