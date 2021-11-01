import base64
import json
from strenum import StrEnum
from urllib.parse import urlparse, unquote, parse_qs
import re


class ServerType(StrEnum):
    vmess = 'vmess'
    shadowsocks = 'shadowsocks'
    trojan = 'trojan'


class Server:
    type: ServerType
    remark: str
    address: str
    port: int
    extra: dict

    # for vmess
    vmess_user_id: str
    vmess_user_alter_id: int
    vmess_user_security: str

    stream_settings_network: str
    stream_settings_security: str

    ws_settings_path: str
    ws_settings_host: str

    tls_settings_allow_insecure: bool
    tls_settings_server_name: str

    mux_enable: bool
    mux_concurrency: int

    # for ss
    ss_method: str
    ss_password: str

    # for trojan
    trojan_password: str

    def __init__(self):
        self.extra = {}

    def to_config_obj(self, tag: str):
        if self.type == ServerType.vmess:
            obj = {
                'tag': tag,
                'protocol': 'vmess',
                'settings': {
                    'vnext': [{
                        'address': self.address,
                        'port': self.port,
                        'users': [{
                            'id': self.vmess_user_id,
                            'alterId': self.vmess_user_alter_id,
                            'security': self.vmess_user_security
                        }]
                    }]
                },
                'streamSettings': {
                    'network': self.stream_settings_network,
                    'security': self.stream_settings_security,
                    'tlsSettings': {
                        'allowInsecure': self.tls_settings_allow_insecure,
                        'serverName': self.tls_settings_server_name
                    }
                },
                'mux': {
                    'enabled': self.mux_enable,
                    'concurrency': self.mux_concurrency
                }
            }
            if self.stream_settings_network == 'ws':
                obj['streamSettings']['wsSettings'] = {}
                if self.ws_settings_path != '':
                    obj['streamSettings']['wsSettings']['path'] = self.ws_settings_path
                if self.ws_settings_host != '':
                    obj['streamSettings']['wsSettings']['headers'] = {
                        'Host': self.ws_settings_host
                    }
            return obj
        if self.type == ServerType.shadowsocks:
            return {
                'tag': tag,
                'protocol': 'shadowsocks',
                'settings': {
                    'servers': [{
                        'address': self.address,
                        'port': self.port,
                        'method': self.ss_method,
                        'password': self.ss_password
                    }]
                }
            }
        if self.type == ServerType.trojan:
            return {
                'tag': tag,
                'protocol': 'trojan',
                'settings': {
                    'servers': [{
                        'address': self.address,
                        'port': self.port,
                        'password': self.trojan_password
                    }]
                }
            }

    def __str__(self):
        return '{remark}({address}:{port})'.format(
            remark=self.remark,
            address=self.address,
            port=self.port
        )

    def __hash__(self):
        return hash(json.dumps({
            'type': self.type,
            'address': self.address,
            'port': self.port,
            'vmess_id': self.vmess_user_id if self.type == 'vmess' else ''
        }))


vmess_protocol = 'vmess://'
shadowsocks_protocol = 'ss://'
trojan_protocol = 'trojan://'


def b64decode(v: str) -> str:
    return base64.b64decode(v.encode()).decode()


def qs_get(d: dict, v: str, default='') -> str:
    return d.get(v, [default])[0]


def vmess1(v: str) -> Server:
    v = v[len(vmess_protocol):]
    obj: dict = json.loads(b64decode(v))

    s = Server()
    s.type = ServerType.vmess
    s.remark = obj.get('ps', '')
    s.address = obj.get('add', '')
    s.port = int(obj.get('port', '0'))

    s.vmess_user_id = obj.get('id', '')
    s.vmess_user_alter_id = int(obj.get('aid', '0'))
    s.vmess_user_security = obj.get('scy', 'none')

    s.stream_settings_network = obj.get('net', 'tcp')
    s.stream_settings_security = obj.get('tls', 'none')

    s.ws_settings_path = obj.get('path', '')
    s.ws_settings_host = obj.get('host', '')

    s.tls_settings_allow_insecure = False
    s.tls_settings_server_name = obj.get('sni', '')

    s.mux_enable = False
    s.mux_concurrency = 8

    return s


def vmess2(v: str) -> Server:
    parsed = urlparse(v)
    detail = b64decode(parsed.netloc)
    qs = parse_qs(parsed.query)
    match = re.match(r'^(?P<method>.+):(?P<id>.+)@(?P<host>.+):(?P<port>.+)$', detail)

    s = Server()
    s.type = ServerType.vmess
    s.remark = qs_get(qs, 'remark')
    s.address = match.group('host')
    s.port = int(match.group('port'))

    s.vmess_user_id = match.group('id')
    s.vmess_user_alter_id = int(qs_get(qs, 'aid', '0'))
    s.vmess_user_security = match.group('method')

    s.stream_settings_network = qs_get(qs, 'network')
    s.stream_settings_security = 'tls' if qs_get(qs, 'tls', '0') == '1' else 'none'

    s.ws_settings_path = qs_get(qs, 'path')
    s.ws_settings_host = ''

    s.tls_settings_allow_insecure = qs_get(qs, 'allowInsecure', '0') == '1'
    s.tls_settings_server_name = ''

    s.mux_enable = qs_get(qs, 'mux', '0') == '1'
    s.mux_concurrency = int(qs_get(qs, 'muxConcurrency', '8'))

    return s


def shadowsocks1(v: str) -> Server:
    parsed = urlparse(v, allow_fragments=True)
    b64 = parsed.username
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    detail = b64decode(b64)

    s = Server()
    s.type = ServerType.shadowsocks
    s.remark = unquote(parsed.fragment)
    s.address = parsed.hostname
    s.port = int(parsed.port)

    s.ss_method = detail.split(':')[0]
    s.ss_password = detail.split(':')[1]

    return s


def shadowsocks2(v: str) -> Server:
    parsed = urlparse(v, allow_fragments=True)
    detail = b64decode(parsed.netloc)
    match = re.match(r'^(?P<method>.+):(?P<pwd>.+)@(?P<host>.+):(?P<port>.+)$', detail)

    s = Server()
    s.type = ServerType.shadowsocks
    s.remark = unquote(parsed.fragment)
    s.address = match.group('host')
    s.port = int(match.group('port'))

    s.ss_method = match.group('method')
    s.ss_password = match.group('pwd')

    return s


def trojan(v: str) -> Server:
    parsed = urlparse(v, allow_fragments=True)

    s = Server()
    s.type = ServerType.trojan
    s.remark = unquote(parsed.fragment)
    s.address = parsed.hostname
    s.port = int(parsed.port)

    s.trojan_password = parsed.username

    return s


def parse(v: str) -> Server:
    if v.startswith(vmess_protocol) and '?' not in v:
        return vmess1(v)
    if v.startswith(vmess_protocol) and '?' in v:
        return vmess2(v)
    if v.startswith(shadowsocks_protocol) and '@' in v:
        return shadowsocks1(v)
    if v.startswith(shadowsocks_protocol) and '@' not in v:
        return shadowsocks2(v)
    if v.startswith(trojan_protocol):
        return trojan(v)


if __name__ == '__main__':
    print(vmess1(
        'vmess://eyJ2IjogIjIiLCAicHMiOiAiZ2l0aHViLmNvbS9mcmVlZnEgLSBcdTRmYzRcdTdmNTdcdTY1YWYgIDE0IiwgImFkZCI6ICJ2Mi5zc3JzdWIuY29tIiwgInBvcnQiOiAiMTU4IiwgImlkIjogIjZkNmQ5OWIwLWJlOGEtNDNiYy1hZDczLTJmYjBmMTU5NTc5MyIsICJhaWQiOiAiMCIsICJzY3kiOiAiYXV0byIsICJuZXQiOiAid3MiLCAidHlwZSI6ICJub25lIiwgImhvc3QiOiAiIiwgInBhdGgiOiAiL3NzcnN1YiIsICJ0bHMiOiAidGxzIiwgInNuaSI6ICIifQ=='))
    print(vmess2(
        'vmess://Y2hhY2hhMjAtcG9seTEzMDU6OTUxMzc4NTctNzBmYS00YWM4LThmOTAtNDIyMGFlYjY2MmNmQHVuaS5raXRzdW5lYmkuZnVuOjQ0NA==?network=kcp&uplinkCapacity=1&downlinkCapacity=4&aid=0&tls=0&allowInsecure=1&mux=1&muxConcurrency=8&remark=KCP%20Test%20Outbound'))
    print(shadowsocks1(
        'ss://YWVzLTI1Ni1nY206Rm9PaUdsa0FBOXlQRUdQ@167.88.63.60:7306#github.com/freefq%20-%20%E7%91%9E%E5%85%B8%20%2013'))
    print(shadowsocks2(
        'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpZYXp1WjJaRTlwNVJuM0NBTktsRDZTcUMwT1RTeVhCSVJleXBhY0Q0RmFlOGd4ODdsT0QzU1kzM2pGQXdDeEAxNTQuMTcuMi41NDoxODMzMw==#%f0%9f%87%ba%f0%9f%87%b8US_49'))
    print(trojan(
        'trojan://5b092e88-82d8-47eb-a7a2-98bcf02754e9@t4.ssrsub.com:8443#github.com/freefq%20-%20%E4%BF%84%E7%BD%97%E6%96%AF%20%2020'))
    print(shadowsocks1('ss://YWVzLTI1Ni1nY206YTc4MTcyYjM@1.fbplay.net:10100#%E9%9F%A9%E5%9B%BD-4.45MB/s'))
