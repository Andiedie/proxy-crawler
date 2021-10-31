import time
import uuid
import requests
import logging
import base64
import conf
import net
import parser
from typing import List
from subprocess import run, DEVNULL, Popen

log = logging.getLogger('proxy-crawler')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s:\n\t%(message)s',
                                  '%Y-%m-%d %H:%M:%S'))
log.addHandler(ch)

assert run(['which', 'v2ray'], stdout=DEVNULL).returncode == 0, 'v2ray is not installed.'

sources = [
    'https://cdn.jsdelivr.net/gh/freefq/free/v2',
    # 'https://cdn.jsdelivr.net/gh/StormragerCN/v2ray/v2ray',
    # 'https://cdn.jsdelivr.net/gh/eycorsican/rule-sets/kitsunebi_sub',
    # 'https://cdn.jsdelivr.net/gh/umelabs/node.umelabs.dev/Subscribe/v2ray.md',
    # 'https://youlianboshi.netlify.app',
    # 'https://jiang.netlify.app'
]

servers: List[parser.Server] = []
# 爬取节点
for link in sources:
    log.info('fetching servers from %s', link)
    resp = requests.get(link)
    if resp.status_code != 200:
        log.warning('%s requests fail with code %d', link, resp.status_code)
        continue
    subscriptions = base64.b64decode(resp.text).decode()
    for sub in subscriptions.splitlines():
        sub = sub.strip()
        if sub == '':
            continue
        # log.debug(sub)
        server = parser.parse(sub)
        server.extra['source'] = link
        server.extra['uuid'] = uuid.uuid4().hex
        # log.debug(server)
        servers.append(server)

log.info('servers: %d', len(servers))

# 节点去重
dedup_map = {}
dedup_servers = []
for server in servers:
    if server.port == 0 or hash(server) in dedup_map:
        continue
    dedup_map[hash(server)] = True
    dedup_servers.append(server)

servers = dedup_servers

log.info('dedup servers: %d', len(servers))

port = net.get_free_port()
log.info('using port %d', port)

log.info('config path %s', conf.config_path)
conf.gen_test_conf(port, servers)

# 使用 v2ray
# 测试速度
p = Popen(['v2ray', '--config=%s' % conf.config_path], stdout=DEVNULL)
time.sleep(2)

proxy = {
    'http': f'http://localhost:{port}',
}
for server in servers:
    ping = net.ping(port, server.extra['uuid'])
    if ping == net.unavailable:
        log.info(f'{server} unavailable')
        continue

    speed = net.speedtest(port, server.extra['uuid'])
    log.info(f'{server} ping {ping}ms download %.2fMiB/s', speed / (1024 * 1024))
    server.extra['ping'] = ping
    server.extra['download'] = speed

p.kill()

# 取前十
servers = sorted(servers,
                 key=lambda x: x.extra.get('download', net.no_speed) / x.extra.get('ping', net.unavailable),
                 reverse=True)[:10]

print(servers)

if __name__ == '__main__':
    pass

# 生成 JSON
