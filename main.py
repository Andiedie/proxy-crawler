from gevent import monkey
import uuid
import time
import requests
import logging
import base64
import conf
import net
import parser
from typing import List
from subprocess import run, DEVNULL, Popen
import gevent.pool
from itertools import groupby
monkey.patch_socket()


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
    'https://cdn.jsdelivr.net/gh/StormragerCN/v2ray/v2ray',
    'https://cdn.jsdelivr.net/gh/eycorsican/rule-sets/kitsunebi_sub',
    'https://jiang.netlify.app'
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
        server.extra['subscribe'] = sub
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


tested_count = 0


# 测试速度
def net_test(s: parser.Server):
    global tested_count
    ping = net.ping(port, s.extra['uuid'])
    if ping == net.unavailable:
        tested_count += 1
        log.info(f'({tested_count}/{len(servers)}) {s} unavailable, subscribe: {s.extra["subscribe"]}')
        return
    download = net.speedtest(port, s.extra['uuid'])
    s.extra['ping'] = ping
    s.extra['download'] = download
    s.extra['download_human'] = '%.2fMiB/s' % (download / (1024 * 1024))
    tested_count += 1
    log.info(f'({tested_count}/{len(servers)}) {s} ping {ping}ms download {s.extra["download_human"]}')


# 使用 v2ray
p = Popen(['v2ray', '--config=%s' % conf.config_path],
          stdout=DEVNULL
          )
time.sleep(1)

pool = gevent.pool.Pool(3)
proxy = {
    'http': f'http://localhost:{port}',
}
pool.map(net_test, servers)

p.kill()


available_cnt = len([
    s for s in servers
    if s.extra.get("ping", net.unavailable) != net.unavailable and
    s.extra.get("download", net.no_speed) != net.no_speed
])
log.info(f'available server {available_cnt}/{len(servers)}')
log.info('\t\n'.join([
    '(%d / %d) %s' % (
        len([
            s for s in group
            if s.extra.get("ping", net.unavailable) != net.unavailable and
               s.extra.get("download", net.no_speed) != net.no_speed
        ]),
        len(list(group)),
        key
    )
    for key, group in
    [(key, list(group)) for key, group in groupby(servers, key=lambda x: x.extra["source"])]
]))


# 取前十
servers = sorted(servers,
                 key=lambda x: x.extra.get('download', net.no_speed) / (x.extra.get('ping', net.unavailable) / 100),
                 reverse=True)[:10]

log.info('final servers:\n\t%s' % '\n\t'.join([
    f'ping {s.extra.get("ping")}ms\tdownload {s.extra.get("download_human")}\t{s}'
    for s in servers
]))

if __name__ == '__main__':
    pass

# 生成 JSON
