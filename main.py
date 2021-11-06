import uuid
import time
import requests
import base64
import conf
import net
from v2ray import Server, parse
from typing import List
from subprocess import run, DEVNULL, Popen
import gevent.pool
from itertools import groupby
import logger
from gevent import monkey

monkey.patch_socket()

log = logger.get_logger('proxy-crawler')

assert run(['v2ray', '--version'], stdout=DEVNULL).returncode == 0, 'v2ray is not installed.'

sources = [
    'https://jiang.netlify.app',
    'https://cdn.jsdelivr.net/gh/freefq/free/v2',
]

servers: List[Server] = []
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
        server = parse(sub)
        if server is None:
            log.warning(f'unsupported subscribe {sub}')
            continue
        server.extra['source'] = link
        server.extra['subscribe'] = sub
        server.extra['uuid'] = uuid.uuid4().hex
        servers.append(server)
        # print(server, server.extra)

log.info('servers: %d', len(servers))

# 节点去重
dedup_map = {}
dedup_servers = []
for server in servers:
    if server.port == 0 or hash(server) in dedup_map:
        # print('duplicated', server, server.extra)
        continue
    dedup_map[hash(server)] = True
    dedup_servers.append(server)

servers = dedup_servers

log.info('dedup servers: %d', len(servers))

port = net.get_free_port()
log.info('using port %d', port)

log.info('test config path %s', conf.test_config_path)
conf.gen_test_conf(port, servers)

tested_count = 0


# 测试速度
def net_test(s: Server):
    global tested_count
    # log.debug(f'{s} start ping')
    ping = net.ping(port, s.extra['uuid'])
    if ping == net.unavailable:
        tested_count += 1
        log.info(f'({tested_count}/{len(servers)}) {s} unavailable, subscribe: {s.extra["subscribe"]}')
        return
    # log.debug(f'{s} start speedtest')
    download = net.speedtest(port, s.extra['uuid'])
    s.extra['ping'] = ping
    s.extra['download'] = download
    s.extra['download_human'] = '%.2fMiB/s' % (download / (1024 * 1024))
    tested_count += 1
    log.info(f'({tested_count}/{len(servers)}) {s} ping {ping}ms download {s.extra["download_human"]}')


# 使用 v2ray
p = Popen(['v2ray', '--config=%s' % conf.test_config_path],
          stdout=DEVNULL
          )
time.sleep(1)

pool = gevent.pool.Pool(5)
pool.map(net_test, servers)

p.kill()

available_cnt = len([
    s for s in servers
    if s.extra.get("ping", net.unavailable) != net.unavailable
    and s.extra.get("download", net.no_speed) != net.no_speed
])
log.info(f'available server {available_cnt}/{len(servers)}')
log.info('\n\t'.join([
    '(%d/%d) %s' % (
        len([
            s for s in group
            if s.extra.get("ping", net.unavailable) != net.unavailable
            and s.extra.get("download", net.no_speed) != net.no_speed
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

# 生成 JSON
log.info('gen outbound configs in path %s', conf.real_config_path)
conf.gen_conf(servers)

if __name__ == '__main__':
    pass
