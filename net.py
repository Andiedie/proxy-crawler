import logger
import math
import socket
import time
import requests
import uuid
import gevent.timeout

unavailable = 99999
no_speed = 0

log = logger.get_logger('net')
log.disabled = True


def get_free_port() -> int:
    sock = socket.socket()
    sock.bind(('', 0))
    free_port = sock.getsockname()[1]
    sock.close()
    return free_port


# returns ms
def ping(port: int, ua: str, times: int = 5) -> int:
    res = 0
    success_cnt = 0
    while times > 0:
        times -= 1
        timeout = gevent.Timeout(3)
        timeout.start()
        try:
            start = time.time() * 1000
            # noinspection HttpUrlsUsage
            resp = requests.get('http://www.google.com/generate_204',
                                proxies={'http': f'http://127.0.0.1:{port}'},
                                headers={'User-Agent': ua})
            end = time.time() * 1000
            if resp.status_code != 204:
                log.info(f'ping try {times} fail with {resp.status_code}')
                continue
            p = math.floor(end - start)
            log.info(f'ping try {times} success with {p}ms')
            res += p
            success_cnt += 1
        except (gevent.Timeout, requests.exceptions.RequestException) as e:
            log.info(f'ping try {times} fail with exception {e}')
            continue
        finally:
            timeout.close()
    if res == 0:
        return unavailable
    return math.floor(res / success_cnt)


# returns bytes/s
def speedtest(port: int, ua: str, download_bytes=1024*1024*20) -> int:
    try_times = 3
    while try_times > 0:
        try_times -= 1
        start = time.time() * 1000
        timeout = gevent.Timeout(20)
        timeout.start()
        try:
            # noinspection HttpUrlsUsage
            resp = requests.get(f'http://speed.cloudflare.com/__down?measId={uuid.uuid4()}&bytes={download_bytes}',
                                proxies={'http': f'http://127.0.0.1:{port}'},
                                headers={'User-Agent': ua})
        except (gevent.Timeout, requests.exceptions.RequestException) as e:
            log.info(f'speedtest try {try_times} fail with {e}')
            continue
        finally:
            timeout.close()

        end = time.time() * 1000
        if resp.status_code != 200:
            log.info(f'speedtest try {try_times} fail with {resp.status_code}')
            continue
        speed = math.floor(len(resp.text) / ((end - start) / 1000))
        log.info(f'speedtest try {try_times} success with {speed}bytes/s')
        return speed
    return no_speed


if __name__ == '__main__':
    log.disabled = False
    from gevent import monkey
    monkey.patch_socket()
    print(ping(1080, ''))
    print(speedtest(1080, ''))
