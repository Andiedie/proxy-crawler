import math
import socket
import time
import requests
import uuid

unavailable = 99999
no_speed = 0


def get_free_port() -> int:
    sock = socket.socket()
    sock.bind(('', 0))
    free_port = sock.getsockname()[1]
    sock.close()
    return free_port


# returns ms
def ping(port: int, ua: str, times: int = 5) -> int:
    res = 0
    cnt = 0
    while cnt < times:
        cnt += 1
        try:
            start = time.time() * 1000
            # noinspection HttpUrlsUsage
            resp = requests.get('http://www.google.com/generate_204',
                                proxies={'http': f'http://127.0.0.1:{port}'},
                                headers={'User-Agent': ua},
                                timeout=3)
            end = time.time() * 1000
            if resp.status_code != 204:
                return unavailable
            res += math.floor(end - start)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout, requests.exceptions.Timeout) as e:
            return unavailable
    return math.floor(res / times)


# returns bytes/s
def speedtest(port: int, ua: str, download_bytes=1024*1024*30) -> int:
    start = time.time() * 1000
    resp = requests.get(f'http://speed.cloudflare.com/__down?measId={uuid.uuid4()}&bytes={download_bytes}',
                        proxies={'http': f'http://127.0.0.1:{port}'},
                        headers={'User-Agent': ua})
    end = time.time() * 1000
    if resp.status_code != 200:
        return no_speed
    return math.floor(len(resp.text) / ((end - start) / 1000))
