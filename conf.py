import os
import pathlib
from v2ray import Server
from typing import List
import json
import shutil

test_config_path = pathlib.Path(__file__).parent.joinpath('v2ray_config.json').resolve()
real_config_path = pathlib.Path(os.environ.get('V2RAY_CONFIG_PATH', '.')).joinpath('outbounds')


def gen_test_conf(port: int, servers: List[Server]):
    config = {
        'inbounds': [{
            'port': port,
            'listen': '127.0.0.1',
            'protocol': 'http'
        }],
        'outbounds': [
            server.to_config_obj(server.extra['uuid'])
            for server in servers
        ],
        'routing': {
            'rules': [
                {
                    'type': 'field',
                    'attrs': f"'{server.extra['uuid']}' in attrs['user-agent']",
                    'outboundTag': server.extra['uuid']
                }
                for server in servers
            ]
        }
    }

    with open(test_config_path, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def gen_conf(servers: List[Server]):
    shutil.rmtree(real_config_path, ignore_errors=True)
    real_config_path.mkdir(parents=True, exist_ok=True)
    for server in servers:
        config = {
            'outbounds': [server.to_config_obj(f'proxy-{server.extra["uuid"]}')]
        }

        with open(real_config_path.joinpath(f'{server.extra["uuid"]}_tail.json').resolve(), 'w') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
