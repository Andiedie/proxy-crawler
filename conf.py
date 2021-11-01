import pathlib
from parser import Server
from typing import List
import json

config_path = pathlib.Path(__file__).parent.joinpath('v2ray_config.json').resolve()


def gen_test_conf(port: int, servers: List[Server]):
    config = {
        # 'log': {
        #     'access': '',
        #     'error': ''
        # },
        'inbounds': [{
            'port': port,
            'listen': '127.0.0.1',
            'protocol': 'http'
        }],
        'outbounds': [
            server.to_config_obj(server.extra['uuid'])
            # print(server.extra)
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

    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
