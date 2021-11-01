import logging


def get_logger(name: str):
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s:\n\t%(message)s',
                                      '%Y-%m-%d %H:%M:%S'))
    log.addHandler(ch)
    return log
