# coding: utf-8

import time

from client import OnlyKey

def main():
    only_key = OnlyKey()

    only_key.set_time(time.time())
    only_key.close()
