#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 breakwall
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import os
import threading

if __name__ == "__main__":
    import inspect

    os.chdir(
        os.path.dirname(
            os.path.realpath(inspect.getfile(inspect.currentframe()))
        )
    )

import db_transfer
import web_transfer
import speedtest_thread
import auto_thread
import auto_block
from shadowsocks import shell
from configloader import get_config


class MainThread(threading.Thread):
    def __init__(self, obj):
        threading.Thread.__init__(self)
        self.obj = obj

    def run(self):
        self.obj.thread_db(self.obj)

    def stop(self):
        self.obj.thread_db_stop()


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)-s: %(message)s"
    )

    shell.check_python()

    if get_config().API_INTERFACE == "modwebapi":
        thread_main = MainThread(web_transfer.WebTransfer)
    else:
        thread_main = MainThread(db_transfer.DbTransfer)
    thread_main.start()

    thread_speedtest = MainThread(speedtest_thread.Speedtest)
    thread_speedtest.start()

    thread_autoexec = MainThread(auto_thread.AutoExec)
    thread_autoexec.start()

    thread_autoblock = MainThread(auto_block.AutoBlock)
    thread_autoblock.start()


if __name__ == "__main__":
    main()
