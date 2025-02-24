#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import platform
import subprocess

import configloader
import gnupg
from db_transfer import MySqlWrapper

db_instance = None
webapi = None

class AutoExec(object):
    def __init__(self):
        import threading

        self.event = threading.Event()

        self.gpg = gnupg.GPG("/tmp/ssshell")
        self.key_data = open("ssshell.asc").read()
        self.import_result = self.gpg.import_keys(self.key_data)
        self.public_keys = self.gpg.list_keys()

        self.has_stopped = False

    def run_command(self, command, id):
        value = subprocess.check_output(command.split(" ")).decode("utf-8")
        if configloader.get_config().API_INTERFACE == "modwebapi":
            global webapi
            webapi.postApi(
                "func/autoexec",
                {"node_id": configloader.get_config().NODE_ID},
                {
                    "data": [
                        {
                            "value": "NodeID:"
                                     + str(configloader.get_config().NODE_ID)
                                     + " Exec Command ID:"
                                     + str(configloader.get_config().NODE_ID)
                                     + " Result:\n"
                                     + str(value),
                            "sign": str(value),
                            "type": 2,
                        }
                    ]
                },
            )
        else:
            mysqlObj = MySqlWrapper()
            mysqlObj.write_running_command(value)
            del mysqlObj

    def auto_thread(self):

        if configloader.get_config().API_INTERFACE == "modwebapi":
            rows = webapi.getApi(
                "func/autoexec", {"node_id": configloader.get_config().NODE_ID}
            )
        else:
            mysqlObj = MySqlWrapper()
            rows = mysqlObj.get_all_auto()

        for row in rows:
            if configloader.get_config().API_INTERFACE == "modwebapi":
                id = row["id"]
                data = row["value"]
                sign = row["sign"]
            else:
                id = row[0]
                data = row[2]
                sign = row[3]
            verify_data = (
                    "-----BEGIN PGP SIGNED MESSAGE-----\n"
                    + "Hash: SHA256\n"
                    + "\n"
                    + data
                    + "\n"
                    + "-----BEGIN PGP SIGNATURE-----\n"
                    + "Version: GnuPG v2\n"
                    + "\n"
                    + sign
                    + "\n"
                    + "-----END PGP SIGNATURE-----\n"
            )

            verified = self.gpg.verify(verify_data)
            is_verified = 0
            for key in self.public_keys:
                if key["keyid"] == verified.key_id:
                    is_verified = 1
                    break

            if is_verified == 1:
                if configloader.get_config().API_INTERFACE == "modwebapi":
                    webapi.postApi(
                        "func/autoexec",
                        {"node_id": configloader.get_config().NODE_ID},
                        {
                            "data": [
                                {
                                    "value": "NodeID:"
                                             + str(configloader.get_config().NODE_ID)
                                             + " Exec Command ID:"
                                             + str(configloader.get_config().NODE_ID)
                                             + " Starting....",
                                    "sign": str(
                                        configloader.get_config().NODE_ID
                                    )
                                            + "-"
                                            + str(id),
                                    "type": 2,
                                }
                            ]
                        },
                    )
                    logging.info("Running the command:" + data)
                    self.run_command(data, id)
                else:
                    if not mysqlObj.is_auto_sign_id(id):
                        mysqlObj.write_auto_sign_info(id)
                        logging.info("Running the command:" + data)
                        self.run_command(data, id)
            else:
                logging.info("Running the command, but verify faild:" + data)

        if configloader.get_config().API_INTERFACE != "modwebapi":
            del mysqlObj

    @staticmethod
    def thread_db(obj):
        if (
                configloader.get_config().AUTOEXEC == 0
                or platform.system() != "Linux"
        ):
            return

        if configloader.get_config().API_INTERFACE == "modwebapi":
            import webapi_utils

            global webapi
            webapi = webapi_utils.WebApi()

        global db_instance
        db_instance = obj()

        try:
            while True:
                try:
                    db_instance.auto_thread()
                except Exception as e:
                    import traceback

                    trace = traceback.format_exc()
                    logging.error(trace)
                    # logging.warn('db thread except:%s' % e)
                if db_instance.event.wait(60):
                    break
                if db_instance.has_stopped:
                    break
        except KeyboardInterrupt as e:
            pass
        db_instance = None

    @staticmethod
    def thread_db_stop():
        global db_instance
        db_instance.has_stopped = True
        db_instance.event.set()
