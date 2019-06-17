#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import os
import platform
import socket

import fcntl

from configloader import get_config
from db_transfer import new_server
from server_pool import ServerPool
from shadowsocks import common, shell

switchrule = None
db_instance = None


def uptime():
    with open("/proc/uptime", "r") as f:
        return float(f.readline().split()[0])


def is_all_thread_alive():
    if not ServerPool.get_instance().thread.is_alive():
        return False
    return True


def new_server(port, passwd, cfg):
    protocol = cfg.get(
        "protocol",
        ServerPool.get_instance().config.get("protocol", "origin"),
    )
    method = cfg.get(
        "method", ServerPool.get_instance().config.get("method", "None")
    )
    obfs = cfg.get(
        "obfs", ServerPool.get_instance().config.get("obfs", "plain")
    )
    logging.info(
        "db start server at port [%s] pass [%s] protocol [%s] method [%s] obfs [%s]"
        % (port, passwd, protocol, method, obfs)
    )
    ServerPool.new_server(port, cfg)


def cmp(val1, val2):
    if isinstance(val1, bytes):
        val1 = common.to_str(val1)
    if isinstance(val2, bytes):
        val2 = common.to_str(val2)
    return val1 == val2


def traffic_show(traffic):
    if traffic < 1024:
        return str(round(traffic, 2)) + "B"

    if traffic < 1024 * 1024:
        return str(round((traffic / 1024), 2)) + "KB"

    if traffic < 1024 * 1024 * 1024:
        return str(round((traffic / 1024 / 1024), 2)) + "MB"

    return str(round((traffic / 1024 / 1024 / 1024), 2)) + "GB"


def load():
    import os

    return os.popen(
        'cat /proc/loadavg | awk \'{ print $1" "$2" "$3 }\''
    ).readlines()[0]


class WebTransfer(object):
    def __init__(self):
        import threading

        self.last_update_transfer = {}
        self.event = threading.Event()
        self.port_uid_table = {}
        self.uid_port_table = {}
        self.node_speedlimit = 0.00
        self.traffic_rate = 0.0

        self.detect_text_list = {}

        self.detect_hex_list = {}

        self.mu_only = False
        self.is_relay = False

        self.relay_rule_list = {}
        self.node_ip_list = []
        self.mu_port_list = []

        self.has_stopped = False

    def update_all_user(self, dt_transfer):
        global webapi

        update_transfer = {}

        data = []
        for tid in dt_transfer.keys():
            if dt_transfer[tid][0] == 0 and dt_transfer[tid][1] == 0:
                continue
            data.append(
                {
                    "u": dt_transfer[tid][0],
                    "d": dt_transfer[tid][1],
                    "user_id": self.port_uid_table[tid],
                }
            )
            update_transfer[tid] = dt_transfer[tid]
        webapi.post_api(
            "users/traffic", {"node_id": get_config().NODE_ID}, {"data": data}
        )

        webapi.post_api(
            "nodes/%d/info" % get_config().NODE_ID,
            {"node_id": get_config().NODE_ID},
            {"uptime": str(uptime()), "load": str(load())},
        )

        online_iplist = ServerPool.get_instance().get_servers_iplist()
        data = []
        for port in online_iplist.keys():
            for ip in online_iplist[port]:
                data.append({"ip": ip, "user_id": self.port_uid_table[port]})
        webapi.post_api(
            "users/aliveip", {"node_id": get_config().NODE_ID}, {"data": data}
        )

        detect_log_list = ServerPool.get_instance().get_servers_detect_log()
        data = []
        for port in detect_log_list.keys():
            for rule_id in detect_log_list[port]:
                data.append(
                    {"list_id": rule_id, "user_id": self.port_uid_table[port]}
                )
        webapi.post_api(
            "users/detectlog",
            {"node_id": get_config().NODE_ID},
            {"data": data},
        )

        deny_str = ""
        data = []
        if platform.system() == "Linux" and get_config().ANTISSATTACK == 1:
            wrong_iplist = ServerPool.get_instance().get_servers_wrong()
            server_ip = socket.gethostbyname(get_config().MYSQL_HOST)
            for tid in wrong_iplist.keys():
                for ip in wrong_iplist[tid]:
                    is_ipv6 = False
                    if common.is_ip(ip):
                        if common.is_ip(ip) == socket.AF_INET:
                            realip = ip
                        else:
                            if common.match_ipv4_address(ip) is not None:
                                realip = common.match_ipv4_address(ip)
                            else:
                                is_ipv6 = True
                                realip = ip
                    else:
                        continue

                    if str(realip).find(str(server_ip)) != -1:
                        continue

                    has_match_node = False
                    for node_ip in self.node_ip_list:
                        if str(realip).find(node_ip) != -1:
                            has_match_node = True
                            continue

                    if has_match_node:
                        continue

                    if get_config().CLOUDSAFE == 1:
                        data.append({"ip": realip})
                    else:
                        if not is_ipv6:
                            os.system(
                                "route add -host %s gw 127.0.0.1" % str(realip)
                            )
                            deny_str = deny_str + "\nALL: " + str(realip)
                        else:
                            os.system(
                                "ip -6 route add ::1/128 via %s/128"
                                % str(realip)
                            )
                            deny_str = (
                                    deny_str + "\nALL: [" + str(realip) + "]/128"
                            )

                        logging.info("Local Block ip:" + str(realip))
                if get_config().CLOUDSAFE == 0:
                    deny_file = open("/etc/hosts.deny", "a")
                    fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
                    deny_file.write(deny_str)
                    deny_file.close()
            webapi.post_api(
                "func/block_ip",
                {"node_id": get_config().NODE_ID},
                {"data": data},
            )
        return update_transfer

    def push_db_all_user(self):
        # 更新用户流量到数据库
        last_transfer = self.last_update_transfer
        curr_transfer = ServerPool.get_instance().get_servers_transfer()
        # 上次和本次的增量
        dt_transfer = {}
        for tid in curr_transfer.keys():
            if tid in last_transfer:
                if (
                        curr_transfer[tid][0]
                        + curr_transfer[tid][1]
                        - last_transfer[tid][0]
                        - last_transfer[tid][1]
                        <= 0
                ):
                    continue
                if (
                        last_transfer[tid][0] <= curr_transfer[tid][0]
                        and last_transfer[tid][1] <= curr_transfer[tid][1]
                ):
                    dt_transfer[tid] = [
                        curr_transfer[tid][0] - last_transfer[tid][0],
                        curr_transfer[tid][1] - last_transfer[tid][1],
                    ]
                else:
                    dt_transfer[tid] = [
                        curr_transfer[tid][0],
                        curr_transfer[tid][1],
                    ]
            else:
                if curr_transfer[tid][0] + curr_transfer[tid][1] <= 0:
                    continue
                dt_transfer[tid] = [curr_transfer[tid][0], curr_transfer[tid][1]]
        for tid in dt_transfer.keys():
            last = last_transfer.get(tid, [0, 0])
            last_transfer[tid] = [
                last[0] + dt_transfer[tid][0],
                last[1] + dt_transfer[tid][1],
            ]
        self.last_update_transfer = last_transfer.copy()
        self.update_all_user(dt_transfer)

    def pull_db_all_user(self):
        global webapi

        nodeinfo = webapi.get_api("nodes/%d/info" % get_config().NODE_ID)

        if not nodeinfo:
            rows = []
            return rows

        self.node_speedlimit = nodeinfo["node_speedlimit"]
        self.traffic_rate = nodeinfo["traffic_rate"]

        self.mu_only = nodeinfo["mu_only"]

        if nodeinfo["sort"] == 10:
            self.is_relay = True
        else:
            self.is_relay = False

        data = webapi.get_api("users", {"node_id": get_config().NODE_ID})

        if not data:
            rows = []
            return rows

        rows = data

        # 读取节点IP
        # SELECT * FROM `ss_node`  where `node_ip` != ''
        self.node_ip_list = []
        data = webapi.get_api("nodes")
        for node in data:
            temp_list = str(node["node_ip"]).split(",")
            self.node_ip_list.append(temp_list[0])

        # 读取审计规则,数据包匹配部分

        self.detect_text_list = {}
        self.detect_hex_list = {}
        data = webapi.get_api("func/detect_rules")
        for rule in data:
            d = {"id": int(rule["id"]), "regex": str(rule["regex"])}
            if int(rule["type"]) == 1:
                self.detect_text_list[d["id"]] = d.copy()
            else:
                self.detect_hex_list[d["id"]] = d.copy()

        # 读取中转规则，如果是中转节点的话

        if self.is_relay:
            self.relay_rule_list = {}

            data = webapi.get_api(
                "func/relay_rules", {"node_id": get_config().NODE_ID}
            )
            for rule in data:
                d = {"id": int(rule["id"]), "user_id": int(rule["user_id"]), "dist_ip": str(rule["dist_ip"]),
                     "port": int(rule["port"]), "priority": int(rule["priority"])}
                self.relay_rule_list[d["id"]] = d.copy()

        return rows

    def del_server_out_of_bound_safe(self, last_rows, rows):
        # 停止超流量的服务
        # 启动没超流量的服务
        # 需要动态载入switchrule，以便实时修改规则

        cur_servers = {}
        new_servers = {}

        md5_users = {}

        self.mu_port_list = []

        for row in rows:
            if row["is_multi_user"] != 0:
                self.mu_port_list.append(int(row["port"]))
                continue

            md5_users[row["id"]] = row.copy()
            del md5_users[row["id"]]["u"]
            del md5_users[row["id"]]["d"]
            if md5_users[row["id"]]["disconnect_ip"] is None:
                md5_users[row["id"]]["disconnect_ip"] = ""

            if md5_users[row["id"]]["forbidden_ip"] is None:
                md5_users[row["id"]]["forbidden_ip"] = ""

            if md5_users[row["id"]]["forbidden_port"] is None:
                md5_users[row["id"]]["forbidden_port"] = ""
            md5_users[row["id"]]["md5"] = common.get_md5(
                str(row["id"])
                + row["passwd"]
                + row["method"]
                + row["obfs"]
                + row["protocol"]
            )

        for row in rows:
            self.port_uid_table[row["port"]] = row["id"]
            self.uid_port_table[row["id"]] = row["port"]

        if self.mu_only == 1:
            i = 0
            while i < len(rows):
                if rows[i]["is_multi_user"] == 0:
                    rows.pop(i)
                    i -= 1
                else:
                    pass
                i += 1

        if self.mu_only == -1:
            i = 0
            while i < len(rows):
                if rows[i]["is_multi_user"] != 0:
                    rows.pop(i)
                    i -= 1
                else:
                    pass
                i += 1

        for row in rows:
            port = row["port"]
            user_id = row["id"]
            passwd = common.to_bytes(row["passwd"])
            cfg = {"password": passwd}

            read_config_keys = [
                "method",
                "obfs",
                "obfs_param",
                "protocol",
                "protocol_param",
                "forbidden_ip",
                "forbidden_port",
                "node_speedlimit",
                "disconnect_ip",
                "is_multi_user",
            ]

            for name in read_config_keys:
                if name in row and row[name]:
                    cfg[name] = row[name]

            merge_config_keys = ["password"] + read_config_keys
            for name in cfg.keys():
                if hasattr(cfg[name], "encode"):
                    pass

            if "node_speedlimit" in cfg:
                if (
                        float(self.node_speedlimit) > 0.0
                        or float(cfg["node_speedlimit"]) > 0.0
                ):
                    cfg["node_speedlimit"] = max(
                        float(self.node_speedlimit),
                        float(cfg["node_speedlimit"]),
                    )
            else:
                cfg["node_speedlimit"] = max(
                    float(self.node_speedlimit), float(0.00)
                )

            if "disconnect_ip" not in cfg:
                cfg["disconnect_ip"] = ""

            if "forbidden_ip" not in cfg:
                cfg["forbidden_ip"] = ""

            if "forbidden_port" not in cfg:
                cfg["forbidden_port"] = ""

            if "protocol_param" not in cfg:
                cfg["protocol_param"] = ""

            if "obfs_param" not in cfg:
                cfg["obfs_param"] = ""

            if "is_multi_user" not in cfg:
                cfg["is_multi_user"] = 0

            if port not in cur_servers:
                cur_servers[port] = passwd
            else:
                logging.error(
                    "more than one user use the same port [%s]" % (port,)
                )
                continue

            if cfg["is_multi_user"] != 0:
                cfg["users_table"] = md5_users.copy()

            cfg["detect_hex_list"] = self.detect_hex_list.copy()
            cfg["detect_text_list"] = self.detect_text_list.copy()

            if self.is_relay and row["is_multi_user"] != 2:
                temp_relay_rules = {}
                for id in self.relay_rule_list:
                    if (
                            (
                                    self.relay_rule_list[id]["user_id"] == user_id
                                    or self.relay_rule_list[id]["user_id"] == 0
                            )
                            or row["is_multi_user"] != 0
                    ) and (
                            self.relay_rule_list[id]["port"] == 0
                            or self.relay_rule_list[id]["port"] == port
                    ):
                        has_higher_priority = False
                        for priority_id in self.relay_rule_list:
                            if (
                                    (
                                            (
                                                    self.relay_rule_list[priority_id][
                                                        "priority"
                                                    ]
                                                    > self.relay_rule_list[id]["priority"]
                                                    and self.relay_rule_list[id]["id"]
                                                    != self.relay_rule_list[priority_id][
                                                        "id"
                                                    ]
                                            )
                                            or (
                                                    self.relay_rule_list[priority_id][
                                                        "priority"
                                                    ]
                                                    == self.relay_rule_list[id]["priority"]
                                                    and self.relay_rule_list[id]["id"]
                                                    > self.relay_rule_list[priority_id][
                                                        "id"
                                                    ]
                                            )
                                    )
                                    and (
                                    self.relay_rule_list[priority_id][
                                        "user_id"
                                    ]
                                    == user_id
                                    or self.relay_rule_list[priority_id][
                                        "user_id"
                                    ]
                                    == 0
                            )
                                    and (
                                    self.relay_rule_list[priority_id]["port"]
                                    == port
                                    or self.relay_rule_list[priority_id][
                                        "port"
                                    ]
                                    == 0
                            )
                            ):
                                has_higher_priority = True
                                continue

                        if has_higher_priority:
                            continue

                        if (
                                self.relay_rule_list[id]["dist_ip"] == "0.0.0.0"
                                and row["is_multi_user"] == 0
                        ):
                            continue

                        temp_relay_rules[id] = self.relay_rule_list[id]

                cfg["relay_rules"] = temp_relay_rules.copy()
            else:
                temp_relay_rules = {}

                cfg["relay_rules"] = temp_relay_rules.copy()

            if ServerPool.get_instance().server_is_run(port) > 0:
                cfgchange = False

                if port in ServerPool.get_instance().tcp_servers_pool:
                    ServerPool.get_instance().tcp_servers_pool[
                        port
                    ].modify_detect_text_list(self.detect_text_list)
                    ServerPool.get_instance().tcp_servers_pool[
                        port
                    ].modify_detect_hex_list(self.detect_hex_list)
                if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                    ServerPool.get_instance().tcp_ipv6_servers_pool[
                        port
                    ].modify_detect_text_list(self.detect_text_list)
                    ServerPool.get_instance().tcp_ipv6_servers_pool[
                        port
                    ].modify_detect_hex_list(self.detect_hex_list)
                if port in ServerPool.get_instance().udp_servers_pool:
                    ServerPool.get_instance().udp_servers_pool[
                        port
                    ].modify_detect_text_list(self.detect_text_list)
                    ServerPool.get_instance().udp_servers_pool[
                        port
                    ].modify_detect_hex_list(self.detect_hex_list)
                if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                    ServerPool.get_instance().udp_ipv6_servers_pool[
                        port
                    ].modify_detect_text_list(self.detect_text_list)
                    ServerPool.get_instance().udp_ipv6_servers_pool[
                        port
                    ].modify_detect_hex_list(self.detect_hex_list)

                if row["is_multi_user"] != 0:
                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[
                            port
                        ].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[
                            port
                        ].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[
                            port
                        ].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[
                            port
                        ].modify_multi_user_table(md5_users)

                if self.is_relay and row["is_multi_user"] != 2:
                    temp_relay_rules = {}
                    for id in self.relay_rule_list:
                        if (
                                (
                                        self.relay_rule_list[id]["user_id"] == user_id
                                        or self.relay_rule_list[id]["user_id"] == 0
                                )
                                or row["is_multi_user"] != 0
                        ) and (
                                self.relay_rule_list[id]["port"] == 0
                                or self.relay_rule_list[id]["port"] == port
                        ):
                            has_higher_priority = False
                            for priority_id in self.relay_rule_list:
                                if (
                                        (
                                                (
                                                        self.relay_rule_list[priority_id][
                                                            "priority"
                                                        ]
                                                        > self.relay_rule_list[id][
                                                            "priority"
                                                        ]
                                                        and self.relay_rule_list[id]["id"]
                                                        != self.relay_rule_list[
                                                            priority_id
                                                        ]["id"]
                                                )
                                                or (
                                                        self.relay_rule_list[priority_id][
                                                            "priority"
                                                        ]
                                                        == self.relay_rule_list[id][
                                                            "priority"
                                                        ]
                                                        and self.relay_rule_list[id]["id"]
                                                        > self.relay_rule_list[
                                                            priority_id
                                                        ]["id"]
                                                )
                                        )
                                        and (
                                        self.relay_rule_list[priority_id][
                                            "user_id"
                                        ]
                                        == user_id
                                        or self.relay_rule_list[priority_id][
                                            "user_id"
                                        ]
                                        == 0
                                )
                                        and (
                                        self.relay_rule_list[priority_id][
                                            "port"
                                        ]
                                        == port
                                        or self.relay_rule_list[priority_id][
                                            "port"
                                        ]
                                        == 0
                                )
                                ):
                                    has_higher_priority = True
                                    continue

                            if has_higher_priority:
                                continue

                            if (
                                    self.relay_rule_list[id]["dist_ip"]
                                    == "0.0.0.0"
                                    and row["is_multi_user"] == 0
                            ):
                                continue

                            temp_relay_rules[id] = self.relay_rule_list[id]

                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[
                            port
                        ].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[
                            port
                        ].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[
                            port
                        ].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[
                            port
                        ].push_relay_rules(temp_relay_rules)

                else:
                    temp_relay_rules = {}

                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[
                            port
                        ].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[
                            port
                        ].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[
                            port
                        ].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[
                            port
                        ].push_relay_rules(temp_relay_rules)

                if port in ServerPool.get_instance().tcp_servers_pool:
                    relay = ServerPool.get_instance().tcp_servers_pool[port]
                    for name in merge_config_keys:
                        if name in cfg and not cmp(
                                cfg[name], relay._config[name]
                        ):
                            cfgchange = True
                            break
                if (
                        not cfgchange
                        and port in ServerPool.get_instance().tcp_ipv6_servers_pool
                ):
                    relay = ServerPool.get_instance().tcp_ipv6_servers_pool[
                        port
                    ]
                    for name in merge_config_keys:
                        if name in cfg and not cmp(
                                cfg[name], relay._config[name]
                        ):
                            cfgchange = True
                            break
                # config changed
                if cfgchange:
                    self.del_server(port, "config changed")
                    new_servers[port] = (passwd, cfg)
            elif ServerPool.get_instance().server_run_status(port) is False:
                # new_servers[port] = passwd
                new_server(port, passwd, cfg)

        for row in last_rows:
            if row["port"] in cur_servers:
                pass
            else:
                self.del_server(row["port"], "port not exist")

        if len(new_servers) > 0:
            from shadowsocks import eventloop

            self.event.wait(
                eventloop.TIMEOUT_PRECISION + eventloop.TIMEOUT_PRECISION / 2
            )
            for port in new_servers.keys():
                passwd, cfg = new_servers[port]
                new_server(port, passwd, cfg)

        ServerPool.get_instance().push_uid_port_table(self.uid_port_table)

    def del_server(self, port, reason):
        logging.info(
            "db stop server at port [%s] reason: %s!" % (port, reason)
        )
        ServerPool.get_instance().cb_del_server(port)
        if port in self.last_update_transfer:
            del self.last_update_transfer[port]

        for mu_user_port in self.mu_port_list:
            if mu_user_port in ServerPool.get_instance().tcp_servers_pool:
                ServerPool.get_instance().tcp_servers_pool[
                    mu_user_port
                ].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                ServerPool.get_instance().tcp_ipv6_servers_pool[
                    mu_user_port
                ].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().udp_servers_pool:
                ServerPool.get_instance().udp_servers_pool[
                    mu_user_port
                ].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().udp_ipv6_servers_pool:
                ServerPool.get_instance().udp_ipv6_servers_pool[
                    mu_user_port
                ].reset_single_multi_user_traffic(self.port_uid_table[port])

    @staticmethod
    def del_servers():
        global db_instance
        for port in [
            v for v in ServerPool.get_instance().tcp_servers_pool.keys()
        ]:
            if ServerPool.get_instance().server_is_run(port) > 0:
                ServerPool.get_instance().cb_del_server(port)
                if port in db_instance.last_update_transfer:
                    del db_instance.last_update_transfer[port]
        for port in [
            v for v in ServerPool.get_instance().tcp_ipv6_servers_pool.keys()
        ]:
            if ServerPool.get_instance().server_is_run(port) > 0:
                ServerPool.get_instance().cb_del_server(port)
                if port in db_instance.last_update_transfer:
                    del db_instance.last_update_transfer[port]

    @staticmethod
    def thread_db(obj):
        import socket
        import webapi_utils

        global db_instance
        global webapi
        timeout = 60
        socket.setdefaulttimeout(timeout)
        db_instance = obj()
        webapi = webapi_utils.WebApi()

        shell.log_shadowsocks_version()
        try:
            import resource

            logging.info(
                "current process RLIMIT_NOFILE resource: soft %d hard %d"
                % resource.getrlimit(resource.RLIMIT_NOFILE)
            )
        except:
            pass
        db_instance.del_servers()
        ServerPool.get_instance().stop()
        db_instance = None

    @staticmethod
    def thread_db_stop():
        global db_instance
        db_instance.has_stopped = True
        db_instance.event.set()
