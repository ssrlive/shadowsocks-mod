#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
import os
import socket
from server_pool import ServerPool
import traceback
from shadowsocks import common, shell, lru_cache
from configloader import load_config, get_config
import importloader
import platform
import datetime
import fcntl
from auto_block import hosts_deny_file_path
import cymysql


switchrule = None
db_instance = None


class DbTransfer(object):

    def __init__(self):
        reload(sys)
        sys.setdefaultencoding('utf-8')
        import threading
        self.last_update_transfer = {}
        self.event = threading.Event()
        self.port_uid_table = {}
        self.uid_port_table = {}
        self.node_speedlimit = 0.00
        self.traffic_rate = 0.0

        self.detect_text_list = {}
        self.detect_text_ischanged = False

        self.detect_hex_list = {}
        self.detect_hex_ischanged = False
        self.mu_only = False
        self.is_relay = False

        self.relay_rule_list = {}
        self.node_ip_list = []
        self.mu_port_list = []

        self.has_stopped = False

    def __del__(self):
        pass

    def update_all_user(self, dt_transfer):
        update_transfer = {}

        query_sub_when = ''
        query_sub_when2 = ''
        query_sub_in = None

        alive_user_count = 0
        bandwidth_thistime = 0

        mysqlObj = MySqlWrapper()

        for id in dt_transfer.keys():
            if dt_transfer[id][0] == 0 and dt_transfer[id][1] == 0:
                continue

            query_sub_when += ' WHEN %s THEN u+%s' % (
                id, dt_transfer[id][0] * self.traffic_rate)
            query_sub_when2 += ' WHEN %s THEN d+%s' % (
                id, dt_transfer[id][1] * self.traffic_rate)
            update_transfer[id] = dt_transfer[id]

            alive_user_count = alive_user_count + 1

            traffic = self.trafficShow((dt_transfer[id][0] + dt_transfer[id][1]) * self.traffic_rate)

            mysqlObj.add_user_traffic_log(self.port_uid_table[id], 
                dt_transfer[id][0], dt_transfer[id][1], self.traffic_rate, traffic)

            bandwidth_thistime = bandwidth_thistime + \
                (dt_transfer[id][0] + dt_transfer[id][1])

            if query_sub_in is not None:
                query_sub_in += ',%s' % id
            else:
                query_sub_in = '%s' % id
        if query_sub_when != '':
            query_sql = 'UPDATE user SET u = CASE port' + query_sub_when + \
                ' END, d = CASE port' + query_sub_when2 + \
                ' END, t = unix_timestamp() ' + \
                ' WHERE port IN (%s)' % query_sub_in
            mysqlObj.execute_query(query_sql, False)

        mysqlObj.update_node_heartbeat(bandwidth_thistime)

        mysqlObj.add_alive_user_count(alive_user_count)

        mysqlObj.add_node_networking_info(self.uptime(), self.load())

        online_iplist = ServerPool.get_instance().get_servers_iplist()
        for id in online_iplist.keys():
            for ip in online_iplist[id]:
                mysqlObj.add_alive_ip_info(self.port_uid_table[id], ip)

        detect_log_list = ServerPool.get_instance().get_servers_detect_log()
        for port in detect_log_list.keys():
            for rule_id in detect_log_list[port]:
                mysqlObj.add_detect_log_info(self.port_uid_table[port], rule_id)

        deny_str = ""
        if platform.system() == 'Linux' and get_config().ANTISSATTACK == 1:
            wrong_iplist = ServerPool.get_instance().get_servers_wrong()
            server_ip = socket.gethostbyname(get_config().MYSQL_HOST)
            for id in wrong_iplist.keys():
                for ip in wrong_iplist[id]:
                    realip = ""
                    is_ipv6 = False
                    if common.is_ip(ip):
                        if(common.is_ip(ip) == socket.AF_INET):
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

                    if mysqlObj.is_ip_in_blockip(realip):
                        continue

                    if get_config().CLOUDSAFE == 1:
                        mysqlObj.add_block_ip(realip)
                    else:
                        if not is_ipv6:
                            os.system('route add -host %s gw 127.0.0.1' %
                                      str(realip))
                            deny_str = deny_str + "\nALL: " + str(realip)
                        else:
                            os.system(
                                'ip -6 route add ::1/128 via %s/128' %
                                str(realip))
                            deny_str = deny_str + \
                                "\nALL: [" + str(realip) + "]/128"

                        logging.info("Local Block ip:" + str(realip))
                if get_config().CLOUDSAFE == 0:
                    deny_file = open(hosts_deny_file_path(), 'a')
                    fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
                    deny_file.write(deny_str)
                    deny_file.close()
        del mysqlObj
        return update_transfer

    def uptime(self):
        with open('/proc/uptime', 'r') as f:
            return float(f.readline().split()[0])

    def load(self):
        import os
        cmd = "cat /proc/loadavg | awk '{ print $1 \" \" $2 \" \" $3 }'"
        return os.popen(cmd).readlines()[0][:-2]

    def trafficShow(self, Traffic):
        if Traffic < 1024:
            return str(round((Traffic), 2)) + "B"

        if Traffic < 1024 * 1024:
            return str(round((Traffic / 1024), 2)) + "KB"

        if Traffic < 1024 * 1024 * 1024:
            return str(round((Traffic / 1024 / 1024), 2)) + "MB"

        return str(round((Traffic / 1024 / 1024 / 1024), 2)) + "GB"

    def push_db_all_user(self):
        # 更新用户流量到数据库
        last_transfer = self.last_update_transfer
        curr_transfer = ServerPool.get_instance().get_servers_transfer()
        # 上次和本次的增量
        dt_transfer = {}
        for id in curr_transfer.keys():
            if id in last_transfer:
                if curr_transfer[id][0] + curr_transfer[id][1] - \
                        last_transfer[id][0] - last_transfer[id][1] <= 0:
                    continue
                if last_transfer[id][0] <= curr_transfer[id][0] and \
                        last_transfer[id][1] <= curr_transfer[id][1]:
                    dt_transfer[id] = [
                        curr_transfer[id][0] - last_transfer[id][0],
                        curr_transfer[id][1] - last_transfer[id][1]]
                else:
                    dt_transfer[id] = [curr_transfer[
                        id][0], curr_transfer[id][1]]
            else:
                if curr_transfer[id][0] + curr_transfer[id][1] <= 0:
                    continue
                dt_transfer[id] = [curr_transfer[id][0], curr_transfer[id][1]]
        for id in dt_transfer.keys():
            last = last_transfer.get(id, [0, 0])
            last_transfer[id] = [last[0] + dt_transfer[id]
                                 [0], last[1] + dt_transfer[id][1]]
        self.last_update_transfer = last_transfer.copy()
        self.update_all_user(dt_transfer)

    def pull_db_all_user(self):
        # 数据库所有用户信息
        try:
            switchrule = importloader.load('switchrule')
            keys = switchrule.getKeys()
        except Exception as e:
            keys = [
                'id',
                'port',
                'u',
                'd',
                'transfer_enable',
                'passwd',
                'enable',
                'method',
                'protocol',
                'protocol_param',
                'obfs',
                'obfs_param',
                'node_speedlimit',
                'forbidden_ip',
                'forbidden_port',
                'disconnect_ip',
                'is_multi_user']

        mysqlObj = MySqlWrapper()

        nodeinfo = mysqlObj.get_current_node_info()
        if nodeinfo is None:
            return []

        self.node_speedlimit = float(nodeinfo[2])
        self.traffic_rate = float(nodeinfo[3])

        self.mu_only = int(nodeinfo[4])

        if nodeinfo[5] == 10:
            self.is_relay = True
        else:
            self.is_relay = False

        if nodeinfo[0] == 0:
            node_group_sql = ""
        else:
            node_group_sql = "AND `node_group`=" + str(nodeinfo[0])

        users = mysqlObj.get_all_user_info(keys, nodeinfo[1], node_group_sql)

        rows = []
        for r in users:
            d = {}
            for column in range(len(keys)):
                d[keys[column]] = r[column]
            rows.append(d)

        # 读取节点IP
        # SELECT * FROM `ss_node`  where `node_ip` != ''
        self.node_ip_list = []
        node_ips = mysqlObj.get_node_ip_list()
        for r in node_ips:
            temp_list = str(r[0]).split(',')
            self.node_ip_list.append(temp_list[0])

        # 读取审计规则,数据包匹配部分
        keys_detect = ['id', 'regex']

        detect_list_1 = mysqlObj.get_detect_list_with_type_1(keys_detect)

        exist_id_list = []

        for r in detect_list_1:
            id = int(r[0])
            exist_id_list.append(id)
            if id not in self.detect_text_list:
                d = {}
                d['id'] = id
                d['regex'] = str(r[1])
                self.detect_text_list[id] = d
                self.detect_text_ischanged = True
            else:
                if r[1] != self.detect_text_list[id]['regex']:
                    del self.detect_text_list[id]
                    d = {}
                    d['id'] = id
                    d['regex'] = str(r[1])
                    self.detect_text_list[id] = d
                    self.detect_text_ischanged = True

        deleted_id_list = []
        for id in self.detect_text_list:
            if id not in exist_id_list:
                deleted_id_list.append(id)
                self.detect_text_ischanged = True

        for id in deleted_id_list:
            del self.detect_text_list[id]

        detect_list_2 = mysqlObj.get_detect_list_with_type_2(keys_detect)

        exist_id_list = []

        for r in detect_list_2:
            id = int(r[0])
            exist_id_list.append(id)
            if r[0] not in self.detect_hex_list:
                d = {}
                d['id'] = id
                d['regex'] = str(r[1])
                self.detect_hex_list[id] = d
                self.detect_hex_ischanged = True
            else:
                if r[1] != self.detect_hex_list[r[0]]['regex']:
                    del self.detect_hex_list[id]
                    d = {}
                    d['id'] = int(r[0])
                    d['regex'] = str(r[1])
                    self.detect_hex_list[id] = d
                    self.detect_hex_ischanged = True

        deleted_id_list = []
        for id in self.detect_hex_list:
            if id not in exist_id_list:
                deleted_id_list.append(id)
                self.detect_hex_ischanged = True

        for id in deleted_id_list:
            del self.detect_hex_list[id]

        # 读取中转规则，如果是中转节点的话

        if self.is_relay:
            self.relay_rule_list = mysqlObj.get_relay_rules()

        del mysqlObj
        return rows

    def cmp(self, val1, val2):
        if isinstance(val1, bytes):
            val1 = common.to_str(val1)
        if isinstance(val2, bytes):
            val2 = common.to_str(val2)
        return val1 == val2

    def del_server_out_of_bound_safe(self, last_rows, rows):
        # 停止超流量的服务
        # 启动没超流量的服务
        # 需要动态载入switchrule，以便实时修改规则

        try:
            switchrule = importloader.load('switchrule')
        except Exception as e:
            logging.error('load switchrule.py fail')
        cur_servers = {}
        new_servers = {}

        md5_users = {}

        self.mu_port_list = []

        for row in rows:
            if row['is_multi_user'] != 0:
                self.mu_port_list.append(int(row['port']))
                continue

            md5_users[row['id']] = row.copy()
            del md5_users[row['id']]['u']
            del md5_users[row['id']]['d']
            if md5_users[row['id']]['disconnect_ip'] is None:
                md5_users[row['id']]['disconnect_ip'] = ''

            if md5_users[row['id']]['forbidden_ip'] is None:
                md5_users[row['id']]['forbidden_ip'] = ''

            if md5_users[row['id']]['forbidden_port'] is None:
                md5_users[row['id']]['forbidden_port'] = ''
            md5_users[row['id']]['md5'] = common.get_md5(
                str(row['id']) + row['passwd'] + row['method'] + row['obfs'] + row['protocol'])

        for row in rows:
            self.port_uid_table[row['port']] = row['id']
            self.uid_port_table[row['id']] = row['port']

        if self.mu_only == 1:
            i = 0
            while i < len(rows):
                if rows[i]['is_multi_user'] == 0:
                    rows.pop(i)
                    i -= 1
                else:
                    pass
                i += 1

        for row in rows:
            port = row['port']
            user_id = row['id']
            passwd = common.to_bytes(row['passwd'])
            cfg = {'password': passwd}

            read_config_keys = [
                'method',
                'obfs',
                'obfs_param',
                'protocol',
                'protocol_param',
                'forbidden_ip',
                'forbidden_port',
                'node_speedlimit',
                'disconnect_ip',
                'is_multi_user']

            for name in read_config_keys:
                if name in row and row[name]:
                    cfg[name] = row[name]

            merge_config_keys = ['password'] + read_config_keys
            for name in cfg.keys():
                if hasattr(cfg[name], 'encode'):
                    try:
                        cfg[name] = cfg[name].encode('utf-8')
                    except Exception as e:
                        logging.warning(
                            'encode cfg key "%s" fail, val "%s"' % (name, cfg[name]))

            if 'node_speedlimit' in cfg:
                if float(
                        self.node_speedlimit) > 0.0 or float(
                        cfg['node_speedlimit']) > 0.0:
                    cfg['node_speedlimit'] = max(
                        float(
                            self.node_speedlimit), float(
                            cfg['node_speedlimit']))
            else:
                cfg['node_speedlimit'] = max(
                    float(self.node_speedlimit), float(0.00))

            if 'disconnect_ip' not in cfg:
                cfg['disconnect_ip'] = ''

            if 'forbidden_ip' not in cfg:
                cfg['forbidden_ip'] = ''

            if 'forbidden_port' not in cfg:
                cfg['forbidden_port'] = ''

            if 'protocol_param' not in cfg:
                cfg['protocol_param'] = ''

            if 'obfs_param' not in cfg:
                cfg['obfs_param'] = ''

            if 'is_multi_user' not in cfg:
                cfg['is_multi_user'] = 0

            if port not in cur_servers:
                cur_servers[port] = passwd
            else:
                logging.error(
                    'more than one user use the same port [%s]' % (port,))
                continue

            if cfg['is_multi_user'] != 0:
                cfg['users_table'] = md5_users.copy()

            cfg['detect_hex_list'] = self.detect_hex_list.copy()
            cfg['detect_text_list'] = self.detect_text_list.copy()

            if self.is_relay and row['is_multi_user'] != 2:
                temp_relay_rules = {}
                for id in self.relay_rule_list:
                    if ((self.relay_rule_list[id]['user_id'] == user_id or self.relay_rule_list[id]['user_id'] == 0) or row[
                            'is_multi_user'] != 0) and (self.relay_rule_list[id]['port'] == 0 or self.relay_rule_list[id]['port'] == port):
                        has_higher_priority = False
                        for priority_id in self.relay_rule_list:
                            if (
                                    (
                                        self.relay_rule_list[priority_id]['priority'] > self.relay_rule_list[id]['priority'] and self.relay_rule_list[id]['id'] != self.relay_rule_list[priority_id]['id']) or (
                                        self.relay_rule_list[priority_id]['priority'] == self.relay_rule_list[id]['priority'] and self.relay_rule_list[id]['id'] > self.relay_rule_list[priority_id]['id'])) and (
                                    self.relay_rule_list[priority_id]['user_id'] == user_id or self.relay_rule_list[priority_id]['user_id'] == 0) and (
                                    self.relay_rule_list[priority_id]['port'] == port or self.relay_rule_list[priority_id]['port'] == 0):
                                has_higher_priority = True
                                continue

                        if has_higher_priority:
                            continue

                        if self.relay_rule_list[id]['dist_ip'] == '0.0.0.0' and row['is_multi_user'] == 0:
                            continue

                        temp_relay_rules[id] = self.relay_rule_list[id]

                cfg['relay_rules'] = temp_relay_rules.copy()
            else:
                temp_relay_rules = {}

                cfg['relay_rules'] = temp_relay_rules.copy()

            if ServerPool.get_instance().server_is_run(port) > 0:
                cfgchange = False
                if self.detect_text_ischanged or self.detect_hex_ischanged:
                    cfgchange = True

                if port in ServerPool.get_instance().tcp_servers_pool:
                    ServerPool.get_instance().tcp_servers_pool[
                        port].modify_detect_text_list(self.detect_text_list)
                    ServerPool.get_instance().tcp_servers_pool[
                        port].modify_detect_hex_list(self.detect_hex_list)
                if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                    ServerPool.get_instance().tcp_ipv6_servers_pool[
                        port].modify_detect_text_list(self.detect_text_list)
                    ServerPool.get_instance().tcp_ipv6_servers_pool[
                        port].modify_detect_hex_list(self.detect_hex_list)
                if port in ServerPool.get_instance().udp_servers_pool:
                    ServerPool.get_instance().udp_servers_pool[
                        port].modify_detect_text_list(self.detect_text_list)
                    ServerPool.get_instance().udp_servers_pool[
                        port].modify_detect_hex_list(self.detect_hex_list)
                if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                    ServerPool.get_instance().udp_ipv6_servers_pool[
                        port].modify_detect_text_list(self.detect_text_list)
                    ServerPool.get_instance().udp_ipv6_servers_pool[
                        port].modify_detect_hex_list(self.detect_hex_list)

                if row['is_multi_user'] != 0:
                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[
                            port].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[
                            port].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[
                            port].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[
                            port].modify_multi_user_table(md5_users)

                if self.is_relay and row['is_multi_user'] != 2:
                    temp_relay_rules = {}
                    for id in self.relay_rule_list:
                        if ((self.relay_rule_list[id]['user_id'] == user_id or self.relay_rule_list[id]['user_id'] == 0) or row[
                                'is_multi_user'] != 0) and (self.relay_rule_list[id]['port'] == 0 or self.relay_rule_list[id]['port'] == port):
                            has_higher_priority = False
                            for priority_id in self.relay_rule_list:
                                if (
                                        (
                                            self.relay_rule_list[priority_id]['priority'] > self.relay_rule_list[id]['priority'] and self.relay_rule_list[id]['id'] != self.relay_rule_list[priority_id]['id']) or (
                                            self.relay_rule_list[priority_id]['priority'] == self.relay_rule_list[id]['priority'] and self.relay_rule_list[id]['id'] > self.relay_rule_list[priority_id]['id'])) and (
                                        self.relay_rule_list[priority_id]['user_id'] == user_id or self.relay_rule_list[priority_id]['user_id'] == 0) and (
                                        self.relay_rule_list[priority_id]['port'] == port or self.relay_rule_list[priority_id]['port'] == 0):
                                    has_higher_priority = True
                                    continue

                            if has_higher_priority:
                                continue

                            if self.relay_rule_list[id][
                                    'dist_ip'] == '0.0.0.0' and row['is_multi_user'] == 0:
                                continue

                            temp_relay_rules[id] = self.relay_rule_list[id]

                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[
                            port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[
                            port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[
                            port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[
                            port].push_relay_rules(temp_relay_rules)

                else:
                    temp_relay_rules = {}

                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[
                            port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[
                            port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[
                            port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[
                            port].push_relay_rules(temp_relay_rules)

                if port in ServerPool.get_instance().tcp_servers_pool:
                    relay = ServerPool.get_instance().tcp_servers_pool[port]
                    for name in merge_config_keys:
                        if name in cfg and not self.cmp(
                                cfg[name], relay._config[name]):
                            cfgchange = True
                            break
                if not cfgchange and port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                    relay = ServerPool.get_instance().tcp_ipv6_servers_pool[
                        port]
                    for name in merge_config_keys:
                        if name in cfg and not self.cmp(
                                cfg[name], relay._config[name]):
                            cfgchange = True
                            break
                # config changed
                if cfgchange:
                    self.del_server(port, "config changed")
                    new_servers[port] = (passwd, cfg)
            elif ServerPool.get_instance().server_run_status(port) is False:
                # new_servers[port] = passwd
                self.new_server(port, passwd, cfg)

        for row in last_rows:
            if row['port'] in cur_servers:
                pass
            else:
                self.del_server(row['port'], "port not exist")

        if len(new_servers) > 0:
            from shadowsocks import eventloop
            self.event.wait(eventloop.TIMEOUT_PRECISION +
                            eventloop.TIMEOUT_PRECISION / 2)
            for port in new_servers.keys():
                passwd, cfg = new_servers[port]
                self.new_server(port, passwd, cfg)

        ServerPool.get_instance().push_uid_port_table(self.uid_port_table)

    def del_server(self, port, reason):
        logging.info(
            'db stop server at port [%s] reason: %s!' % (port, reason))
        ServerPool.get_instance().cb_del_server(port)
        if port in self.last_update_transfer:
            del self.last_update_transfer[port]

        for mu_user_port in self.mu_port_list:
            if mu_user_port in ServerPool.get_instance().tcp_servers_pool:
                ServerPool.get_instance().tcp_servers_pool[
                    mu_user_port].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                ServerPool.get_instance().tcp_ipv6_servers_pool[
                    mu_user_port].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().udp_servers_pool:
                ServerPool.get_instance().udp_servers_pool[
                    mu_user_port].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().udp_ipv6_servers_pool:
                ServerPool.get_instance().udp_ipv6_servers_pool[
                    mu_user_port].reset_single_multi_user_traffic(self.port_uid_table[port])

    def new_server(self, port, passwd, cfg):
        protocol = cfg.get(
            'protocol',
            ServerPool.get_instance().config.get(
                'protocol',
                'origin'))
        method = cfg.get(
            'method', ServerPool.get_instance().config.get('method', 'None'))
        obfs = cfg.get(
            'obfs', ServerPool.get_instance().config.get('obfs', 'plain'))
        logging.info(
            'db start server at port [%s] pass [%s] protocol [%s] method [%s] obfs [%s]' %
            (port, passwd, protocol, method, obfs))
        ServerPool.get_instance().new_server(port, cfg)

    @staticmethod
    def del_servers():
        global db_instance
        for port in [
                v for v in ServerPool.get_instance().tcp_servers_pool.keys()]:
            if ServerPool.get_instance().server_is_run(port) > 0:
                ServerPool.get_instance().cb_del_server(port)
                if port in db_instance.last_update_transfer:
                    del db_instance.last_update_transfer[port]
        for port in [
                v for v in ServerPool.get_instance().tcp_ipv6_servers_pool.keys()]:
            if ServerPool.get_instance().server_is_run(port) > 0:
                ServerPool.get_instance().cb_del_server(port)
                if port in db_instance.last_update_transfer:
                    del db_instance.last_update_transfer[port]

    @staticmethod
    def thread_db(obj):
        import socket
        import time
        global db_instance
        timeout = 60
        socket.setdefaulttimeout(timeout)
        last_rows = []
        db_instance = obj()

        shell.log_shadowsocks_version()
        try:
            import resource
            logging.info(
                'current process RLIMIT_NOFILE resource: soft %d hard %d' %
                resource.getrlimit(
                    resource.RLIMIT_NOFILE))
        except:
            pass
        try:
            while True:
                load_config()
                try:
                    db_instance.push_db_all_user()
                    rows = db_instance.pull_db_all_user()
                    db_instance.del_server_out_of_bound_safe(last_rows, rows)
                    db_instance.detect_text_ischanged = False
                    db_instance.detect_hex_ischanged = False
                    last_rows = rows
                except Exception as e:
                    trace = traceback.format_exc()
                    logging.error(trace)
                    # logging.warn('db thread except:%s' % e)
                if db_instance.event.wait(60) or not db_instance.is_all_thread_alive():
                    break
                if db_instance.has_stopped:
                    break
        except KeyboardInterrupt as e:
            pass
        db_instance.del_servers()
        ServerPool.get_instance().stop()
        db_instance = None

    @staticmethod
    def thread_db_stop():
        global db_instance
        db_instance.has_stopped = True
        db_instance.event.set()

    def is_all_thread_alive(self):
        if not ServerPool.get_instance().thread.is_alive():
            return False
        return True

config = None

class MySqlWrapper(object):
    def __init__(self):
        global config
        config = get_config()
        if config.MYSQL_SSL_ENABLE == 1:
            self.conn = cymysql.connect(
                host=config.MYSQL_HOST,
                port=config.MYSQL_PORT,
                user=config.MYSQL_USER,
                passwd=config.MYSQL_PASS,
                db=config.MYSQL_DB,
                charset="utf8",
                ssl={
                    "ca": config.MYSQL_SSL_CA,
                    "cert": config.MYSQL_SSL_CERT,
                    "key": config.MYSQL_SSL_KEY,
                },
            )
        else:
            self.conn = cymysql.connect(
                host=config.MYSQL_HOST,
                port=config.MYSQL_PORT,
                user=config.MYSQL_USER,
                passwd=config.MYSQL_PASS,
                db=config.MYSQL_DB,
                charset="utf8",
            )
        self.conn.autocommit(True)

    def __del__(self):
        self.conn.commit()
        self.conn.close()

    def write_running_command(self, cmd):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO `auto` (`id`, `value`, `sign`, `datetime`,`type`) VALUES (NULL, 'NodeID:"
            + str(config.NODE_ID)
            + " Result:\n"
            + str(cmd)
            + "', 'NOT', unix_timestamp(),'2')"
        )
        cur.close()

    def write_speed_test_info(self, CTPing, CTUpSpeed, CTDLSpeed, CUPing, CUUpSpeed, CUDLSpeed, CMPing, CMUpSpeed, CMDLSpeed):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO `speedtest` (`id`, `nodeid`, `datetime`, `telecomping`, `telecomeupload`, `telecomedownload`, `unicomping`, `unicomupload`, `unicomdownload`, `cmccping`, `cmccupload`, `cmccdownload`) VALUES (NULL, '"
            + str(config.NODE_ID)
            + "', unix_timestamp(), '"
            + CTPing
            + "', '"
            + CTUpSpeed
            + "', '"
            + CTDLSpeed
            + "', '"
            + CUPing
            + "', '"
            + CUUpSpeed
            + "', '"
            + CUDLSpeed
            + "', '"
            + CMPing
            + "', '"
            + CMUpSpeed
            + "', '"
            + CMDLSpeed
            + "')"
        )
        cur.close()

    def get_all_node_ip(self):
        # 读取节点IP
        # SELECT * FROM `ss_node`  where `node_ip` != ''
        node_ip_list = []
        cur = self.conn.cursor()
        cur.execute(
            "SELECT `node_ip` FROM `ss_node`  where `node_ip` != ''"
        )
        for r in cur.fetchall():
            temp_list = str(r[0]).split(",")
            node_ip_list.append(temp_list[0])
        cur.close()
        return node_ip_list
 
    def is_ip_in_blockip(self, ip):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM `blockip` where `ip` = '"
            + str(ip)
            + "'"
        )
        rows = cur.fetchone()
        cur.close()
        return (rows is not None)

    def write_ip_to_blockip(self, ip):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO `blockip` (`id`, `nodeid`, `ip`, `datetime`) VALUES (NULL, '"
            + str(config.NODE_ID)
            + "', '"
            + str(ip)
            + "', unix_timestamp())"
        )
        cur.close()

    def get_all_blockip(self):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM `blockip` where `datetime`>unix_timestamp()-60"
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    def get_all_unblockip(self):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM `unblockip` where `datetime`>unix_timestamp()-60"
        )
        rows = cur.fetchall()
        cur.close()

    def get_all_auto(self):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM `auto` where `datetime`>unix_timestamp()-60 AND `type`=1"
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    def is_auto_sign_id(self, id):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM `auto`  where `sign`='"
            + str(config.NODE_ID)
            + "-"
            + str(id)
            + "'"
        )
        rows = cur.fetchone()
        cur.close()
        return (rows is not None)

    def write_auto_sign_info(self, id):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO `auto` (`id`, `value`, `sign`, `datetime`,`type`) VALUES (NULL, 'NodeID:"
            + str(config.NODE_ID)
            + " Exec Command ID:"
            + str(config.NODE_ID)
            + " Starting....', '"
            + str(config.NODE_ID)
            + "-"
            + str(id)
            + "', unix_timestamp(),'2')"
        )
        cur.close()

    def get_relay_rules(self):
        relay_rule_list = {}

        keys_detect = ['id', 'user_id', 'dist_ip', 'port', 'priority']

        cur = self.conn.cursor()
        cur.execute("SELECT " +
            ','.join(keys_detect) +
            " FROM relay where `source_node_id` = 0 or `source_node_id` = " +
            str(config.NODE_ID))

        for r in cur.fetchall():
            d = {}
            d['id'] = int(r[0])
            d['user_id'] = int(r[1])
            d['dist_ip'] = str(r[2])
            d['port'] = int(r[3])
            d['priority'] = int(r[4])
            relay_rule_list[d['id']] = d

        cur.close()
        return relay_rule_list

    def get_detect_list_with_type_2(self, keys_detect):
        cur = self.conn.cursor()
        cur.execute("SELECT " + ','.join(keys_detect) +
                    " FROM detect_list where `type` = 2")
        rows = cur.fetchall()
        cur.close()
        return rows

    def get_detect_list_with_type_1(self, keys_detect):
        cur = self.conn.cursor()
        cur.execute("SELECT " + ','.join(keys_detect) +
                    " FROM detect_list where `type` = 1")
        rows = cur.fetchall()
        cur.close()
        return rows

    def get_node_ip_list(self):
        cur = self.conn.cursor()
        cur.execute("SELECT `node_ip` FROM `ss_node`  where `node_ip` != ''")
        rows = cur.fetchall()
        cur.close()
        return rows

    def add_user_traffic_log(self, user_id, u, d, traffic_rate, traffic):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO `user_traffic_log` (`id`, `user_id`, `u`, `d`, `Node_ID`, `rate`, `traffic`, `log_time`) VALUES (NULL, '" +
            str(user_id) +
            "', '" +
            str(u) +
            "', '" +
            str(d) +
            "', '" +
            str(config.NODE_ID) +
            "', '" +
            str(traffic_rate) +
            "', '" +
            traffic +
            "', unix_timestamp()); ")
        cur.close()

    def update_node_heartbeat(self, bandwidth):
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE `ss_node` SET `node_heartbeat`=unix_timestamp(),`node_bandwidth`=`node_bandwidth`+'" +
            str(bandwidth) +
            "' WHERE `id` = " +
            str(config.NODE_ID) +
            " ; ")
        cur.close()

    def add_alive_user_count(self, alive_user_count):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO `ss_node_online_log` (`id`, `node_id`, `online_user`, `log_time`) VALUES (NULL, '" +
                    str(config.NODE_ID) + "', '" + str(alive_user_count) + "', unix_timestamp()); ")
        cur.close()

    def add_node_networking_info(self, uptime, load_info):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO `ss_node_info` (`id`, `node_id`, `uptime`, `load`, `log_time`) VALUES (NULL, '" +
                    str(config.NODE_ID) + "', '" + str(uptime) + "', '" + str(load_info) + "', unix_timestamp()); ")
        cur.close()        

    def get_current_node_info(self):
        cur = self.conn.cursor()
        cur.execute("SELECT `node_group`,`node_class`,`node_speedlimit`,`traffic_rate`,`mu_only`,`sort` FROM ss_node where `id`='" +
                    str(config.NODE_ID) + "' AND (`node_bandwidth`<`node_bandwidth_limit` OR `node_bandwidth_limit`=0)")
        nodeinfo = cur.fetchone()
        cur.close()
        return nodeinfo

    def add_block_ip(self, realip):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO `blockip` (`id`, `nodeid`, `ip`, `datetime`) VALUES (NULL, '" +
            str(config.NODE_ID) +
            "', '" +
            str(realip) +
            "', unix_timestamp())")
        cur.close()

    def add_detect_log_info(self, user_id, list_id):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO `detect_log` (`id`, `user_id`, `list_id`, `datetime`, `node_id`) VALUES (NULL, '" + 
            str(user_id) + 
            "', '" + 
            str(list_id) + 
            "', UNIX_TIMESTAMP(), '" + 
            str(config.NODE_ID) +
            "')"
        )
        cur.close()

    def add_alive_ip_info(self, userid, ip):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO `alive_ip` (`id`, `nodeid`,`userid`, `ip`, `datetime`) VALUES (NULL, '" + 
            str(config.NODE_ID) + 
            "','" + 
            str(userid) + 
            "', '" + 
            str(ip) + 
            "', unix_timestamp())")
        cur.close()

    def execute_query(self, query_sql, fetchall):
        cur = self.conn.cursor()
        cur.execute(query_sql)
        if fetchall:
            rows = cur.fetchall
        else:
            rows = cur.fetchone
        cur.close()
        return rows

    def get_all_user_info(self, fields, class_id, node_group_sql):
        cur = self.conn.cursor()
        cur.execute("SELECT " +
                    ','.join(fields) +
                    " FROM user WHERE ((`class`>=" +
                    str(class_id) +
                    " " +
                    node_group_sql +
                    ") OR `is_admin`=1) AND`enable`=1 AND `expire_in`>now() AND `transfer_enable`>`u`+`d`")
        rows = cur.fetchall()
        cur.close()
        return rows

