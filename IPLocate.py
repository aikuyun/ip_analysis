#!/usr/bin/python
# -*- coding: utf-8 -*-

# 该脚本用于根据 ip 地址定位用户。

from __future__ import print_function, division
import re
import socket
import struct
import os

import multiprocessing

import time


_unpack_S = lambda s: struct.unpack("12s", s)
_unpack_L = lambda l: struct.unpack("<L", l)
_unpack_Q = lambda q: struct.unpack("Q", q)


import datetime

start_time = datetime.datetime.now()


def _to_str(something):
    if isinstance(something, bytes):
        return something.decode('utf8')
    else:
        return something


class IP(object):
    def __init__(self, ):
        self.base_len = 64
        self.offset_addr = 0
        self.offset_owner = 0
        self.offset_info = None
        self.ip_re = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')


    def load_dat(self, fname):
        '''Load Dat File To Memory'''
        try:
            f = open(fname, "rb")
            finfo = f.read()
            self.offset_info = finfo[16:]
            self.offset_addr, = _unpack_Q(finfo[0:8])
            self.offset_owner, = _unpack_Q(finfo[8:16])
            f.close()
        except Exception as e:
            print(e)
            print("Loda File Fail.")
            exit(0)

    # def load_dat(self, fname):
    #     '''Load HDFS Dat File To Memory'''
    #     try:
    #         # f = open(fname, "rb")
    #         # with client.open("/user/tsl/IP_trial_2019M04_single_WGS84.dat") as finfo:
    #         with client.read("/user/tsl/IP_trial_2019M04_single_WGS84.dat") as finfo:
    #             # finfo = f.read()
    #             for line in finfo:
    #                 print(line)
    #                 self.offset_info = line[16:]
    #                 self.offset_addr, = _unpack_Q(line[0:8])
    #                 self.offset_owner, = _unpack_Q(line[8:16])
    #         # f.close()
    #     except Exception as e:
    #         print(e)
    #         print("Loda File Fail.")
    #         exit(0)

    def locate_ip(self, ip):
        '''Locate IP'''
        if self.ip_re.match(ip):
            nip = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ip)))[0])
        else:
            return ['Error IP']

        record_min = 0
        record_max = self.offset_addr // self.base_len - 1
        record_mid = (record_min + record_max) // 2
        while record_max - record_min >= 0:
            minip, = _unpack_L(self.offset_info[record_mid * self.base_len: record_mid * self.base_len + 4])
            maxip, = _unpack_L(self.offset_info[record_mid * self.base_len + 4: record_mid * self.base_len + 8])
            if nip < minip:
                record_max = record_mid - 1
            elif (nip == minip) or (nip > minip and nip < maxip) or (nip == maxip):
                addr_begin, = _unpack_Q(self.offset_info[record_mid * self.base_len + 8: record_mid * self.base_len + 16])
                addr_length, = _unpack_Q(self.offset_info[record_mid * self.base_len + 16: record_mid * self.base_len + 24])
                owner_begin, = _unpack_Q(self.offset_info[record_mid * self.base_len + 24: record_mid * self.base_len + 32])
                owner_length, = _unpack_Q(self.offset_info[record_mid * self.base_len + 32: record_mid * self.base_len + 40])
                wgs_lon, = _unpack_S(self.offset_info[record_mid * self.base_len + 40: record_mid * self.base_len + 52])
                wgs_lat, = _unpack_S(self.offset_info[record_mid * self.base_len + 52: record_mid * self.base_len + 64])
                addr_bundle = self.offset_info[addr_begin:addr_begin + addr_length]
                if isinstance(addr_bundle, bytes):  # python3 python2
                    addr_bundle = addr_bundle.decode('utf8')
                addr = addr_bundle.split("|")
                owner = self.offset_info[owner_begin:owner_begin + owner_length]

                tmp_list = [str(minip), str(maxip), addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], _to_str(wgs_lon), _to_str(wgs_lat), _to_str(owner)]
                res_list = []
                for item in tmp_list:
                    item = item.replace('\x00', '')
                    res_list.append(item)
                return res_list
            elif nip > maxip:
                record_min = record_mid + 1
            else:
                print("Error Case")
            record_mid = (record_min + record_max) // 2
        return ['Not Found.']


# python2 的一个 bug，这里悬疑==需要额外处理一下。
# 解析 ip，并存入文件
def ip_analysis(test,file_name, target_file):
    test.load_dat("./data/IP_trial_2019M04_single_WGS84.dat")
    print(file_name)
    print(target_file)
    # 异常的简洁版写法
    with open(target_file, 'a+') as f1:
        with open(file_name, 'r') as f:
            # print(f.read())
            ip_uuids = f.readlines()
            # print(len(ip_uuids))
            for ip_uuid in ip_uuids:
                ip = ip_uuid.split('\t')[0]
                # print(ip)
                result = test.locate_ip(ip)
                # print(len(result))
                # return result
                print(ip)
                if len(result) > 1:
                    f1.write('\t'.join([ip, result[5], result[6], result[7], '\n']))
                else:
                    print('error')


# test
def ip_analysis_1(file_name, target_file):
    print(file_name)
    with open(target_file, 'a+') as f1:
        # 异常的简洁版写法
        with open(file_name, 'r') as f:
            ip_uuids = f.readlines()
            for ip_uuid in ip_uuids:
                f1.write(ip_uuid)


if __name__ == '__main__':

    test = IP()
    os.makedirs('./data/out/')
    os.makedirs('./data/split/')

    source_dir = './data/ip.txt'
    target_dir_0 = './data/split/'

    target_dir_1 = './data/out/'

    # --------------切分逻辑开始--------------
    # 计数器
    flag_0 = 0
    flag_1 = 0

    # 切分的行数

    line_nums = 0

    # 文件后缀
    name = 1

    # 存放数据
    dataList = []

    print("开始。。。。。")

    with open(source_dir, 'r') as f_source_0:
        for line in f_source_0:
            flag_0 += 1

    line_nums = flag_0 // 3

    print(line_nums)

    with open(source_dir, 'r') as f_source_1:
        for line in f_source_1:
            flag_1 += 1
            dataList.append(line)
            if flag_1 == line_nums:
                with open(target_dir_0 + "ip_" + str(name) + ".txt", 'w+') as f_target:
                    for data in dataList:
                        f_target.write(data)
                name += 1
                flag_1 = 0
                dataList = []

    # 处理最后一批行数少于 line_nums 行的
    with open(target_dir_0 + "ip_" + str(name) + ".txt", 'w+') as f_target:
        for data in dataList:
            f_target.write(data)

    print("切分完成: "+ str(name) + "份文件")

    # --------------切分逻辑结束--------------

    # --------------分散读取计算--------------

    pool = multiprocessing.Pool(processes=name)

    rs = []

    for n in range(1, name+1):

        file_name = target_dir_0 + "ip_"+ str(n) + ".txt"

        target_file = target_dir_1 + "ip_city" + str(n) + ".txt"

        # rs.append(pool.apply_async(ip_analysis, (test, file_name, target_file,)))

        ip_analysis(test, file_name,target_file)

        time.sleep(1)

    print('等待所有进程...')
    pool.close()
    pool.join()  # behind close() or terminate()

    for r in rs:
        print(r.get())

    end_time = datetime.datetime.now()

    print(end_time-start_time)

    # 获取目标文件夹的路径
    filedir = os.getcwd() + '/data/out/'
    # 获取当前文件夹中的文件名称列表
    filenames = os.listdir(filedir)
    # 打开当前目录下的result.txt文件，如果没有则创建
    f = open('ip.txt', 'w')
    # 先遍历文件名
    for filename in filenames:
        filepath = filedir + '/' + filename
        # 遍历单个文件，读取行数
        for line in open(filepath):
            f.writelines(line)
    # 关闭文件
    f.close()

