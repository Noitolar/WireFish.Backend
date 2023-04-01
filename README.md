# WireFish.Backend

## 概要

WireFish项目的后端接口，主要是Flask服务器+Scapy的结构

## 运行环境

系统：Windows

解释器：Python3.10

网络端口：http://localhost:5000

程序本体已经打包好，可以在任何Windows系统中直接运行

## 主要依赖

* flask：轻量级python服务器框架
* flask-cors：服务器跨域
* scapy：libpcap/winpcap的python封装，同时本项目中对原版scapy做了一些修改

## 基本结构

* ./dist/app.exe：使用pyinstaller封装的可执行文件
* api.py：sniffer类
* app.py：Flask服务器
* utils.py：工具库
* sample.pcap：用于静态测试的数据包文件

## 嗅探器类

### 数据结构

* target_interface：嗅探的网卡，默认嗅探全部网卡
* packet_filter：过滤器，BPF语法
* packets：抓包的缓存
* infos：抓包摘要的缓存
* status：嗅探器工作状态

### 类方法

* get_network_ionterfaces：获取网卡列表
* flush：清空缓存
* reset：还原嗅探器状态
* sniffer_callback：嗅探器回调函数
* sniff_realtime：实时抓包
* sniff_offline：用sample.pcap测试抓包
* get_update：增量输出缓存的数据包摘要
* extract_sessions：将缓存中的数据包按照session进行归类

## 主要接口

* get_interfaces：获取网卡列表
* set_interface：设置要嗅探的网卡
* set_filter：设置过滤器
* test_sniffer：用sample.pcap测试嗅探器功能
* start_sniffer：开启嗅探器
* update：返回增量更新的数据包摘要
* session：返回session归类后的序号组