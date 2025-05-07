#! /usr/bin/python3
# -*- coding: utf-8 -*- 


import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding=sys.stdout.encoding, errors='xmlcharrefreplace', line_buffering=True, write_through=False )

import ipaddress
import subprocess
import argparse
ps = argparse.ArgumentParser(description="修改wireguard的peer的AllowedIPs\n主要用来方便用peer的别名来切换公网网段的路由\n不会改变那些未在文件中的定义的网段")
ps.add_argument("wgIFfile", help="指定wg的设置文件路径")
ps.add_argument("-p", "--pub_net_seg", metavar="FILE", help="指定用来定义公网网段的文件", default="pubnetseg.txt")
ps.add_argument("-r", "--route", action="store_true", help="向51821号路由表添加已定义的公网网段 用这个就不要在peer的AllowedIPs中设置公网网段")
ps.add_argument("-s", "--set_pubnetseg2peer", metavar="PEER", help="向PEER的AllowedIPs中添加公网网段 并将其他peer的AllowedIPs中的公网网段去除")
    
args = ps.parse_args()



def check_file(file_path):
    """检查一下文件是否存在"""
    if not os.path.isfile(file_path):
        print(f"{file_path} 不存在", file=sys.stderr) 
        sys.exit(1)    

###########################
"""
这一段检查了wg的.conf文件是否存在
如果存在 就把工作路径设置为.conf文件所在路径
然后检查一下记录公网网段的文件是否存在 默认是pub_net_seg.txt
"""
check_file(args.wgIFfile)
IFF = os.path.abspath(args.wgIFfile)
workpath = os.path.dirname(IFF)
os.chdir(workpath)
IFname=os.path.splitext(os.path.basename(IFF))[0]
check_file(args.pub_net_seg)
###########################
IF={IFname:{}}
"""
IF的结构类似于
{
    "saowg":{
        "in1wg":{
            "PublicKey":"+BkUhDYirtHN88/LOCz0qNKg/nIUHL7uCD0VBhXX33o=",
            "AllowedIPs":["10.6.6.1", "10.6.6.13"],
            },
        "on5wg":{
            "PublicKey":"g062BtgXIvX2V4uSW/SWkFUVaLmeDS9TRXrqxM7Jn2c=",
            "AllowedIPs":["10.6.6.15"],
            },
        }
}
"""


###################
"""这段是读取pubnetseg.txt文件获取哪些是需要处理的公网网段"""
with open(args.pub_net_seg, 'r', encoding='utf-8') as pub_net_seg:
    PNS = pub_net_seg.readlines()

import ipaddress
PNSlist = []    #公网网段pub_net_seg的列表 ipaddress
for n in PNS:
    try:
        net = ipaddress.ip_network(n.strip())
        if not net in PNSlist:
            PNSlist.append(net)
    except:
        print(f"{n.strip()} 不是一个网段 ... 忽略")
######################





###########################
"""这是AI给的"""
def rc(command):
    try:
        # 使用 subprocess.run 执行命令，捕获输出并在终端显示
        result = subprocess.run(
            command,
            shell=False,  # 如果命令是字符串，需启用 shell=True
            check=True,  # 如果命令返回非零退出码，抛出异常
            text=True,   # 输出为字符串（而非字节）
            stdout=subprocess.PIPE,  # 捕获标准输出
            stderr=subprocess.PIPE   # 捕获标准错误
        )
        # 打印标准输出
        if result.stdout:
            print(result.stdout.strip())
        return result
    except subprocess.CalledProcessError as e:
        # 如果命令执行失败，打印错误信息并退出
        print(f"Error executing command: {e}", file=sys.stderr)
        if e.stderr:
            print(e.stderr.strip(), file=sys.stderr)
        sys.exit(e.returncode)
    except Exception as e:
        # 捕获其他异常（如命令不存在等）
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
#######################################
#print(PNSlist)
if args.route:
    print(f"准备将{args.pub_net_seg}中定义的网段添加到51821路由表")
    for ip in PNSlist:
        comm = ["ip", "-4", "route", "add", str(ip), "dev", IFname, "table", "51821"]
        print(" ".join(comm))
        rc(comm)
        print("Done!")
        







############################
"""
这段是处理saowg.conf文件
主要是读取[Peer]#saowg这样的行 用注释中的别名来命名peer
如果[Peer]开头的行没有注释别名 那么直接用这个peer的pubkey
"""
with open(IFF, 'r', encoding='utf-8') as IFconf:
    IFconf = IFconf.readlines()

pubkey2peername = {}
for n in IFconf:
    plp = n.split("#") #pls: peer line parts
    if plp[0].strip() == r"[Peer]":
        try:
            peername = plp[1].strip()
        except:
            peername = ""
    klp = n.split("=",1) #klp: key line parts
    if klp[0].strip() == r"PublicKey":
        ppubk = klp[1].split("#")[0].strip()
        if not peername:
            peername = ppubk
        if not peername in pubkey2peername:
            pubkey2peername[ppubk] = peername
            IF[IFname][peername] = {} 
            IF[IFname][peername]["PublicKey"] = ppubk
            IF[IFname][peername]["AllowedIPs"] = []
      
####################################
        
######################################
"""
这一段用wg命令读取接口当前各个peer的allowedips
把不属于已定义的公网IP段的部分加入IF[saowg][peer]["allowed-ips"]中
"""
r=subprocess.run(['wg', 'show', IFname, 'allowed-ips'], capture_output=True, text=True,)

rls = r.stdout.split("\n")
for l in rls:
    try:
        ppubk = l.split("\t")[0]
        ips = l.split("\t")[1].split(" ")
    except:
       continue
    for ip in ips:
        if ip:
            ipn = ipaddress.ip_network(ip)
            if not ipn in PNSlist:
                IF[IFname][pubkey2peername[ppubk]]["AllowedIPs"].append(str(ipn))
#######################################


def setaip(peer):
    pubkey = IF[IFname][peer]["PublicKey"]
    ips = ",".join(IF[IFname][peer]["AllowedIPs"])
    comm = ["wg", "set", IFname, "peer", pubkey, "allowed-ips", ips]
    print(" ".join(comm))
    rc(comm)
    print("Done!")

def pdata(data):
    from pprint import pprint
    pprint(data)

if not args.set_pubnetseg2peer:
    print("已定义的公网网段: ")
    pdata(PNSlist)
    print("接口数据: ")
    pdata(IF)
else:
    tp = args.set_pubnetseg2peer
    if not tp in IF[IFname].keys():
        print(f"peer {tp} 不存在", file=sys.stderr) 
        sys.exit(1)
    for ip in PNSlist:
        IF[IFname][tp]["AllowedIPs"].append(str(ip))
    for peer in IF[IFname].keys():
        setaip(peer)
    print("切换完成!")
    print(f"现在出口节点是{args.set_pubnetseg2peer}")       
    
    
















