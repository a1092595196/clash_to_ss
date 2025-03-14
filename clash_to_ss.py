import os
import sys
import re
import json
import time
import requests
import base64
import socket
from urllib.parse import quote, unquote, urlparse, parse_qs

# =====================
# 核心配置参数
# =====================
SUBCONVERTER_API = os.getenv("SUBCONVERTER_API", "http://127.0.0.1:25500/sub")
CLASH_SUBSCRIPTIONS = os.getenv("CLASH_SUBSCRIPTIONS", "").split(',')
PORT_START = int(os.getenv("PORT_START", 10000))
MAX_PORTS = int(os.getenv("MAX_PORTS", 300))
XRAY_CONFIG_PATH = os.getenv("XRAY_CONFIG_PATH", "/usr/local/etc/xray/config.json")
LOG_FILE = os.getenv("LOG_FILE", "/var/log/clash_to_ss.log")

def log(message):
    with open(LOG_FILE, "a") as f:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"[{timestamp}] {message}\n")

def fetch_ss_subscriptions():
    all_uris = []
    for sub_url in CLASH_SUBSCRIPTIONS:
        try:
            log(f"处理订阅: {sub_url}")
            encoded_url = quote(sub_url)
            url = f"{SUBCONVERTER_API}?target=ss&url={encoded_url}&list=true"
            resp = requests.get(url, timeout=15)
            
            if resp.status_code == 200:
                uris = resp.text.splitlines()
                log(f"获取到{len(uris)}条SS链接: {sub_url}")
                all_uris.extend(uris)
            else:
                log(f"订阅返回异常状态码: {resp.status_code} URL: {sub_url}")
        
        except Exception as e:
            log(f"处理订阅失败: {sub_url} | 错误: {str(e)}")
    
    return all_uris

def parse_ss_uri(uri):
    try:
        pattern = r'^ss://(?P<base64>[^@]*)@(?P<host_port>[^?#]*)(?:\?(?P<query>.*?))?(?:#(?P<name>.*))?'
        match = re.match(pattern, uri)
        if not match:
            log(f"无效URI格式: {uri}")
            return None

        # 解析Base64部分
        base64_part = match.group('base64')
        padding = len(base64_part) % 4
        if padding:
            base64_part += '=' * (4 - padding)
        decoded = base64.b64decode(base64_part).decode('utf-8')
        method, password = decoded.split(':', 1)

        # 解析主机和端口
        host_port = match.group('host_port')
        parsed = urlparse(f"//{host_port}")
        host = parsed.hostname
        port = parsed.port

        if not all([host, port]):
            raise ValueError("无效的主机或端口")
        if not (1 <= port <= 65535):
            raise ValueError(f"端口超出范围: {port}")

        # 解析查询参数
        query = match.group('query') or ""
        params = parse_qs(query)
        plugin = ""
        obfs_host = ""
        
        if 'plugin' in params:
            plugin_str = unquote(params['plugin'][0])
            if plugin_str.startswith('simple-obfs'):
                # 转换为Xray兼容的obfs-server格式
                plugin_parts = plugin_str.split(';', 1)
                obfs_params = {}
                if len(plugin_parts) > 1:
                    for p in plugin_parts[1].split(';'):
                        if '=' in p:
                            k, v = p.split('=', 1)
                            obfs_params[k] = v
                # 生成插件配置
                plugin = "obfs-server"
                if 'obfs' in obfs_params:
                    plugin += f";obfs={obfs_params['obfs']}"
                if 'obfs-host' in obfs_params:
                    obfs_host = obfs_params['obfs-host']
                    plugin += f";obfs-host={obfs_host}"

        # 解析名称
        name = unquote(match.group('name')) if match.group('name') else ''

        return {
            'name': name,
            'server': host,
            'port': port,
            'method': method,
            'password': password,
            'plugin': plugin,
            'obfs_host': obfs_host  # 保存obfs-host用于TCP伪装
        }
    except Exception as e:
        log(f"解析失败: {uri} | 错误: {str(e)}")
        return None

def generate_xray_config(nodes):
    inbounds = []
    outbounds = []
    routing_rules = []
    
    for idx, node in enumerate(nodes[:MAX_PORTS]):
        sock_port = PORT_START + idx
        
        # 检查端口可用性
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', sock_port))
        except OSError:
            log(f"端口 {sock_port} 被占用，跳过该节点")
            continue
        
        inbounds.append({
            "port": sock_port,
            "listen": "0.0.0.0",
            "protocol": "socks",
            "tag": f"socks-{sock_port}",
            "settings": {
                "auth": "noauth",
                "udp": True
            }
        })
        
        # 构建Shadowsocks出站配置
        ss_config = {
            "address": node['server'],
            "port": node['port'],
            "method": node['method'],
            "password": node['password']
        }
        
        # 添加插件配置
        if node.get('plugin'):
            ss_config['plugin'] = node['plugin']

        # 构建streamSettings
        stream_settings = {
            "network": "tcp",
            "tcpSettings": {
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": ["/"],
                        "headers": {
                            "Host": [node.get('obfs_host', '') or '0a11ab2f647b.microsoft.com'],
                            "User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"],
                            "Accept-Encoding": ["gzip, deflate"],
                            "Connection": ["keep-alive"],
                            "Pragma": "no-cache"
                        }
                    }
                }
            }
        }

        outbounds.append({
            "tag": f"ss-{idx}",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [ss_config]
            },
            "streamSettings": stream_settings  # 添加TCP伪装配置
        })
        
        routing_rules.append({
            "type": "field",
            "inboundTag": [f"socks-{sock_port}"],
            "outboundTag": f"ss-{idx}"
        })
    
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules
        }
    }
    
    try:
        with open(XRAY_CONFIG_PATH + ".tmp", 'w') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        with open(XRAY_CONFIG_PATH + ".tmp", 'r') as f:
            json.load(f)
        
        os.rename(XRAY_CONFIG_PATH + ".tmp", XRAY_CONFIG_PATH)
        log("配置文件验证成功")
    
    except Exception as e:
        log(f"配置文件生成失败: {str(e)}")
        if os.path.exists(XRAY_CONFIG_PATH + ".tmp"):
            os.remove(XRAY_CONFIG_PATH + ".tmp")
        sys.exit(1)

def main():
    nodes = []
    uris = fetch_ss_subscriptions()
    
    for uri in uris:
        parsed = parse_ss_uri(uri)
        if parsed:
            nodes.append(parsed)
    
    if nodes:
        generate_xray_config(nodes)
        log(f"成功更新配置，共{len(nodes)}个节点")
        restart_cmd = "systemctl restart xray"
        if os.system(restart_cmd) != 0:
            log("Xray服务重启失败，请手动检查")
    else:
        log("未获取到有效节点")

if __name__ == "__main__":
    main()
