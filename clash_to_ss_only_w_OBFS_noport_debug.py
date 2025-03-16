import os
import sys
import re
import json
import time
import requests
import base64
from urllib.parse import quote, unquote, urlparse, parse_qs

# =====================
# 核心配置参数
# =====================
SUBCONVERTER_API = os.getenv("SUBCONVERTER_API", "http://127.0.0.1:25500/sub")
CLASH_SUBSCRIPTIONS = os.getenv("CLASH_SUBSCRIPTIONS", "").split(',')
PORT_START = int(os.getenv("PORT_START", 10000))
MAX_PORTS = int(os.getenv("MAX_PORTS", 300))
XRAY_CONFIG_PATH = os.getenv("XRAY_CONFIG_PATH", "/usr/src/app/config.json")
LOG_FILE = os.getenv("LOG_FILE", "/usr/src/app/clash_to_ss.log")
DEFAULT_OBFS_HOST = os.getenv("DEFAULT_OBFS_HOST", "")

def log(message, level="INFO"):
    with open(LOG_FILE, "a") as f:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"[{timestamp}][{level}] {message}\n")

def fetch_ss_subscriptions():
    all_uris = []
    for sub_url in CLASH_SUBSCRIPTIONS:
        try:
            log(f"开始处理订阅: {sub_url}")
            encoded_url = quote(sub_url)
            url = f"{SUBCONVERTER_API}?target=ss&url={encoded_url}&list=true"
            log(f"构造转换器请求URL: {url}", "DEBUG")
            
            resp = requests.get(url, timeout=15)
            log(f"订阅响应状态码: {resp.status_code}", "DEBUG")
            
            if resp.status_code == 200:
                uris = resp.text.splitlines()
                log(f"获取到{len(uris)}条SS链接: {sub_url}")
                all_uris.extend(uris)
            else:
                log(f"订阅返回异常状态码: {resp.status_code} URL: {sub_url}")
        
        except Exception as e:
            log(f"处理订阅失败: {sub_url} | 错误: {str(e)}", "ERROR")
    
    return all_uris

def parse_ss_uri(uri):
    try:
        log(f"开始解析URI: {uri}", "DEBUG")
        
        # 修正后的正则表达式（严格分割查询参数和节点名称）
        pattern = r'^ss://(?P<base64>[^@]*)@(?P<host_port>[^?#]*)(?:\?(?P<query>[^#]*))?(?:#(?P<name>.*))?'
        match = re.match(pattern, uri)
        
        if not match:
            log(f"无效URI格式: {uri}", "ERROR")
            return None

        # Base64解码
        base64_part = match.group('base64')
        padding = len(base64_part) % 4
        if padding:
            base64_part += '=' * (4 - padding)
        decoded = base64.b64decode(base64_part).decode('utf-8')
        method, password = decoded.split(':', 1)
        log(f"解析加密方法: {method} | 密码: {password}", "DEBUG")

        # 主机端口解析
        host_port = match.group('host_port')
        parsed = urlparse(f"//{host_port}")
        host = parsed.hostname
        port = parsed.port
        log(f"解析服务器: {host}:{port}", "DEBUG")

        # 查询参数处理（严格捕获到#之前）
        query = match.group('query') or ""
        params = parse_qs(query)
        log(f"原始查询参数: {query}", "DEBUG")
        log(f"解析后参数字典: {params}", "DEBUG")
        
        plugin = ""
        obfs = ""
        obfs_host = ""
        
        if 'plugin' in params:
            plugin_str = params['plugin'][0]  # parse_qs已自动解码
            log(f"原始插件参数: {plugin_str}", "DEBUG")
            
            if plugin_str.startswith('simple-obfs'):
                parts = plugin_str.split(';', 1)
                obfs_params = {}
                if len(parts) > 1:
                    # 修复参数解析：处理带等号的参数值
                    for param in parts[1].split(';'):
                        param = param.strip()
                        if '=' in param:
                            k, v = param.split('=', 1)
                            obfs_params[k.strip()] = unquote(v.strip().strip('"'))
                obfs = obfs_params.get('obfs', 'http')
                obfs_host = obfs_params.get('obfs-host', '') or DEFAULT_OBFS_HOST
                plugin = f"obfs-server;obfs={obfs};obfs-host={obfs_host}"
                log(f"解析插件参数: {obfs_params}", "DEBUG")
            else:
                log(f"不支持的插件类型: {plugin_str}", "WARNING")
        else:
            log("未检测到插件参数", "DEBUG")

        # 名称处理（修复名称解码）
        raw_name = match.group('name') or ''
        name = unquote(raw_name).replace('+', ' ').strip() if raw_name else ''
        log(f"原始名称: {raw_name} | 解析后名称: {name}", "DEBUG")

        # 最终验证
        log(f"解析节点详情 - 名称: {name}, 方法: {method}, 服务器: {host}:{port}, OBFS Host: {obfs_host or '未设置'}")

        return {
            'name': name,
            'server': host,
            'port': port,
            'method': method,
            'password': password,
            'plugin': plugin,
            'obfs_host': obfs_host
        }
    except Exception as e:
        log(f"解析失败: {uri} | 错误: {str(e)}", "ERROR")
        return None

def generate_xray_config(nodes):
    inbounds = []
    outbounds = []
    routing_rules = []
    
    for idx, node in enumerate(nodes[:MAX_PORTS]):
        sock_port = PORT_START + idx
        
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
        
        ss_config = {
            "address": node['server'],
            "port": node['port'],
            "method": node['method'],
            "password": node['password']
        }
        
        if node.get('plugin'):
            ss_config['plugin'] = node['plugin']

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
                            "Host": [node['obfs_host'] or DEFAULT_OBFS_HOST],
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
            "streamSettings": stream_settings
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
        tmp_path = XRAY_CONFIG_PATH + ".tmp"
        with open(tmp_path, 'w') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        with open(tmp_path, 'r') as f:
            json.load(f)
        
        os.rename(tmp_path, XRAY_CONFIG_PATH)
        log("配置文件验证成功")
    
    except Exception as e:
        log(f"配置文件生成失败: {str(e)}", "ERROR")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
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
        log(f"成功更新配置文件，共{len(nodes)}个节点")
    else:
        log("未获取到有效节点", "WARNING")

if __name__ == "__main__":
    main()