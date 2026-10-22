#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MotionPro OTP v2.9 的 Linux 兼容实现。

完全复刻 APK 的口令算法与站点注册/校时流程：
  * 口令 = HOTP(HMAC-SHA1, 8字节计数器[4字节0 + 4字节大端 time/interval]) 动态截断 % 1e6
  * interval 取值被 native 层限制在 [30, 300] 秒
  * 注册时口令种子为本地随机生成，sm=Base32(seed)（RFC4648，无填充）
  * 站点注册/登录、an_login.js 解析、时间同步与原 APP 相同的 HTTP 端点

仅依赖 Python 3 标准库；读取 Android 数据库时需要 cryptography 或 openssl。
otp -i FILE 可直接读取 JSON 配置、裸 otp.db 或 adb backup (.ab)，无需先导入。
脚本不会在用户目录写入任何默认配置，配置文件路径必须由用户显式指定。
"""

import argparse
import base64
import binascii
import getpass
import gzip
import hashlib
import hmac
import html
import http.client
import io
import json
import os
import re
import shutil
import sqlite3
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import zlib

APP_TITLE = "MotionPro OTP for Linux"

AN_PREFIX = "/prx/000/http/localhost"
# c/b/a/b.java 中的 AES/CBC/PKCS5Padding 密钥与 IV（用于解密 otp.db 中的种子）
DB_AES_KEY = b"arraynetworks920jSd8f*#9*d-#j0.H"
DB_AES_IV = b"arraydevIVclick1"

DEBUG = False


class ToolError(Exception):
    pass


class NetError(ToolError):
    pass


# --------------------------------------------------------------------------
# 算法（与 libvpn.so 中 array_vpn_otp_get_value / encode_data 逐指令对齐）
# --------------------------------------------------------------------------

def clamp_interval(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return 30
    return min(300, max(30, value))


def b32encode(raw):
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def b32decode(text):
    text = text.strip().replace(" ", "").replace("-", "").upper().rstrip("=")
    if not text:
        raise ToolError("种子为空")
    pad = (-len(text)) % 8
    try:
        return base64.b32decode(text + "=" * pad, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ToolError("无效的 Base32 种子: %s" % exc)


def hotp(seed, seconds, interval):
    interval = clamp_interval(interval)
    time32 = seconds & 0xFFFFFFFF          # Java int / native w0 (udiv)
    counter = (time32 // interval) & 0xFFFFFFFF
    message = b"\x00\x00\x00\x00" + struct.pack(">I", counter)
    digest = hmac.new(seed, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return value % 1000000


def java_seconds(now_ms):
    # Java 的 long/int 除法向零截断
    return now_ms // 1000 if now_ms >= 0 else -((-now_ms) // 1000)


def site_seconds(site, at=None):
    now_ms = int(time.time() * 1000) if at is None else int(at) * 1000
    return java_seconds(now_ms + int(site.get("offset_ms", 0)))


def site_state(site, at=None):
    seconds = site_seconds(site, at)
    interval = clamp_interval(site.get("interval", 30))
    code = hotp(b32decode(site["seed_b32"]), seconds, interval)
    remaining = interval - (seconds % interval)
    return code, remaining, interval, seconds


def format_code(code):
    text = "%06d" % code
    return "%s %s %s" % (text[0:2], text[2:4], text[4:6])


# --------------------------------------------------------------------------
# 地址与配置
# --------------------------------------------------------------------------

def parse_address(address):
    """返回 (scheme, host[:port], favorite_path)，与 c/b/a/l.java 一致。"""
    text = (address or "").strip()
    scheme = None
    if "://" in text:
        scheme, text = text.split("://", 1)
        scheme = scheme.lower()
    host, _, path = text.partition("/")
    return scheme, host.strip(), path.strip("/")


def normalize_address(address):
    scheme, host, path = parse_address(address)
    host = re.sub(r"^(\[[^\]]+\]|[^:]+):443$", r"\1", host)
    return host + ("/" + path if path else "")


def split_host_port(host):
    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            raise ToolError("无效的 IPv6 地址: %s" % host)
        name = host[1:end]
        rest = host[end + 1:]
        if rest.startswith(":"):
            try:
                return name, int(rest[1:])
            except ValueError:
                raise ToolError("无效端口: %s" % host)
        return name, 443
    if host.count(":") == 1:
        name, port = host.rsplit(":", 1)
        if port.isdigit():
            return name, int(port)
    return host, 443


def normalize_config_path(path):
    text = (path or "").strip()
    if not text:
        raise ToolError("配置文件路径不能为空")
    path = os.path.abspath(os.path.expanduser(text))
    if os.path.isdir(path):
        raise ToolError("配置文件路径是目录，请指定具体的 .json 文件: %s" % path)
    return path


def prompt_config_path(prompt="配置文件保存路径"):
    while True:
        sys.stderr.write("%s（例: ./sites.json，留空取消）: " % prompt)
        sys.stderr.flush()
        try:
            answer = input().strip()
        except EOFError:
            raise ToolError("没有输入配置文件路径")
        if not answer:
            raise ToolError("已取消，未选择配置文件路径")
        try:
            path = normalize_config_path(answer)
        except ToolError as exc:
            print("错误: %s" % exc, file=sys.stderr)
            continue
        if os.path.exists(path):
            try:
                load_config_for_write(path)
            except ToolError as exc:
                print("错误: %s" % exc, file=sys.stderr)
                print("请换一个路径，或先修正该文件。", file=sys.stderr)
                continue
        return path


def load_config(path, must_exist=True):
    path = normalize_config_path(path)
    if not os.path.exists(path):
        if must_exist:
            raise ToolError("配置文件不存在: %s" % path)
        return {"version": 1, "sites": []}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ToolError("读取配置失败 %s: %s" % (path, exc))
    if not isinstance(data, dict) or not isinstance(data.get("sites"), list):
        raise ToolError("配置文件格式不正确: %s" % path)
    for site in data["sites"]:
        if (not isinstance(site, dict) or not site.get("address")
                or not site.get("seed_b32")):
            raise ToolError("配置文件中存在无效站点记录: %s" % path)
    try:
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            print("警告: %s 权限为 %o，建议 chmod 600" % (path, mode), file=sys.stderr)
    except OSError:
        pass
    return data


def load_config_for_write(path):
    path = normalize_config_path(path)
    if os.path.exists(path):
        try:
            kind = detect_input_kind(path)
        except OSError as exc:
            raise ToolError("无法读取配置文件 %s: %s" % (path, exc))
        if kind != "json":
            raise ToolError("需要 JSON 配置文件，不能使用 .ab/otp.db: %s" % path)
        return load_config(path)
    return {"version": 1, "sites": []}


def load_writable_config(path):
    path = normalize_config_path(path)
    if not os.path.isfile(path):
        raise ToolError("配置文件不存在: %s" % path)
    return load_config_for_write(path)


def save_config(path, config):
    path = normalize_config_path(path)
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory, mode=0o700)
            os.chmod(directory, 0o700)
        except OSError as exc:
            raise ToolError("无法创建配置目录 %s: %s" % (directory, exc))
    try:
        fd, tmp = tempfile.mkstemp(prefix=".sites-", dir=directory)
    except OSError as exc:
        raise ToolError("无法在 %s 创建配置文件: %s" % (directory, exc))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(config, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ToolError("写入配置失败 %s: %s" % (path, exc))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def find_site(sites, selector):
    if not sites:
        raise ToolError("没有可用的站点，请检查输入文件")
    if not selector:
        if len(sites) == 1:
            return sites[0]
        listing = "\n".join("  [%d] %s" % (i + 1, s["address"]) for i, s in enumerate(sites))
        raise ToolError("存在多个站点，请指定站点（地址、序号或子串）:\n" + listing)
    if selector.isdigit():
        index = int(selector)
        if 1 <= index <= len(sites):
            return sites[index - 1]
    needle = selector.casefold()
    matches = [s for s in sites if needle in s["address"].casefold()]
    if not matches:
        raise ToolError("找不到站点: %s" % selector)
    if len(matches) > 1:
        listing = "\n".join("  %s" % s["address"] for s in matches)
        raise ToolError("匹配到多个站点，请输入更精确的名称:\n" + listing)
    return matches[0]


def upsert_site(config, site, force=True):
    for index, existing in enumerate(config["sites"]):
        if existing["address"].casefold() == site["address"].casefold():
            if not force:
                return False
            if existing.get("username") and not site.get("username"):
                site["username"] = existing["username"]
            if existing.get("created_at") and not site.get("created_at"):
                site["created_at"] = existing["created_at"]
            config["sites"][index] = site
            return True
    config["sites"].append(site)
    return True


def mask_seed(seed_b32):
    if len(seed_b32) <= 8:
        return "*" * len(seed_b32)
    return seed_b32[:4] + "…" + seed_b32[-2:]


# --------------------------------------------------------------------------
# HTTP（复刻 c/b/a/c.java：仅 https、超时 20s、禁用证书校验、不自动跟随跳转）
# --------------------------------------------------------------------------

def _debug(message):
    if DEBUG:
        print("[debug] " + message, file=sys.stderr)


def http_request(host, method, path, body=None, cookie=None, verify_tls=False, timeout=20):
    name, port = split_host_port(host)
    if verify_tls:
        context = ssl.create_default_context()
    else:
        context = ssl._create_unverified_context()
    if not path.startswith("/"):
        path = "/" + path
    headers = {
        "Accept": "text/html, image/gif, image/jpeg, */*; q=0.2",
        "Accept-Encoding": "deflate, gzip",
        "User-Agent": "MotionProOTP/2.9 (Linux)",
    }
    if cookie:
        headers["Cookie"] = cookie
    payload = None
    if body is not None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(payload))
    _debug("%s https://%s%s%s" % (method, host, path,
                                   " (%d bytes)" % len(payload) if payload else ""))
    conn = None
    try:
        conn = http.client.HTTPSConnection(name, port, context=context, timeout=timeout)
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        status = response.status
        raw = response.read() if status == 200 else b""
        header_list = response.getheaders()
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise NetError("连接 %s 失败: %s" % (host, exc))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    encoding = ""
    for key, value in header_list:
        if key.lower() == "content-encoding":
            encoding = (value or "").lower()
            break
    if raw and "gzip" in encoding:
        try:
            raw = gzip.decompress(raw)
        except OSError:
            pass
    elif raw and "deflate" in encoding:
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            try:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            except zlib.error:
                pass
    text = raw.decode("utf-8", "replace")

    def header(key):
        for k, v in header_list:
            if k.lower() == key.lower():
                return v
        return None

    set_cookies = [v for k, v in header_list if k.lower() == "set-cookie"]
    _debug("-> HTTP %d (%d bytes)" % (status, len(raw)))
    return {
        "status": status,
        "text": text,
        "headers": header_list,
        "header": header,
        "set_cookies": set_cookies,
    }


def _js_value(text, name):
    index = text.find(name)
    if index < 0:
        return None
    equals = text.find("=", index + len(name))
    if equals < 0:
        return None
    end = text.find(";", equals + 1)
    if end < 0:
        end = text.find("\n", equals + 1)
    if end < 0:
        end = len(text)
    return text[equals + 1:end].strip()


def _unquote(value):
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def _parse_method_name(text):
    match = re.search(
        r"_AN_aaa_method[\s\S]{0,4096}?[\"']name[\"']\s*:\s*[\"']([^\"']+)",
        text)
    return match.group(1) if match else None


def parse_an_login(text):
    info = {
        "version": 1 if "_AN_aaa_otp_version" in text else 0,
        "client_security": False,
        "favorite": "",
        "interval": 30,
        "method": _parse_method_name(text),
    }
    value = _js_value(text, "_AN_clientsecurity_on")
    if value is not None and value.lower() == "true":
        info["client_security"] = True
    value = _js_value(text, "_AN_favorite_name")
    if value:
        info["favorite"] = _unquote(value)
    value = _js_value(text, "_AN_dyncode_interval")
    if value is not None:
        try:
            info["interval"] = clamp_interval(int(value.strip().strip("\"'")))
        except ValueError:
            pass
    return info


def parse_setup_data(xml_text):
    chosen = None
    chosen_name = ""
    for tag in re.findall(r"<Device\b[^>]*>", xml_text, re.I):
        attrs = {}
        for key, value in re.findall(r"([\w:.-]+)\s*=\s*\"([^\"]*)\"", tag):
            attrs[key.lower()] = html.unescape(value)
        success = attrs.get("successurl", "")
        name = attrs.get("name", "")
        if success and (not chosen or chosen_name.lower() == "default"):
            chosen = success
            chosen_name = name
    if not chosen:
        return None
    index = chosen.find("data=")
    if index < 0:
        return None
    return chosen[index + 5:]


def parse_cookie_error(set_cookies):
    for cookie in set_cookies:
        match = re.search(r"_AN_msgID=(\d+)", cookie)
        if match:
            return int(match.group(1))
    return None


def parse_body_error(text):
    match = re.search(r"_AN_msg_id\s*=\s*[\"']?(\d+)", text)
    return int(match.group(1)) if match else None


ERROR_HINTS = {
    202: "用户名或密码错误",
    203: "用户名或密码错误",
    205: "用户名或密码错误",
    206: "用户名或密码错误",
    207: "用户名或密码错误",
    214: "用户名或密码错误",
    215: "用户名或密码错误",
    758: "令牌材料不匹配（密码或种子不正确）",
    805: "该用户名已绑定动态码，服务器未开启“动态码重复绑定”；"
         "原版 APP 换机也会被拒。请管理员解绑，或在 AG 上开启"
         "动态码重复绑定（新凭据会替换旧凭据）后重试",
    10000: "网络错误",
    10002: "服务器配置错误",
    10003: "服务器未提供注册方法",
}


def describe_error(code):
    hint = ERROR_HINTS.get(code)
    return "：%s" % hint if hint else ""


def _now_ms():
    return int(time.time() * 1000)


def _to_int32(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def fetch_server_time(host, verify_tls=False):
    response = http_request(host, "GET", AN_PREFIX + "/system-time",
                            verify_tls=verify_tls)
    if response["status"] != 200:
        raise NetError("获取服务器时间失败：HTTP %d" % response["status"])
    match = re.search(r"<time>\s*(\d+)\s*</time>", response["text"])
    if not match:
        raise NetError("服务器时间响应中未找到 <time> 字段")
    value = int(match.group(1))
    if value < 10000000000:          # 与 e.k() 一致：10 位按秒处理
        value *= 1000
    return value


def sync_offset(host, verify_tls=False):
    before = _now_ms()
    server = fetch_server_time(host, verify_tls=verify_tls)
    after = _now_ms()
    return _to_int32(server - (before + after) // 2)


def _http_checks(address):
    scheme, host, favorite = parse_address(address)
    if scheme and scheme != "https":
        raise ToolError("原 APP 只允许 https:// 地址（输入中可省略协议）")
    if not host:
        raise ToolError("服务器地址为空")
    return host, favorite


def provision(address, username, password, interval_override=None, seed=None,
              do_sync=True, verify_tls=False):
    host, favorite = _http_checks(address)
    seed = seed if seed is not None else os.urandom(10)
    sm = b32encode(seed)
    cookie = "ANStandalone=true;"

    response = http_request(host, "GET", AN_PREFIX + "/an_login.js",
                            cookie=cookie, verify_tls=verify_tls)
    if response["status"] == 200:
        info = parse_an_login(response["text"])
    else:
        print("警告: an_login.js 返回 HTTP %d，使用默认参数继续" % response["status"],
              file=sys.stderr)
        info = parse_an_login("")

    method = info["method"]
    version = info["version"]
    _debug("an_login.js: version=%d method=%s interval=%d client_security=%s" %
           (version, method, info["interval"], info["client_security"]))
    if version == 1:
        register_page = http_request(host, "GET", AN_PREFIX + "/register",
                                     cookie=cookie, verify_tls=verify_tls)
        if register_page["status"] == 200:
            method = _parse_method_name(register_page["text"]) or method
            _debug("register 页 method=%s" % method)

    if info["client_security"]:
        fav = info["favorite"] or favorite
        setup_path = "%s/client_sec/%s/setup.xml" % (
            AN_PREFIX, urllib.parse.quote(fav, safe=""))
        setup = http_request(host, "GET", setup_path,
                             cookie=cookie, verify_tls=verify_tls)
        data = parse_setup_data(setup["text"]) if setup["status"] == 200 else None
        if data is None:
            raise ToolError("服务器启用了客户端安全策略，但 setup.xml 中未找到 data= 参数")
        cookie = ("ANStandalone=true;NSCOOKIE%3Blocalhost%3B%2F%3B"
                  "AN_CLIENTSEC=" + data)

    if not method:
        raise ToolError("未能从服务器获取登录方法名（an_login.js / register 解析失败）")

    endpoint = AN_PREFIX + ("/register" if version else "/login")
    _debug("注册字段: method=%s sm_len=%d" % (method, len(sm)))
    body = "method=%s&uname=%s&pwd=%s&sm=%s" % (
        method,
        urllib.parse.quote(username, safe=""),
        urllib.parse.quote(password, safe=""),
        sm,
    )
    response = http_request(host, "POST", endpoint, body=body,
                            cookie=cookie, verify_tls=verify_tls)

    if response["status"] == 302:
        location = response["header"]("Location") or ""
        if "welcome" in location:
            pass
        elif "login" in location:
            code = parse_cookie_error(response["set_cookies"])
            raise ToolError("认证被拒绝（服务器错误码 %s）%s" %
                            (code if code is not None else "未知",
                             describe_error(code)))
        else:
            raise ToolError("服务器返回意外跳转：%s" % location)
    else:
        code = parse_body_error(response["text"])
        if code is None:
            code = response["status"]
        _debug("POST 响应片段: %s" % response["text"][:600].replace("\n", " "))
        raise ToolError("注册失败：HTTP %d，错误码 %s%s" %
                        (response["status"], code, describe_error(code)))

    if interval_override is not None:
        interval = clamp_interval(interval_override)
    else:
        interval = clamp_interval(info["interval"])

    offset = 0
    if do_sync:
        try:
            offset = sync_offset(host, verify_tls=verify_tls)
        except NetError as exc:
            print("警告: 时间同步失败，offset 置 0（%s）" % exc, file=sys.stderr)

    return {
        "address": normalize_address(address),
        "seed_b32": b32encode(seed),
        "interval": interval,
        "offset_ms": offset,
        "username": username,
        "created_at": int(time.time()),
        "source": "app-login",
        "method": method,
        "otp_version": version,
        "client_security": info["client_security"],
    }


# --------------------------------------------------------------------------
# Android otp.db 导入
# --------------------------------------------------------------------------

def _aes_cbc_decrypt(blob):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        openssl = shutil.which("openssl")
        if not openssl:
            raise ToolError(
                "导入数据库需要 cryptography 库或 openssl 命令（pip install cryptography）")
        process = subprocess.run(
            [openssl, "enc", "-d", "-aes-256-cbc",
             "-K", DB_AES_KEY.hex(), "-iv", DB_AES_IV.hex()],
            input=blob, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode != 0:
            raise ToolError("openssl 解密失败: %s" %
                            process.stderr.decode("utf-8", "replace").strip())
        return process.stdout
    try:
        cipher = Cipher(algorithms.AES(DB_AES_KEY), modes.CBC(DB_AES_IV))
    except TypeError:  # cryptography < 3.1 需要显式 backend
        from cryptography.hazmat.backends import default_backend
        cipher = Cipher(algorithms.AES(DB_AES_KEY), modes.CBC(DB_AES_IV),
                        backend=default_backend())
    decryptor = cipher.decryptor()
    plain = decryptor.update(blob) + decryptor.finalize()
    if plain:
        pad = plain[-1]
        if 1 <= pad <= 16 and plain.endswith(bytes([pad]) * pad):
            plain = plain[:-pad]
    return plain


def extract_android_backup(path):
    """从 adb backup (.ab) 中取出 otp.db，返回 (db_path, temp_dir)。"""
    with open(path, "rb") as fh:
        if fh.readline().strip() != b"ANDROID BACKUP":
            return None
        fh.readline()  # version
        compressed = fh.readline().strip() == b"1"
        algorithm = fh.readline().strip().decode("ascii", "replace").lower()
        if algorithm != "none":
            raise ToolError("暂不支持加密的 adb backup，请使用无密码备份")
        payload = fh.read()
    if compressed:
        try:
            payload = zlib.decompress(payload)
        except zlib.error as exc:
            raise ToolError("adb backup 解压失败: %s" % exc)
    temp_dir = tempfile.mkdtemp(prefix="motionpro-backup-")
    target = os.path.join(temp_dir, "otp.db")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for member in archive.getmembers():
                if member.isfile() and os.path.basename(member.name) == "otp.db":
                    source = archive.extractfile(member)
                    with open(target, "wb") as out:
                        shutil.copyfileobj(source, out)
                    return target, temp_dir
    except (tarfile.TarError, OSError) as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise ToolError("解析 adb backup 失败: %s" % exc)
    shutil.rmtree(temp_dir, ignore_errors=True)
    raise ToolError("adb backup 中未找到 otp.db")


def detect_input_kind(path):
    with open(path, "rb") as fh:
        head = fh.read(16)
    if head.startswith(b"ANDROID BACKUP"):
        return "backup"
    if head.startswith(b"SQLite format 3\x00"):
        return "database"
    return "json"


def read_otp_database(db_path):
    uri = urllib.parse.urljoin("file:", urllib.parse.quote(os.path.abspath(db_path)))
    try:
        conn = sqlite3.connect(uri + "?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise ToolError("无法打开数据库 %s: %s" % (db_path, exc))
    try:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(servers)")]
        if not columns:
            raise ToolError("数据库中不存在 servers 表，可能不是 MotionProOTP 的数据")
        has_interval = "dynamic_interval" in columns
        query = "SELECT address, data, time_differ%s FROM servers" % (
            ", dynamic_interval" if has_interval else "")
        rows = list(conn.execute(query))
    except sqlite3.Error as exc:
        raise ToolError("读取数据库失败: %s" % exc)
    finally:
        conn.close()

    sites = []
    failed = 0
    for row in rows:
        address, blob, time_differ = row[0], row[1], row[2]
        interval = row[3] if has_interval and len(row) > 3 else 30
        if not address or not blob:
            failed += 1
            print("跳过空记录: %s" % address, file=sys.stderr)
            continue
        try:
            seed = _aes_cbc_decrypt(bytes(blob))
            if not 1 <= len(seed) <= 256:
                raise ToolError("解密后的种子长度异常 (%d)" % len(seed))
        except ToolError as exc:
            failed += 1
            print("解密失败 %s: %s" % (address, exc), file=sys.stderr)
            continue
        sites.append({
            "address": address,
            "seed_b32": b32encode(seed),
            "interval": clamp_interval(interval),
            "offset_ms": int(time_differ or 0),
            "created_at": int(time.time()),
            "source": "apk-db",
        })
    return sites, failed


def load_sites_from_input(input_path):
    """只读加载 JSON 配置、裸 otp.db 或 adb backup，返回 (sites, kind, failed)。"""
    path = os.path.abspath(os.path.expanduser(input_path))
    if not os.path.isfile(path):
        raise ToolError("输入文件不存在或不是普通文件: %s" % path)
    try:
        kind = detect_input_kind(path)
    except OSError as exc:
        raise ToolError("无法读取输入文件 %s: %s" % (path, exc))
    if kind == "json":
        return load_config(path)["sites"], kind, 0

    temp_dir = None
    if kind == "backup":
        db_path, temp_dir = extract_android_backup(path)
        if not db_path:
            raise ToolError("不是有效的 adb backup 文件: %s" % path)
    else:
        db_path = path
    try:
        sites, failed = read_otp_database(db_path)
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
    return sites, kind, failed


def import_database(input_path, output_path, skip_existing=False):
    sites, _, failed = load_sites_from_input(input_path)
    output_path = normalize_config_path(output_path)
    config = load_config_for_write(output_path)
    imported = 0
    skipped = 0
    for site in sites:
        duplicate = any(s["address"].casefold() == site["address"].casefold()
                        for s in config["sites"])
        if duplicate and skip_existing:
            skipped += 1
            print("已存在，跳过: %s" % site["address"])
            continue
        upsert_site(config, site, force=True)
        imported += 1
        print("写入 %-36s" % site["address"])
    if imported:
        save_config(output_path, config)
    elif skipped:
        print("所有站点均已存在，未修改: %s" % output_path)
    elif failed:
        raise ToolError("没有可导入的站点（%d 条记录读取失败）" % failed)
    else:
        raise ToolError("输入文件中没有任何站点")
    return imported, skipped, failed


# --------------------------------------------------------------------------
# 子命令
# --------------------------------------------------------------------------

def cmd_otp(args):
    sites, _, failed = load_sites_from_input(args.input_path)
    if not sites:
        if failed:
            raise ToolError("输入中没有可用站点（%d 条记录读取失败）" % failed)
        raise ToolError("输入文件中没有任何站点")
    at = args.at
    if not args.all:
        sites = [find_site(sites, args.site)]

    def collect():
        results = []
        for site in sites:
            code, remaining, interval, seconds = site_state(site, at)
            results.append({
                "address": site["address"],
                "code": "%06d" % code,
                "display": format_code(code),
                "remaining": remaining,
                "interval": interval,
                "offset_ms": int(site.get("offset_ms", 0)),
                "counter_time": seconds,
            })
        return results

    if args.json:
        print(json.dumps(collect(), ensure_ascii=False, indent=2))
        return 0
    if args.raw:
        if len(sites) != 1:
            raise ToolError("--raw 只能用于单个站点")
        print("%06d" % site_state(sites[0], at)[0])
        return 0

    if args.watch:
        clear = sys.stdout.isatty()
        try:
            while True:
                results = collect()
                if clear:
                    sys.stdout.write("\x1b[2J\x1b[H")
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                for item in results:
                    print("%-32s  %s   剩余 %2ds" % (
                        item["address"], item["display"], item["remaining"]))
                    if item["offset_ms"]:
                        print("%-32s  服务器时间偏移 %+d ms" % ("", item["offset_ms"]))
                print("\n%s  (Ctrl+C 退出)" % stamp)
                sys.stdout.flush()
                time.sleep(max(0.1, 1.0 - (time.time() % 1.0)))
        except KeyboardInterrupt:
            print()
            return 0

    for item in collect():
        print("%-32s  %s   剩余 %2ds" % (
            item["address"], item["display"], item["remaining"]))
    return 0


def cmd_add(args):
    config_path = normalize_config_path(args.config) if args.config else None
    if config_path is None and not sys.stdin.isatty():
        raise ToolError("未指定配置文件路径，且当前不是交互式终端；"
                        "请把 CONFIG 作为参数传入")

    config = None
    if config_path:
        config = load_config_for_write(config_path)
        existing = next((s for s in config["sites"]
                         if s["address"].casefold()
                         == normalize_address(args.address).casefold()), None)
        if existing and not args.force:
            raise ToolError("站点已存在：%s（使用 --force 覆盖）" % existing["address"])

    if not args.username:
        args.username = input("用户名: ").strip()
    if not args.username:
        raise ToolError("用户名不能为空")
    if not args.password:
        args.password = getpass.getpass("密码: ")
    if not args.password:
        raise ToolError("密码不能为空")

    seed = None
    if args.seed:
        seed = parse_seed(args.seed)

    print("正在与 %s 执行 OTP 注册（TLS 证书校验：%s）..." %
          (args.address, "开启" if args.verify_tls else "关闭（与原 APP 一致）"),
          file=sys.stderr)
    site = provision(
        args.address, args.username, args.password,
        interval_override=args.interval,
        seed=seed,
        do_sync=not args.no_sync,
        verify_tls=args.verify_tls,
    )
    code, remaining, _, _ = site_state(site)
    print("注册成功: %s" % site["address"])
    print("当前口令: %s   剩余 %ds" % (format_code(code), remaining))

    if config is None:
        print("请选择配置文件保存路径；若取消或写入失败，本次注册的种子将丢失。",
              file=sys.stderr)
        try:
            config_path = prompt_config_path("注册已完成，请选择配置文件保存路径")
            config = load_config_for_write(config_path)
        except (ToolError, KeyboardInterrupt):
            print("警告: 注册已完成，但配置未保存；本次种子只存在于内存中，"
                  "进程退出后无法恢复。若要继续使用该账号，"
                  "请联系管理员重置后重新注册。", file=sys.stderr)
            raise
        existing = next((s for s in config["sites"]
                         if s["address"].casefold() == site["address"].casefold()), None)
        if existing:
            print("注意: 配置中已有站点 %s，将用本次注册的种子覆盖" %
                  existing["address"], file=sys.stderr)

    upsert_site(config, site, force=True)
    try:
        save_config(config_path, config)
    except ToolError:
        print("警告: 注册已完成但配置写入失败；本次种子只存在于内存中，"
              "进程退出后无法恢复。若要继续使用该账号，"
              "请联系管理员重置后重新注册。", file=sys.stderr)
        raise
    print("配置文件: %s" % config_path)
    return 0


def parse_seed(text):
    value = text.strip()
    if value.startswith("hex:"):
        try:
            return bytes.fromhex(value[4:])
        except ValueError as exc:
            raise ToolError("无效的十六进制种子: %s" % exc)
    if value.startswith("b64:"):
        try:
            return base64.b64decode(value[4:], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ToolError("无效的 Base64 种子: %s" % exc)
    if value.startswith("b32:"):
        value = value[4:]
    elif value.startswith("0x"):
        try:
            return bytes.fromhex(value[2:])
        except ValueError as exc:
            raise ToolError("无效的十六进制种子: %s" % exc)
    return b32decode(value)


def cmd_add_seed(args):
    seed = parse_seed(args.seed)
    if not 1 <= len(seed) <= 256:
        raise ToolError("种子长度必须在 1..256 字节之间")
    config_path = (normalize_config_path(args.config) if args.config
                   else prompt_config_path())
    config = load_config_for_write(config_path)
    existing = next((s for s in config["sites"]
                     if s["address"].casefold() == normalize_address(args.address).casefold()),
                    None)
    if existing and not args.force:
        raise ToolError("站点已存在：%s（使用 --force 覆盖）" % existing["address"])
    site = {
        "address": normalize_address(args.address),
        "seed_b32": b32encode(seed),
        "interval": clamp_interval(args.interval),
        "offset_ms": int(args.offset_ms),
        "username": args.username or "",
        "created_at": int(time.time()),
        "source": "manual",
    }
    upsert_site(config, site, force=True)
    save_config(config_path, config)
    code, remaining, _, _ = site_state(site)
    print("已保存站点: %s" % site["address"])
    print("当前口令: %s   剩余 %ds" % (format_code(code), remaining))
    print("配置文件: %s" % config_path)
    return 0


def cmd_sync(args):
    config = load_writable_config(args.config)
    if args.all:
        sites = config["sites"]
    else:
        sites = [find_site(config["sites"], args.site)]
    if not sites:
        raise ToolError("还没有任何站点")
    failed = 0
    for site in sites:
        host, _ = _http_checks(site["address"])
        try:
            offset = sync_offset(host, verify_tls=args.verify_tls)
        except NetError as exc:
            print("%-32s 同步失败: %s" % (site["address"], exc), file=sys.stderr)
            failed += 1
            continue
        old = int(site.get("offset_ms", 0))
        site["offset_ms"] = offset
        code, remaining, _, _ = site_state(site)
        print("%-32s 偏移 %+d ms（原 %+d）  当前口令 %s  剩余 %ds" % (
            site["address"], offset, old, format_code(code), remaining))
    save_config(args.config, config)
    return 1 if failed else 0


def cmd_import_db(args):
    output_path = normalize_config_path(args.output_path)
    imported, skipped, failed = import_database(
        args.input_path, output_path, skip_existing=args.skip_existing)
    print("已写入 %s: 新增/更新 %d，跳过 %d，失败 %d" %
          (output_path, imported, skipped, failed))
    print("查看口令: otp -i %s" % output_path)
    return 0


def cmd_list(args):
    sites, kind, failed = load_sites_from_input(args.input_path)
    labels = {"json": "JSON 配置", "database": "otp.db", "backup": "adb backup"}
    path = os.path.abspath(os.path.expanduser(args.input_path))
    print("文件: %s (%s)" % (path, labels[kind]))
    if not sites:
        if failed:
            print("没有可用站点（%d 条记录读取失败）" % failed)
            return 1
        print("输入文件中没有任何站点")
        return 0
    for index, site in enumerate(sites, 1):
        code, remaining, _, _ = site_state(site)
        seed = site["seed_b32"] if args.show_secrets else mask_seed(site["seed_b32"])
        print("[%d] %s" % (index, site["address"]))
        print("    口令 %s  剩余 %2ds  间隔 %ds  偏移 %+d ms" % (
            format_code(code), remaining,
            clamp_interval(site.get("interval", 30)),
            int(site.get("offset_ms", 0))))
        print("    种子 %s%s" % (seed, "" if args.show_secrets else
                                  "（--show-secrets 查看）"))
        if site.get("username"):
            print("    用户 %s" % site["username"])
    if failed:
        print("警告: %d 条记录读取失败" % failed, file=sys.stderr)
    return 0


def cmd_remove(args):
    config = load_writable_config(args.config)
    site = find_site(config["sites"], args.site)
    if not args.yes:
        answer = input("确认删除站点 %s ? [y/N] " % site["address"]).strip().lower()
        if answer not in ("y", "yes"):
            print("已取消")
            return 0
    config["sites"] = [s for s in config["sites"] if s is not site]
    save_config(args.config, config)
    print("已删除: %s" % site["address"])
    return 0


# 由 Unicorn 模拟 libvpn.so 得到的向量：(seed_hex, unix_time, interval, expected)
NATIVE_VECTORS = [
    ("00010203040506070809", 1626000000, 30, 248254),
    ("deadbeefcafebabe1234", 1626000030, 60, 331289),
    ("ffffffffffffffffffff", 2000000000, 90, 500795),
    ("31323334353637383930", 1610000000, 300, 182443),
    ("0123456789abcdef0123", 1750000000, 10, 711951),
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1700000000, 1000, 678496),
    ("00", 0, 30, 328482),
    ("5a5a5a5a5a", 4294967290, 30, 317956),
]


def cmd_selftest(args):
    failures = 0
    for seed_hex, seconds, interval, expected in NATIVE_VECTORS:
        actual = hotp(bytes.fromhex(seed_hex), seconds, interval)
        status = "OK" if actual == expected else "FAIL"
        if actual != expected:
            failures += 1
        print("%s  seed=%-32s t=%d int=%d  code=%06d (expect %06d)" % (
            status, seed_hex, seconds, interval, actual, expected))
    encoded = b32encode(bytes.fromhex("00010203040506070809"))
    if encoded != "AAAQEAYEAUDAOCAJ":
        failures += 1
        print("FAIL  Base32: %s" % encoded)
    else:
        print("OK    Base32(00010203040506070809) = %s" % encoded)
    print("自检%s" % ("通过" if failures == 0 else "失败: %d 项" % failures))
    return 0 if failures == 0 else 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    epilog = """示例:
  %(prog)s otp -i ./sites.json
  %(prog)s otp -i /path/to/otp.db --watch
  %(prog)s otp -i backup.ab --all --json
  %(prog)s list -i backup.ab
  %(prog)s import-db -i backup.ab -o ./sites.json
  %(prog)s add vpn.example.com ./sites.json -u alice
  %(prog)s add vpn.example.com -u alice            # 登录成功后再选择保存路径
  %(prog)s sync ./sites.json
  %(prog)s add-seed vpn.example.com ./sites.json --seed b32:JBSWY3DPEHPK3PXP
  %(prog)s remove ./sites.json vpn.example.com
  %(prog)s selftest

-i 直接读取 JSON 配置、裸 otp.db 或 adb backup (.ab)，只读且无需先导入；
对 .ab/otp.db 生成口令不会修改原文件。import-db 仅用于把解密结果持久化为 JSON，
写入 -o 指定的文件。CONFIG 为 JSON 明文配置（含种子，建议权限 0600），
没有默认路径，脚本不会在用户目录自动创建任何文件。
种子格式: 默认 Base32（同 APP 的 sm 参数），也支持 hex:、b64:、0x 前缀。
"""
    parser = argparse.ArgumentParser(
        prog="motionpro-otp",
        description="MotionPro OTP v2.9 的 Linux 兼容实现（HOTP-SHA1，与原 APP 输出一致）",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--debug", action="store_true", help="打印 HTTP 调试信息")
    sub = parser.add_subparsers(dest="cmd")

    config_help = "配置文件路径（JSON，含明文种子）"
    input_help = "JSON 配置、裸 otp.db 或 adb backup (.ab) 文件"

    p = sub.add_parser("otp", help="从 JSON / otp.db / .ab 生成动态口令（只读）")
    p.add_argument("-i", "--input", dest="input_path", required=True,
                   metavar="FILE", help=input_help)
    p.add_argument("site", nargs="?", help="站点地址/序号/子串（单站点可省略）")
    p.add_argument("--at", type=int, help="指定 UNIX 时间戳（仍叠加时间偏移）")
    p.add_argument("--watch", action="store_true", help="持续刷新并显示剩余秒数")
    p.add_argument("--all", action="store_true", help="显示全部站点")
    p.add_argument("--raw", action="store_true", help="只输出 6 位数字")
    p.add_argument("--json", action="store_true", help="JSON 输出")

    p = sub.add_parser("add", help="向服务器注册新站点（等价于 APP 登录注册）")
    p.add_argument("address", help="服务器地址，如 vpn.example.com 或 https://vpn.example.com")
    p.add_argument("config", nargs="?", metavar="CONFIG",
                   help="要写入的 JSON 配置；省略则在登录成功后询问保存位置")
    p.add_argument("-u", "--username", help="用户名")
    p.add_argument("-p", "--password", help="密码（省略则交互输入）")
    p.add_argument("--interval", type=int, help="覆盖服务器下发的口令间隔（30..300）")
    p.add_argument("--seed", help="使用指定种子注册（默认本地随机生成 10 字节）")
    p.add_argument("--no-sync", action="store_true", help="注册后不做时间同步")
    p.add_argument("--force", action="store_true", help="覆盖已存在的站点")
    p.add_argument("--verify-tls", action="store_true",
                   help="校验服务器证书（默认关闭，与原 APP 行为一致）")

    p = sub.add_parser("add-seed", help="手动导入种子建立离线站点")
    p.add_argument("address", help="站点名称/服务器地址")
    p.add_argument("config", nargs="?", metavar="CONFIG",
                   help="要写入的 JSON 配置；省略则询问保存位置")
    p.add_argument("--seed", required=True, help="种子（Base32/hex:/b64:/0x）")
    p.add_argument("--interval", type=int, default=30, help="口令间隔秒数，默认 30")
    p.add_argument("--offset-ms", type=int, default=0, help="服务器时间偏移（毫秒）")
    p.add_argument("--username", help="备注用户名")
    p.add_argument("--force", action="store_true", help="覆盖已存在的站点")

    p = sub.add_parser("sync", help="从服务器同步时间偏移（仅 JSON 配置）")
    p.add_argument("config", metavar="CONFIG",
                   help="可写的 JSON 配置文件路径")
    p.add_argument("site", nargs="?", help="站点地址/序号/子串")
    p.add_argument("--all", action="store_true", help="同步全部站点")
    p.add_argument("--verify-tls", action="store_true", help="校验服务器证书")

    p = sub.add_parser("import-db",
                       help="将 .ab/otp.db 解密并保存为 JSON 配置（可选）")
    p.add_argument("-i", "--input", dest="input_path", required=True, metavar="FILE",
                   help="otp.db 或 adb backup (.ab) 文件（仅接受文件，不接受目录）")
    p.add_argument("-o", "--output", dest="output_path", required=True,
                   metavar="CONFIG",
                   help="要写入的 JSON 配置（不存在则创建，已存在则合并）")
    p.add_argument("--skip-existing", action="store_true", help="已存在站点时不覆盖")

    p = sub.add_parser("list", help="列出 JSON / otp.db / .ab 中的站点（只读）")
    p.add_argument("-i", "--input", dest="input_path", required=True,
                   metavar="FILE", help=input_help)
    p.add_argument("--show-secrets", action="store_true", help="显示完整种子")

    p = sub.add_parser("remove", help="删除 JSON 配置中的站点")
    p.add_argument("config", metavar="CONFIG", help=config_help)
    p.add_argument("site", help="站点地址/序号/子串")
    p.add_argument("--yes", action="store_true", help="不询问确认")

    sub.add_parser("selftest", help="用内置 native 向量自检算法")
    return parser


def main(argv=None):
    global DEBUG
    parser = build_parser()
    args = parser.parse_args(argv)
    DEBUG = args.debug

    if args.cmd is None:
        parser.print_help(sys.stderr)
        print("\n错误: 请指定子命令；脚本不会使用任何默认配置路径",
              file=sys.stderr)
        return 2

    handlers = {
        "otp": cmd_otp,
        "add": cmd_add,
        "add-seed": cmd_add_seed,
        "sync": cmd_sync,
        "import-db": cmd_import_db,
        "list": cmd_list,
        "remove": cmd_remove,
        "selftest": cmd_selftest,
    }
    try:
        return handlers[args.cmd](args)
    except ToolError as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已取消", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
