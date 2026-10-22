# motionpro-otp

在 Linux 上生成 **Array Networks MotionPro OTP** 动态口令的命令行工具。

本项目是对 Android 应用 **MotionProOTP v2.9** 的独立兼容实现，口令算法、时间同步
和站点注册流程均与原 APK 对齐。它可以直接读取手机导出的 `.ab` 备份或
`otp.db` 数据库，也可以读取解密后的 JSON 配置；无需 Android 模拟器，无需
Root（导出备份时除外），也不需要 Google 服务。

> 本项目与 Array Networks 没有任何关系，也未获得其授权或支持。
> 请仅在你本人拥有合法授权的 VPN 环境中使用。

---

## 特性

- **直接读取，无需导入**：`-i` 支持 adb backup（`.ab`）、裸 `otp.db`、JSON 配置
- **生成口令只依赖 Python 标准库**
- 支持实时刷新、只输出 6 位数字、JSON 输出，方便与其他工具组合
- 可在 Linux 上完成原 APP 的 OTP 注册（`add`）
- 可手动导入已有种子（`add-seed`），换机或迁移时无需重新注册
- 可向服务器同步时间偏移（`sync`）
- **没有默认配置路径**：脚本不会在你的家目录里自动创建或读取任何文件，
  所有路径都必须由你显式指定
- 配置文件以 `0600` 权限写入

## 环境要求

- Linux（macOS 理论上可用，但未测试；Windows 未测试）
- Python 3.8 或更新版本
- 可选依赖，仅在读取 `.ab` / `otp.db` 时需要：
  - Python `cryptography` 库，或
  - 系统 `openssl` 命令

```bash
# 方案一：安装 cryptography
pip install cryptography

# 方案二：使用系统自带的 openssl（多数发行版已安装）
openssl version
```

只使用 JSON 配置生成动态码时，不需要任何第三方依赖。

## 安装

```bash
git clone https://github.com/Homio/motionpro-otp.git
cd motionpro-otp
chmod +x motionpro_otp.py
./motionpro-otp selftest
```

仓库中的 `motionpro-otp` 是指向 `motionpro_otp.py` 的符号链接。也可以直接运行：

```bash
python3 motionpro_otp.py --help
```

## 快速开始

### 方式一：直接从手机备份生成动态码

1. 在手机上打开 USB 调试，连接电脑，并确认 `adb devices` 能看到设备。
2. 如果不知道包名，可以先查找：

   ```bash
   adb shell pm list packages | grep -i arraynetworks
   ```

3. 执行备份（不要设置备份密码）：

   ```bash
   adb backup -f motionpro-otp.ab -noapk com.arraynetworks.authentication
   ```

   然后在手机屏幕上点击“备份我的数据”。

4. 直接读取备份文件：

   ```bash
   ./motionpro-otp list -i motionpro-otp.ab
   ./motionpro-otp otp -i motionpro-otp.ab
   ```

`otp -i` 对 `.ab` / `otp.db` 是只读操作，不会修改原文件，也不会生成中间配置。
脚本只在 `/tmp` 下临时解包，并在读取完成后立即删除。

> **备份为空或提示备份被禁用？**
> 部分 Android 版本或厂商 ROM 限制了 `adb backup`。如果你有 Root 权限，也可以
> 直接取出数据库：
>
> ```bash
> adb exec-out su -c 'cat /data/data/com.arraynetworks.authentication/databases/otp.db' > otp.db
> ./motionpro-otp otp -i otp.db
> ```
>
> 加密的 adb backup（设置了备份密码）暂不支持，请重新导出无密码备份。

### 方式二：使用 JSON 配置

```bash
./motionpro-otp otp -i ./sites.json
```

有多个站点时需要指定站点（地址、序号或子串）：

```bash
./motionpro-otp otp -i ./sites.json vpn.example.com
./motionpro-otp otp -i ./sites.json 1
```

### 常用输出选项

```bash
# 持续刷新，显示剩余秒数
./motionpro-otp otp -i ./sites.json --watch

# 只输出单个站点的 6 位数字，适合脚本调用
./motionpro-otp otp -i ./sites.json vpn.example.com --raw

# 显示全部站点
./motionpro-otp otp -i ./sites.json --all

# JSON 输出
./motionpro-otp otp -i ./sites.json --all --json

# 查看指定时间点的动态码（仍然叠加 offset_ms）
./motionpro-otp otp -i ./sites.json --at 1760000000
```

`otp` 的默认输出类似：

```text
vpn.example.com                  32 02 10   剩余 17s
```

`--raw` 输出的是去掉空格后的 6 位数字，例如 `320210`。

---

## 命令参考

### `otp` — 生成动态口令（只读）

```text
motionpro-otp otp -i FILE [site] [--at AT] [--watch] [--all] [--raw] [--json]
```

| 参数 | 说明 |
| --- | --- |
| `-i, --input FILE` | JSON 配置、裸 `otp.db` 或 `.ab` 备份 |
| `site` | 站点地址、序号（从 1 开始）或子串；只有一个站点时可省略 |
| `--at AT` | 指定 UNIX 时间戳，仍会叠加配置中的服务器时间偏移 |
| `--watch` | 每秒刷新，显示剩余秒数；`Ctrl+C` 退出 |
| `--all` | 显示全部站点 |
| `--raw` | 只输出 6 位数字，仅限单个站点 |
| `--json` | 输出 JSON 数组 |

### `add` — 向服务器注册新站点

等价于原 APP 的“登录并绑定动态码”流程。

```bash
# 交互输入密码；成功后询问配置保存路径
./motionpro-otp add vpn.example.com -u alice

# 直接指定配置文件
./motionpro-otp add vpn.example.com ./sites.json -u alice
```

| 参数 | 说明 |
| --- | --- |
| `address` | 服务器地址，如 `vpn.example.com` 或 `https://vpn.example.com` |
| `CONFIG` | 可选，要写入的 JSON 配置；省略则注册成功后询问 |
| `-u, --username` | 用户名 |
| `-p, --password` | 密码；省略则交互输入 |
| `--interval` | 覆盖服务器下发的口令间隔（限制为 30..300 秒） |
| `--seed` | 使用指定种子注册；默认在本地随机生成 10 字节 |
| `--no-sync` | 注册后不进行时间同步 |
| `--force` | 覆盖本地配置中已存在的同名站点 |
| `--verify-tls` | 校验证书；默认关闭，与原 APP 行为一致 |

注意事项：

- 服务器通常只允许一个用户名绑定一份 OTP 凭据。已绑定过的账号再次注册会收到
  **错误码 805**，需要管理员在服务器端解绑。`--force` 只覆盖本地配置，不会解绑服务器。
- 如果手机上的原 APP 还能使用，优先导出 `.ab` / `otp.db`，不要重新注册。
- 注册成功后如果取消保存路径，本次生成的种子只存在于内存中，退出后无法恢复；
  此时需要管理员重置后重新注册。
- 注册使用 `https`，与原 APP 一样默认不校验证书。若服务器证书链正常，建议加上
  `--verify-tls`，避免密码和种子被中间人截获。

### `add-seed` — 手动导入种子

已经拥有种子时使用，不需要连接服务器，也不会改变服务器绑定关系。

```bash
./motionpro-otp add-seed vpn.example.com ./sites.json \
  --seed b32:JBSWY3DPEHPK3PXP --interval 30
```

| 参数 | 说明 |
| --- | --- |
| `address` | 站点名称/服务器地址 |
| `CONFIG` | 可选，省略则询问保存位置 |
| `--seed` | 必填，种子（格式见下文） |
| `--interval` | 口令间隔秒数，默认 30（限制 30..300） |
| `--offset-ms` | 服务器时间偏移（毫秒），默认 0 |
| `--username` | 可选的用户名备注 |
| `--force` | 覆盖已存在的站点 |

种子格式：

- 默认 Base32，与 APP 的 `sm` 参数一致；可带 `b32:` 前缀
- `hex:` 或 `0x` 前缀的十六进制
- `b64:` 前缀的 Base64

### `import-db` — 将数据库解密并保存为 JSON（可选）

```bash
./motionpro-otp import-db -i motionpro-otp.ab -o ./sites.json
./motionpro-otp import-db -i otp.db -o ./sites.json --skip-existing
```

`import-db` **不是**生成口令的前置步骤。它只用于把解密结果持久化为 JSON 配置。
输出文件包含明文种子，请确保权限为 `0600`，不要提交到 Git。

已存在同名站点时默认覆盖，可用 `--skip-existing` 保留原记录。

### `list` — 查看站点（只读）

```bash
./motionpro-otp list -i motionpro-otp.ab
./motionpro-otp list -i ./sites.json --show-secrets
```

默认隐藏种子，仅显示首尾字符；`--show-secrets` 显示完整种子。

### `sync` — 同步服务器时间偏移

```bash
./motionpro-otp sync ./sites.json
./motionpro-otp sync ./sites.json --all
./motionpro-otp sync ./sites.json --verify-tls
```

动态码依赖服务器时间。如果本机时钟准确但动态码总被拒绝，可以尝试同步一次；服务器
时间偏移会写回 JSON 配置。

> `sync` 需要可写的 JSON 配置，不支持直接写回 `.ab` / `otp.db`。

### `remove` — 删除 JSON 配置中的站点

```bash
./motionpro-otp remove ./sites.json vpn.example.com
./motionpro-otp remove ./sites.json vpn.example.com --yes
```

只删除本地配置，不会解绑服务器端凭据。

### `selftest` — 算法自检

```bash
./motionpro-otp selftest
```

使用从 `libvpn.so` 提取的测试向量校验 HOTP 结果和 Base32 编码。

---

## 配置文件格式

```json
{
  "version": 1,
  "sites": [
    {
      "address": "vpn.example.com",
      "seed_b32": "JBSWY3DPEHPK3PXP",
      "interval": 30,
      "offset_ms": 0,
      "username": "alice",
      "created_at": 1760000000,
      "source": "apk-db"
    }
  ]
}
```

| 字段 | 说明 |
| --- | --- |
| `address` | 站点地址（可能包含路径） |
| `seed_b32` | Base32 编码的种子 |
| `interval` | 口令间隔（秒），加载时会限制到 30..300 |
| `offset_ms` | 服务器时间相对本机的偏移（毫秒） |
| `username` | 可选，用户名备注 |
| `created_at` | 可选，创建时间（UNIX 秒） |
| `source` | 可选，`app-login`、`apk-db` 或 `manual` |

上例中的种子只是演示，不是有效凭据。配置文件包含**明文种子**，任何拿到它的人都能
生成你的动态码，等同于拿到第二因素。请：

```bash
chmod 600 sites.json
```

并且不要把它提交到 Git、网盘或聊天工具中。仓库的 `.gitignore` 已忽略
`sites.json`、`config.json`、`*.ab`、`*.db` 和 `.env`。

---

## 与 VPN 工具配合

本项目只负责生成动态码，不包含 VPN 客户端。若你同时使用
[motionpro-vpn](https://github.com/Homio/motionpro-vpn)，可以在自己的胶水脚本中把
两者串起来（两个项目相互独立，路径由你决定）：

```bash
#!/usr/bin/env bash
set -euo pipefail

OTP_TOOL=/opt/motionpro-otp/motionpro-otp
VPN_TOOL=/opt/motionpro-vpn/motionpro-vpn
CONFIG="$HOME/.config/motionpro/sites.json"

CODE=$("$OTP_TOOL" otp -i "$CONFIG" vpn.example.com --raw)
"$VPN_TOOL" connect -H vpn.example.com -u alice -x "$CODE"
```

动态码有时效性，建议在连接前立即生成；不要缓存后重复使用。

---

## 工作原理

- 计数器：`counter = uint32(unix_time + offset_ms/1000) / interval`
- 口令：`HOTP(HMAC-SHA1, 4 字节 0 + 4 字节大端 counter)`
- 动态截断后对 `1,000,000` 取模，补零为 6 位
- 显示时拆成三组两位数字，例如 `320210` 显示为 `32 02 10`
- interval 被限制在 30..300 秒，与原 APP 的 native 实现一致
- 注册流程复刻原 APP：读取 `an_login.js`、必要时访问 `register` 页面和
  `client_sec` 策略，然后以 `method/uname/pwd/sm` 提交注册请求
- 时间同步读取服务器的 `/system-time`，用请求前后本机时间的中点计算偏移

Android 数据库中的种子以 AES-256-CBC/PKCS5 加密保存，密钥和 IV 来自 APK 本身。
因此 `.ab` / `otp.db` 虽然看起来是加密的，也必须按敏感数据保管。

## 常见问题

**为什么直接读 `.ab` 提示需要 cryptography 或 openssl？**

JSON 配置不需要解密，只用标准库；`.ab` / `otp.db` 中的种子是 AES 加密的，需要
`pip install cryptography` 或系统 `openssl`。

**为什么注册返回 805？**

该用户名已经在服务器上绑定过动态码，服务器未开启重复绑定。请联系管理员解绑。
原版 APP 换手机时也会遇到同样的限制。

**动态码一直被服务器拒绝怎么办？**

1. 确认手机时间和本机时间都准确；
2. 执行 `./motionpro-otp sync ./sites.json`；
3. 确认 `interval` 与服务器下发值一致（通常是 30 秒）；
4. 确认使用的是当前站点的种子，且没有在别处触发过重新注册。

**能否直接读取手机目录里的 `otp.db`？**

可以，`otp -i` 支持裸 SQLite 数据库；但普通 Android 应用目录需要 Root 才能读取。
没有 Root 时请使用 `adb backup`。

**脚本会把配置写到哪里？**

不会写入任何默认位置。只有 `add` / `add-seed` / `import-db` / `sync` / `remove`
会写文件，并且路径必须由命令行参数或交互提示显式给出。

## 限制

- 只支持 HTTPS 服务器，与原 APP 一致
- 不支持设置了密码的加密 adb backup
- 只实现 MotionPro OTP 的用户名 + 密码 + 动态口令流程；不支持短信、推送等
  其他二次认证方式
- 注册能否成功取决于服务器策略和账号状态，工具无法绕过管理员的绑定限制
- 本项目不包含 VPN 隧道功能

## 安全与免责声明

- 本工具按“原样”提供，不提供任何明示或暗示的担保。
- 使用本工具可能违反你的组织内部规定。请先确认你拥有相应授权。
- 请自行保管好配置文件、`.ab` 备份和 `otp.db`；泄露种子等同于泄露动态口令。
- 默认关闭 TLS 证书校验是为了复刻原 APP 行为；在不可信网络中注册时请使用
  `--verify-tls`。
- 因账号锁定、配置丢失、服务端策略变化或误用造成的后果由使用者自行承担。

## License

[MIT](LICENSE)
