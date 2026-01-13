# SSH Init Script (Strict Single-Port Mode)

> 一句话：**修改 SSH 端口 + 写入 root 公钥 + 禁用密码登录**，并尽力处理 SELinux/本机防火墙，降低暴力破解风险，避免常见自锁。

---

## 🚀 使用方式（最先看这里）

### 方式 A：下载到本地再执行（推荐）
```bash
curl -fsSL "https://raw.githubusercontent.com/pengyuyanzu/Rule/dev/init.sh" -o init.sh \
  && chmod +x init.sh \
  && sudo ./init.sh
