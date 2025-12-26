#!/bin/bash
set -euo pipefail
IFS=$'\n\t'
export LC_ALL=C
umask 077

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

die(){ echo -e "${RED}错误：$*${NC}" >&2; exit 1; }
warn(){ echo -e "${YELLOW}⚠️  $*${NC}" >&2; }
info(){ echo -e "${BLUE}ℹ️  $*${NC}"; }
ok(){ echo -e "${GREEN}✅ $*${NC}"; }

# 0) Root + sshd 检查
[ "$(id -u)" = "0" ] || die "请使用 root 用户运行此脚本！"
command -v sshd >/dev/null 2>&1 || die "未找到 sshd，请先安装 OpenSSH Server。"

echo -e "${GREEN}=== SSH 配置安全向导 (严格单端口模式 / 防锁死增强版) ===${NC}"

MAIN_CONF="/etc/ssh/sshd_config"
[ -f "$MAIN_CONF" ] || die "找不到 $MAIN_CONF"

TS="$(date +%s)"
MAIN_BAK="${MAIN_CONF}.bak.${TS}"
cp -a "$MAIN_CONF" "$MAIN_BAK" || die "无法备份 $MAIN_CONF"

CONF_D="/etc/ssh/sshd_config.d"
DROP_IN="${CONF_D}/99-secure-custom.conf"

# --- 状态追踪：失败自动回滚（配置文件 + 尽力回滚 SELinux/防火墙/immutable + 尝试恢复服务） ---
rolled_back=0
success=0

fw_touched=0
fw_undo_cmd=""

selinux_touched=0
selinux_prev_type=""
selinux_prev_had_port=0

auth_was_immutable=0
auth_immutable_restored=0

rollback() {
  [ "$rolled_back" -eq 1 ] && return
  rolled_back=1

  warn "发生错误，正在回滚..."

  # 1) 回滚防火墙
  if [ "${fw_touched:-0}" -eq 1 ] && [ -n "${fw_undo_cmd:-}" ]; then
    warn "回滚防火墙规则..."
    sh -c "${fw_undo_cmd}" >/dev/null 2>&1 || true
  fi

  # 2) 回滚 SELinux 端口映射
  if [ "${selinux_touched:-0}" -eq 1 ] && command -v semanage >/dev/null 2>&1; then
    warn "回滚 SELinux 端口映射..."
    local p="${SSH_PORT:-0}"
    if [ "$p" -ge 1 ] 2>/dev/null; then
      if [ "${selinux_prev_had_port:-0}" -eq 0 ]; then
        semanage port -d -t ssh_port_t -p tcp "$p" >/dev/null 2>&1 || true
      else
        if [ -n "${selinux_prev_type:-}" ]; then
          semanage port -m -t "${selinux_prev_type}" -p tcp "$p" >/dev/null 2>&1 || true
        fi
      fi
    fi
  fi

  # 3) 恢复 authorized_keys immutable
  if [ "${auth_was_immutable:-0}" -eq 1 ] && [ "${auth_immutable_restored:-0}" -eq 0 ] && command -v chattr >/dev/null 2>&1; then
    chattr +i "/root/.ssh/authorized_keys" >/dev/null 2>&1 || true
  fi

  # 4) 回滚 sshd 配置文件
  warn "还原 sshd 配置文件..."
  rm -f "$DROP_IN" 2>/dev/null || true
  cp -a "$MAIN_BAK" "$MAIN_CONF" 2>/dev/null || true

  # 5) 尝试恢复 sshd 服务
  warn "尝试恢复 SSH 服务..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || true
  elif command -v service >/dev/null 2>&1; then
    service sshd restart >/dev/null 2>&1 || service ssh restart >/dev/null 2>&1 || true
  fi

  warn "回滚结束。请检查日志：journalctl -u sshd -e 或 /var/log/auth.log"
}

on_exit() {
  if [ "$success" -eq 0 ]; then
    rollback
  fi
}
trap on_exit EXIT INT TERM

# ---------- 通用：保持目标文件元数据（owner/mode） ----------
preserve_meta_and_move() {
  local tmp="$1" dest="$2"
  if [ -e "$dest" ]; then
    chown --reference="$dest" "$tmp" 2>/dev/null || true
    chmod --reference="$dest" "$tmp" 2>/dev/null || true
  else
    chown root:root "$tmp" 2>/dev/null || true
    chmod 600 "$tmp" 2>/dev/null || true
  fi
  mv -f "$tmp" "$dest"
}

# 1) 端口占用检查（更稳的 ss 过滤优先）
is_listening() {
  local p="$1"

  if command -v ss >/dev/null 2>&1; then
    # 优先使用 ss 的过滤语法（失败则回退）
    if ss -H -ltn "sport = :$p" >/dev/null 2>&1; then
      ss -H -ltn "sport = :$p" 2>/dev/null | awk 'END{exit (NR==0)}'
      return $?
    fi
    # 回退：只看 LISTEN(-l) + TCP(-t) + numeric(-n)，末尾端口精确匹配
    ss -H -ltn 2>/dev/null | awk -v port=":$p" '$4 ~ port"$" {found=1} END{exit !found}'
    return $?
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | awk -v p="$p" '$4 ~ ":"p"$" {found=1} END{exit !found}'
    return $?
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  else
    return 2
  fi
}

# 1.1) 读端口
while true; do
  read -r -p "请输入新的 SSH 端口号 (1024-65535): " SSH_PORT
  [[ "${SSH_PORT:-}" =~ ^[0-9]+$ ]] || { warn "端口必须是数字"; continue; }
  [ "$SSH_PORT" -ge 1024 ] && [ "$SSH_PORT" -le 65535 ] || { warn "端口需在 1024-65535"; continue; }

  if is_listening "$SSH_PORT"; then
    warn "端口 $SSH_PORT 似乎已被占用，请换一个。"
    continue
  else
    rc=$?
    if [ "$rc" -eq 2 ]; then
      warn "系统缺少 ss/netstat/lsof，无法确认端口是否占用；将继续，但请你稍后重点确认 sshd 监听状态。"
    fi
  fi
  break
done

# 1.2) 云安全组确认（可跳过）
if [ "${SKIP_CLOUD_CONFIRM:-0}" != "1" ]; then
  echo ""
  echo -e "${RED}🛑 重要：如果是云服务器，还必须在云控制台安全组/防火墙放行 TCP 端口 ${SSH_PORT}。${NC}"
  read -r -p "你确认【已经】在云安全组放行了端口 $SSH_PORT 吗？[y/N] " confirm
  [[ "${confirm:-}" =~ ^[Yy]$ ]] || die "未确认云安全组放行，已中止（避免锁死）。"
fi

# 2) 强提醒：将禁用密码登录（可跳过确认）
if [ "${SKIP_PRIVATEKEY_CONFIRM:-0}" != "1" ]; then
  echo ""
  echo -e "${RED}🛑 重要：脚本将执行 PasswordAuthentication no（禁用密码登录），仅允许密钥登录。${NC}"
  echo -e "${RED}请确认你【确实持有】对应私钥，并能在新窗口测试登录，否则可能锁死。${NC}"
  read -r -p "确认继续？[y/N] " pkc
  [[ "${pkc:-}" =~ ^[Yy]$ ]] || die "用户取消。"
fi

# 3) 公钥输入 + ssh-keygen 校验（允许在已存在有效 key 时跳过）
SSH_DIR="/root/.ssh"
AUTH_FILE="${SSH_DIR}/authorized_keys"

has_existing_key=0
if [ -f "$AUTH_FILE" ] && [ -s "$AUTH_FILE" ]; then
  if grep -Eq '^[[:alnum:]@._+-]+[[:space:]]+[A-Za-z0-9+/]+=*([[:space:]].*)?$' "$AUTH_FILE" 2>/dev/null; then
    has_existing_key=1
  fi
fi

echo ""
if [ "$has_existing_key" -eq 1 ]; then
  info "检测到 root 已存在 authorized_keys。你可以回车跳过写入（仍会改端口并禁用密码）。"
  read -r -p "请粘贴你的 SSH 公钥（回车跳过）： " SSH_KEY
else
  echo -e "${GREEN}请粘贴你的 SSH 公钥(单行，格式：type base64 [comment])：${NC}"
  read -r SSH_KEY
fi

if [ -z "${SSH_KEY:-}" ]; then
  [ "$has_existing_key" -eq 1 ] || die "未提供公钥且系统中也未检测到现有 key，拒绝继续（避免锁死）。"
  ok "跳过公钥写入（保留现有 authorized_keys）。"
else
  printf '%s\n' "$SSH_KEY" | grep -Eq '^[A-Za-z0-9@._+-]+[[:space:]]+[A-Za-z0-9+/]+=*([[:space:]].*)?$' \
    || die "公钥格式不正确（应为：type base64 [comment]）"

  command -v ssh-keygen >/dev/null 2>&1 || die "未找到 ssh-keygen（建议安装 openssh-client），为避免写入无效 key 导致锁死，本脚本拒绝继续。"

  tmpk="$(mktemp /tmp/keycheck.XXXXXX)"
  printf "%s\n" "$SSH_KEY" > "$tmpk"
  ssh-keygen -l -f "$tmpk" >/dev/null 2>&1 || { rm -f "$tmpk"; die "ssh-keygen 校验失败：公钥无效"; }
  rm -f "$tmpk"

  # 3.1) 安全写入 /root/.ssh/authorized_keys（拒绝软链 + immutable 恢复 + owner/mode）
  [ -L "/root" ] && die "/root 是符号链接，拒绝继续"
  [ -L "$SSH_DIR" ] && die "$SSH_DIR 是符号链接，拒绝继续"
  [ -L "$AUTH_FILE" ] && die "$AUTH_FILE 是符号链接，拒绝继续"

  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR"

  if command -v lsattr >/dev/null 2>&1 && [ -e "$AUTH_FILE" ]; then
    if lsattr -d "$AUTH_FILE" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      auth_was_immutable=1
    fi
  fi

  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$AUTH_FILE" 2>/dev/null || true
  fi

  touch "$AUTH_FILE"
  chmod 600 "$AUTH_FILE"
  chown -R root:root "$SSH_DIR" 2>/dev/null || true

  if grep -qxF "$SSH_KEY" "$AUTH_FILE" 2>/dev/null; then
    ok "公钥已存在，跳过写入。"
  else
    if [ -s "$AUTH_FILE" ] && [ "$(tail -c 1 "$AUTH_FILE" 2>/dev/null || true)" != $'\n' ]; then
      echo "" >> "$AUTH_FILE"
    fi
    echo "$SSH_KEY" >> "$AUTH_FILE"
    ok "公钥已写入 $AUTH_FILE"
  fi

  if [ "$auth_was_immutable" -eq 1 ] && command -v chattr >/dev/null 2>&1; then
    chattr +i "$AUTH_FILE" 2>/dev/null || true
    auth_immutable_restored=1
  fi
fi

# 4) 配置策略：优先 drop-in；不支持则回退主配置托管块（插到 Match 前）
supports_include() {
  local tmp
  tmp="$(mktemp /tmp/sshd-include-test.XXXXXX)"
  cat > "$tmp" <<EOF
Include /etc/ssh/sshd_config.d/*.conf
Port 22
EOF
  if sshd -t -f "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"
    return 0
  fi
  if sshd -t -f "$tmp" 2>&1 | grep -qi "Bad configuration option: Include"; then
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
  return 0
}

insert_before_first_match() {
  local file="$1"
  local insert_text_file="$2"
  local tmp
  tmp="$(mktemp "$(dirname "$file")/.sshd-merge.XXXXXX")"

  local match_line
  match_line="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*Match[[:space:]]/ {print NR; exit}' "$file" 2>/dev/null || true)"

  if [ -z "$match_line" ]; then
    cat "$file" "$insert_text_file" > "$tmp"
  else
    awk -v ml="$match_line" -v ins="$insert_text_file" '
      NR < ml {print}
      NR == ml {
        while ((getline line < ins) > 0) print line
        close(ins)
        print
      }
      NR > ml {print}
    ' "$file" > "$tmp"
  fi

  preserve_meta_and_move "$tmp" "$file"
}

remove_managed_block() {
  local file="$1"
  local b="# BEGIN SECURE-INIT MANAGED BLOCK"
  local e="# END SECURE-INIT MANAGED BLOCK"
  local tmp
  tmp="$(mktemp "$(dirname "$file")/.sshd-strip.XXXXXX")"

  awk -v b="$b" -v e="$e" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip!=1 {print}
  ' "$file" > "$tmp"

  preserve_meta_and_move "$tmp" "$file"
}

disable_global_ports_in_main() {
  local file="$1"
  local tmp
  tmp="$(mktemp "$(dirname "$file")/.sshd-noglobalport.XXXXXX)"
  local match_line

  match_line="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*Match[[:space:]]/ {print NR; exit}' "$file" 2>/dev/null || true)"

  if [ -z "$match_line" ]; then
    awk '{
      low=tolower($0)
      if (low ~ /^[[:space:]]*port[[:space:]]+/) { print "# [disabled by secure-init] " $0; next }
      print
    }' "$file" > "$tmp"
  else
    awk -v ml="$match_line" '{
      if (NR < ml) {
        low=tolower($0)
        if (low ~ /^[[:space:]]*port[[:space:]]+/) { print "# [disabled by secure-init] " $0; next }
        print; next
      }
      print
    }' "$file" > "$tmp"
  fi

  preserve_meta_and_move "$tmp" "$file"
}

has_sshd_config_d_include() {
  local file="$1"
  awk '
    /^[[:space:]]*#/ {next}
    {
      line=$0
      gsub(/"/,"",line)
      gsub(/[[:space:]]+/," ",line)
      low=tolower(line)
      if (low ~ /^[[:space:]]*include[[:space:]]+\/etc\/ssh\/sshd_config\.d\/\*\.conf([[:space:]]|$)/) {found=1}
    }
    END{exit !found}
  ' "$file"
}

write_dropin_atomic() {
  mkdir -p "$CONF_D"
  [ -L "$DROP_IN" ] && die "$DROP_IN 是符号链接，拒绝继续"

  local tmp
  tmp="$(mktemp "$CONF_D/.99-secure-custom.conf.XXXXXX")"

  cat > "$tmp" <<EOF
# Generated by Secure-Init-Script
Port $SSH_PORT
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Hardening (anti-bruteforce / timeout)
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

  chown root:root "$tmp" 2>/dev/null || true
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$DROP_IN"
}

check_other_dropin_ports_or_die() {
  [ -d "$CONF_D" ] || return 0
  local found
  found="$(grep -RniE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$CONF_D" 2>/dev/null | grep -vF "$DROP_IN" || true)"
  if [ -n "$found" ]; then
    warn "检测到 $CONF_D 中存在其他 Port 配置（可能导致多端口监听/行为不确定）："
    echo "$found" >&2
    die "请先清理/确认这些 Port 配置后再运行本脚本。"
  fi
}

echo "正在生成 SSH 安全配置..."
dropin_used="n"

if supports_include; then
  check_other_dropin_ports_or_die

  if has_sshd_config_d_include "$MAIN_CONF"; then
    write_dropin_atomic
    disable_global_ports_in_main "$MAIN_CONF"
    dropin_used="y"
  else
    tmpins="$(mktemp /tmp/sshd-include-line.XXXXXX)"
    echo "Include /etc/ssh/sshd_config.d/*.conf" > "$tmpins"
    remove_managed_block "$MAIN_CONF"
    insert_before_first_match "$MAIN_CONF" "$tmpins"
    rm -f "$tmpins"

    write_dropin_atomic
    disable_global_ports_in_main "$MAIN_CONF"
    dropin_used="y"
  fi
else
  warn "检测到 sshd 不支持 Include：将回退为直接修改 $MAIN_CONF（插到 Match 前的托管块方式）"
  remove_managed_block "$MAIN_CONF"
  tmpblock="$(mktemp /tmp/sshd-managed-block.XXXXXX)"
  cat > "$tmpblock" <<EOF
# BEGIN SECURE-INIT MANAGED BLOCK
# Generated: $(date)
Port $SSH_PORT
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Hardening (anti-bruteforce / timeout)
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
# END SECURE-INIT MANAGED BLOCK
EOF
  insert_before_first_match "$MAIN_CONF" "$tmpblock"
  rm -f "$tmpblock"
fi

# 5) sshd 语法校验
echo "正在校验配置..."
sshd -t >/dev/null 2>&1 || die "sshd 配置语法校验失败（已自动回滚）。请检查 $MAIN_CONF。"
ok "sshd 配置语法校验通过"

# 5.1) 单端口硬校验
ports="$(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2}')"
port_count="$(printf "%s\n" $ports | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
if [ "$port_count" -ne 1 ]; then
  warn "检测到最终生效的 Port 不止一个（或无法解析）："
  printf "%s\n" $ports >&2
  die "为避免多端口监听/行为不确定，已中止并自动回滚。请用 sshd -T 排查来源。"
fi

# 6) SELinux 端口（Enforcing 下：没有 semanage 就拒绝继续；记录旧映射以便回滚）
if command -v getenforce >/dev/null 2>&1; then
  if getenforce 2>/dev/null | grep -qi '^Enforcing$'; then
    echo "检测到 SELinux Enforcing，准备配置 SSH 端口规则..."
    command -v semanage >/dev/null 2>&1 || die "SELinux 为 Enforcing 但未找到 semanage。为避免 sshd 无法绑定新端口导致锁死，本脚本拒绝继续。"

    selinux_prev_type="$(semanage port -l 2>/dev/null | awk -v p="$SSH_PORT" '
      function has_port(token, p, a, b) {
        if (token ~ /^[0-9]+$/) return (token == p)
        if (token ~ /^[0-9]+-[0-9]+$/) { split(token, r, "-"); a=r[1]; b=r[2]; return (p >= a && p <= b) }
        return 0
      }
      $2=="tcp" {
        ports=$3
        gsub(/,/," ",ports)
        n=split(ports, arr, /[[:space:]]+/)
        for(i=1;i<=n;i++){
          if (arr[i] != "" && has_port(arr[i], p)) { print $1; exit }
        }
      }
    ')"
    if [ -n "$selinux_prev_type" ]; then selinux_prev_had_port=1; else selinux_prev_had_port=0; fi

    semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" >/dev/null 2>&1 || \
    semanage port -m -t ssh_port_t -p tcp "$SSH_PORT" >/dev/null 2>&1 || \
    die "SELinux 端口规则设置失败：请手动处理 semanage port -a/-m 后再重试（避免锁死）。"
    selinux_touched=1
  fi
fi

# 7) 防火墙放行 —— 放在 restart 之前（避免竞态锁死）
echo "正在配置防火墙..."
fw_undo_cmd=""
fw_touched=0

ufw_active() { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; }
firewalld_active() { command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi "^running$"; }

if ufw_active; then
  ufw allow "${SSH_PORT}/tcp" >/dev/null || die "UFW 放行失败"
  ufw reload >/dev/null || true
  fw_undo_cmd="ufw delete allow ${SSH_PORT}/tcp"
  fw_touched=1
  ok "UFW 已放行 ${SSH_PORT}/tcp"
elif firewalld_active; then
  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null || die "firewalld 放行失败"
  firewall-cmd --reload >/dev/null || true
  fw_undo_cmd="firewall-cmd --permanent --remove-port=${SSH_PORT}/tcp && firewall-cmd --reload"
  fw_touched=1
  ok "firewalld 已放行 ${SSH_PORT}/tcp"
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT || die "iptables 放行失败"

  fw_undo_cmd="iptables -D INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT 2>/dev/null || true"

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
      ip6tables -I INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || true
    fw_undo_cmd="${fw_undo_cmd}; ip6tables -D INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT 2>/dev/null || true"
  fi

  fw_touched=1
  warn "iptables 规则可能不持久化（重启可能丢失）。如需持久化请配置 iptables-persistent/nftables/发行版防火墙。"
else
  warn "未检测到活动防火墙工具，将不自动放行端口（请自行确保可达）。"
fi

# 8) 重启 SSH 服务
echo "正在重启 SSH 服务..."
restart_ok=0
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart sshd >/dev/null 2>&1 && restart_ok=1 || true
  [ "$restart_ok" -eq 0 ] && systemctl restart ssh >/dev/null 2>&1 && restart_ok=1 || true
fi
if [ "$restart_ok" -eq 0 ] && command -v service >/dev/null 2>&1; then
  service sshd restart >/dev/null 2>&1 && restart_ok=1 || true
  [ "$restart_ok" -eq 0 ] && service ssh restart >/dev/null 2>&1 && restart_ok=1 || true
fi
[ "$restart_ok" -eq 1 ] || die "无法自动重启 SSH 服务（已自动回滚）。请手动重启并检查日志。"

# 9) 本地监听检查（轮询等待，避免慢启动误判回滚）
echo "等待端口 $SSH_PORT 生效..."
tries=10
while [ "$tries" -gt 0 ]; do
  if is_listening "$SSH_PORT"; then
    break
  fi
  sleep 1
  tries=$((tries - 1))
done

if is_listening "$SSH_PORT"; then
  ok "sshd 已监听端口 $SSH_PORT（严格单端口模式）"
else
  rc=$?
  if [ "$rc" -eq 2 ]; then
    warn "未能确认端口监听状态（缺少 ss/netstat/lsof）。请手动检查：ss -lnt | grep :$SSH_PORT"
  else
    die "未检测到 sshd 在端口 $SSH_PORT 监听（已自动回滚）。请查看日志：journalctl -u sshd -e 或 /var/log/auth.log"
  fi
fi

# 成功：取消回滚
success=1
trap - EXIT INT TERM

echo ""
ok "所有步骤完成！"
echo "端口: $SSH_PORT"
echo "配置方式: $([ "$dropin_used" = "y" ] && echo "drop-in (sshd_config.d)" || echo "主配置托管块")"
echo -e "${RED}⚠️  请不要关闭当前窗口，务必新开窗口测试： ssh -p $SSH_PORT root@<服务器IP>${NC}"
echo "主配置备份: $MAIN_BAK"
echo ""

if [ -n "${fw_undo_cmd:-}" ] && [ "${fw_touched:-0}" -eq 1 ]; then
  echo "如需撤销本次防火墙放行，可执行："
  echo "  $fw_undo_cmd"
  echo ""
fi

if [ "${selinux_touched:-0}" -eq 1 ]; then
  echo "SELinux 提示：可用以下命令查看/回退端口映射（按实际情况选择）："
  echo "  semanage port -l | grep -i ssh_port_t"
  echo "  # 如需删除该端口映射："
  echo "  semanage port -d -t ssh_port_t -p tcp $SSH_PORT"
  echo ""
fi

echo "建议立刻确认最终生效配置："
echo "  sshd -T | egrep -i '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|maxauthtries|logingracetime|clientaliveinterval|clientalivecountmax) '"
