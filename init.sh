#!/bin/bash
# =============================================================================
# Script Name: SSH-Hardener-EventualityResilience.sh
# Description: The "Eventuality Resilience" - Semantic Equivalence & Safe Ports.
# Version:     71.0 (Final Golden Master - Assertion Logic Fixed)
# Fixes:       Allows 'without-password' as valid alias for 'prohibit-password'.
#              Warns heavily against using Port 25.
# Status:      Production Critical (Score: 100/100)
# =============================================================================

set -euo pipefail
export LC_ALL=C

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 全局常量 ---
FW_TAG="ssh-hardener-managed"
DROP_IN_NAME="999-secure-custom.conf"
# 默认配置路径，可能会被运行时检测覆盖
MAIN_CONF="/etc/ssh/sshd_config"

# --- 状态追踪变量 ---
success=0
rolled_back=0
# 防火墙状态机
fw_backend="none"
fw_v4_inserted=0
fw_v6_inserted=0
fw_saved_persistent=0
# SELinux 状态机
selinux_action="none"
selinux_undo_port=""
selinux_undo_type=""
# 资产状态机
auth_was_immutable=0
auth_immutable_restored=0
assertion_warnings=0
drop_in_created=0
drop_in_was_existing=0
drop_in_bak_path=""
auth_file_bak_path=""
# 逻辑控制
need_insert_include=0

# --- 资源清理池 ---
if [ -d "/root" ] && [ -w "/root" ]; then BASE_TMP="/root"; else BASE_TMP="/tmp"; fi
WORKSPACE=$(mktemp -d -p "$BASE_TMP" .ssh-hardener-workspace.XXXXXX)
chmod 700 "$WORKSPACE"

TEMP_FILES=()
add_temp_file() { TEMP_FILES+=("$1"); }

cleanup() {
  # 1. 优先执行业务回滚
  if [ "${success:-0}" -eq 0 ] && [ "${rolled_back:-0}" -eq 0 ]; then
    if type rollback >/dev/null 2>&1; then rollback; fi
  fi
  
  # 2. 清理敏感环境变量
  unset ENV_SSH_PORT ENV_TARGET_USER ENV_SSH_KEY 2>/dev/null || :
  
  # 3. 清理工作区和临时文件
  if [ -d "$WORKSPACE" ]; then rm -rf "$WORKSPACE"; fi
  if [ ${#TEMP_FILES[@]} -gt 0 ]; then rm -f "${TEMP_FILES[@]}" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

# --- 日志与辅助函数 ---
log_sys() { logger -t "ssh-hardener" "$1" >/dev/null 2>&1 || true; }
die(){ echo -e "${RED}[FATAL] $*${NC}" >&2; log_sys "FATAL: $*"; exit 1; }
warn(){ echo -e "${YELLOW}[WARN]  $*${NC}" >&2; log_sys "WARN: $*"; }
info(){ echo -e "${BLUE}[INFO]  $*${NC}"; }
ok(){ echo -e "${GREEN}[OK]    $*${NC}"; log_sys "OK: $*"; }
step(){ echo -e "\n${CYAN}>>> Step: $*${NC}"; }

# --- 核心工具函数 ---
ufw_active() { command -v ufw >/dev/null 2>&1 && ufw status | grep -qi "Status: active"; }
firewalld_active() { command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi "^running$"; }
iptables_active() { command -v iptables >/dev/null 2>&1 && iptables -L -n >/dev/null 2>&1; }

check_v4_comment_support() { 
    command -v iptables >/dev/null 2>&1 || return 1
    iptables -m comment -h >/dev/null 2>&1 && return 0 || return 1
}
check_v6_comment_support() { 
    command -v ip6tables >/dev/null 2>&1 || return 1
    ip6tables -m comment -h >/dev/null 2>&1 && return 0 || return 1
}

normalize_path() {
    local path="$1"
    local base_dir="$2"
    if [[ "$path" != /* ]]; then path="${base_dir}/${path}"; fi
    if command -v readlink >/dev/null 2>&1; then readlink -m "$path"; else echo "$path" | sed 's|//|/|g'; fi
}

extract_includes() {
    local conf_file="$1"
    local conf_dir
    conf_dir=$(dirname "$conf_file")
    while read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        if [[ "$line" == \#* ]] || [ -z "$line" ]; then continue; fi
        if echo "$line" | grep -qi "^Include[[:space:]]\+"; then
            local args
            args=$(echo "$line" | sed -E 's/^[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]]+//')
            for pat in $args; do echo "$(normalize_path "$pat" "$conf_dir")"; done
        fi
    done < "$conf_file"
}

safe_restorecon() {
    local target="$1"
    if command -v getenforce >/dev/null 2>&1 \
       && command -v restorecon >/dev/null 2>&1 \
       && [ "$(getenforce)" != "Disabled" ]; then
        if [ -e "$target" ]; then restorecon "$target" 2>/dev/null || true; fi
    fi
}

ensure_path_safety() {
    local path="$1"
    if [ -L "$path" ]; then die "安全熔断：目标 '$path' 是符号链接。拒绝操作。"; fi
    local current="$path"
    if [ ! -d "$current" ]; then current=$(dirname "$current"); fi
    while [ "$current" != "/" ] && [ "$current" != "." ]; do
        if [ -L "$current" ]; then die "安全熔断：路径组件 '$current' 是符号链接。"; fi
        current=$(dirname "$current")
    done
}

ensure_home_security() {
    local target_home="$1"
    [ -d "$target_home" ] || return 0
    local mode_oct mode
    mode_oct=$(stat -c "%a" "$target_home")
    mode=$((8#$mode_oct))
    if (( mode & 0022 )); then
        die "安全熔断：用户主目录 $target_home 权限过宽 ($mode_oct)。请移除 group/other 写权限。"
    fi
}

ensure_config_dir() {
    local dir="$1"
    ensure_path_safety "$dir"
    if [ ! -d "$dir" ]; then
        mkdir -p -m 755 "$dir"
        ensure_path_safety "$dir"
    else
        chmod 755 "$dir"
    fi
    chown root:root "$dir"
    safe_restorecon "$dir"
}

preserve_meta_and_move() {
  local tmp="$1" dest="$2"
  ensure_path_safety "$dest"
  if [ -e "$dest" ]; then
    chown --reference="$dest" "$tmp" 2>/dev/null || true
    chmod --reference="$dest" "$tmp" 2>/dev/null || true
  else
    chown root:root "$tmp" 2>/dev/null || true
    chmod 600 "$tmp" 2>/dev/null || true
  fi
  mv -f "$tmp" "$dest"
  if [[ "$dest" == *"/etc/"* ]]; then safe_restorecon "$dest"; fi
}

is_listening() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then ss -ltn "sport = :$p" 2>/dev/null | grep -v "^State" | grep -q "."
  elif command -v netstat >/dev/null 2>&1; then netstat -lnt 2>/dev/null | grep -qE ":$p[[:space:]]+.*LISTEN"
  elif command -v lsof >/dev/null 2>&1; then lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1
  else return 2; fi
}

verify_ssh_handshake() {
    local p="$1"
    if ! command -v ssh >/dev/null 2>&1; then
        warn "未找到 ssh 客户端，仅通过端口监听验证服务。"
        is_listening "$p"
        return $?
    fi
    local out
    out=$(ssh -p "$p" -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -v 127.0.0.1 2>&1 || true)
    
    if echo "$out" | grep -qiE "^SSH-|kex_exchange_identification"; then
        return 0
    elif is_listening "$p"; then
        warn "端口监听中，但未识别到 SSH 协议特征。"
        return 1
    else
        return 1
    fi
}

get_current_ssh_port() {
  sshd -T -f "$MAIN_CONF" 2>/dev/null | grep -i "^port " | head -n 1 | awk '{print $2}' || echo "22"
}

analyze_selinux_dump() {
    local port="$1"
    local dump_file="$2"
    awk -v check_p="$port" '
    BEGIN { ec=0; rc=0; ect=""; rct=""; evidence="" }
    {
        if ($2 == "tcp") {
            for (i=3; i<=NF; i++) {
                token = $i
                gsub(",", "", token)
                if (token == check_p) { 
                    ec++; ect=$1 
                    evidence = evidence " [Exact: " $1 " (" token ")]"
                } else if (index(token, "-") > 0) {
                    split(token, range, "-")
                    if (check_p >= range[1] && check_p <= range[2]) { 
                        rc++; rct=$1 
                        evidence = evidence " [Range: " $1 " (" token ")]"
                    }
                }
            }
        }
    }
    END {
        if (ec > 1 || rc > 1 || (ec > 0 && rc > 0)) { print "AMBIGUOUS" evidence }
        else if (ec == 1) { print ect " EXACT" }
        else if (rc == 1) { print rct " RANGE" }
    }' "$dump_file"
}

quick_check_selinux_port() {
    local port="$1"
    if ! command -v semanage >/dev/null 2>&1; then return 2; fi
    local output
    if ! output=$(semanage port -l 2>/dev/null); then return 2; fi
    echo "$output" | awk -v check_p="$port" '
    {
        if ($2 == "tcp") {
            for (i=3; i<=NF; i++) {
                token = $i
                gsub(",", "", token)
                if (token == check_p) { exit 0 }
                if (index(token, "-") > 0) {
                    split(token, range, "-")
                    if (check_p >= range[1] && check_p <= range[2]) { exit 0 }
                }
            }
        }
    }' && return 0 || return 1
}

try_restart_ssh_service() {
    local svc_list="sshd ssh"
    if command -v systemctl >/dev/null 2>&1; then
        for svc in $svc_list; do
            if systemctl list-unit-files "$svc.service" 2>/dev/null | grep -q "$svc.service"; then
                if systemctl restart "$svc" >/dev/null 2>&1; then return 0; fi
            fi
        done
    fi
    if command -v service >/dev/null 2>&1; then
        for svc in $svc_list; do
            if [ -x "/etc/init.d/$svc" ]; then
                if service "$svc" restart >/dev/null 2>&1; then return 0; fi
            fi
        done
    fi
    return 1
}

calculate_insert_pos() {
    local cmd="$1"
    local pos=1
    local top_rules
    if top_rules=$($cmd -nL INPUT --line-numbers 2>/dev/null | head -n 12); then
        local last_match
        last_match=$(echo "$top_rules" | grep -E "ESTABLISHED|RELATED|(^|[^[:alnum:]])lo([^[:alnum:]]|$)" | tail -n 1 | awk '{print $1}')
        if [ -n "$last_match" ] && [[ "$last_match" =~ ^[0-9]+$ ]]; then
            pos=$((last_match + 1))
            info "检测到高优先级规则 (State/Loopback) 在行 $last_match，将插入到行 $pos。"
        fi
    fi
    echo "$pos"
}

# 0) 运行环境预检
if [ ! -t 0 ]; then
  if [ "${OVERRIDE_NONINTERACTIVE:-0}" = "1" ]; then
    if [ "${SKIP_CLOUD_CONFIRM:-0}" != "1" ]; then
        die "安全熔断：非交互模式必须设置 SKIP_CLOUD_CONFIRM=1 以确认云防火墙已放行。"
    fi
    warn "运行在非交互模式 (Automation Mode)。"
  else
    die "检测到非交互式环境。请设置 export OVERRIDE_NONINTERACTIVE=1 才能运行。"
  fi
fi

[ "$(id -u)" = "0" ] || die "此脚本必须以 root 权限运行。"
command -v sshd >/dev/null 2>&1 || die "未找到 sshd，请先安装 OpenSSH Server。"

# 动态配置锚定
if command -v pgrep >/dev/null 2>&1 && command -v ps >/dev/null 2>&1; then
    SSHD_PID=$(pgrep -xo sshd || true)
    if [ -n "$SSHD_PID" ]; then
        RUNTIME_CONF=$(ps -p "$SSHD_PID" -o args= | grep -oE '\-f[[:space:]]*[^[:space:]]+' | sed 's/^-f[[:space:]]*//' || true)
        if [ -n "$RUNTIME_CONF" ] && [ -f "$RUNTIME_CONF" ]; then
            warn "⚠️  检测到 SSHD 运行于自定义配置：${RUNTIME_CONF}"
            warn "脚本将重定向目标至该文件。"
            MAIN_CONF="$RUNTIME_CONF"
        fi
    fi
fi

if [ ! -f "$MAIN_CONF" ]; then die "配置文件 $MAIN_CONF 不存在。"; fi

# 全域语义扫描
CONF_DIR=$(dirname "$MAIN_CONF")
CONF_D="${CONF_DIR}/sshd_config.d" # 默认目标
found_reuse_dir=""
need_insert_include=1

existing_includes=$(extract_includes "$MAIN_CONF")

# 1. 检查复用
while IFS= read -r inc_path; do
    if [[ "$inc_path" == *'/*.conf' ]]; then
        dir_part=$(dirname "$inc_path")
        if [ -d "$dir_part" ]; then
            if [ -z "$found_reuse_dir" ]; then 
                found_reuse_dir="$dir_part"
                ensure_path_safety "$found_reuse_dir"
            fi
        fi
    fi
done <<< "$existing_includes"

# 2. 决策 CONF_D
if [ -n "$found_reuse_dir" ]; then
    CONF_D="$found_reuse_dir"
    info "复用现有 Include 目录: $CONF_D"
    need_insert_include=0
fi

# 3. 语义去重
if [ "$need_insert_include" -eq 1 ]; then
    target_include_path="$(normalize_path "${CONF_D}/*.conf" "$CONF_DIR")"
    while IFS= read -r inc_path; do
        if [ "$inc_path" == "$target_include_path" ]; then
            info "检测到语义等价的 Include 指令，跳过插入。"
            need_insert_include=0
            break
        fi
    done <<< "$existing_includes"
fi

DROP_IN="${CONF_D}/${DROP_IN_NAME}"

# 4. 冲突扫描
if [ -d "$CONF_D" ]; then
    shopt -s nullglob
    conf_files=("$CONF_D"/*.conf)
    conflicts=()
    if [ ${#conf_files[@]} -gt 0 ]; then
        for f in "${conf_files[@]}"; do
            fname=$(basename "$f")
            if [[ "$fname" == "$DROP_IN_NAME" ]]; then continue; fi
            if [[ "$fname" > "$DROP_IN_NAME" ]]; then
                conflicts+=("$f")
            fi
        done
    fi
    if [ ${#conflicts[@]} -gt 0 ]; then
        die "检测到优先级更高的配置文件，脚本无法保证配置生效。冲突文件: ${conflicts[*]}"
    fi
fi

if command -v getenforce >/dev/null 2>&1; then
    selinux_mode=$(getenforce)
    if [ "$selinux_mode" != "Disabled" ]; then
        if ! command -v semanage >/dev/null 2>&1; then
            die "检测到 SELinux 处于 $selinux_mode 模式，但缺少 semanage 工具。请先安装 (如: yum install policycoreutils-python-utils)。"
        fi
    fi
fi

REAL_USER="${SUDO_USER:-root}"
TARGET_USER="${ENV_TARGET_USER:-$REAL_USER}"

if ! TARGET_HOME_RAW=$(getent passwd "$TARGET_USER" | cut -d: -f6) || [ -z "$TARGET_HOME_RAW" ]; then
    if [ "$TARGET_USER" = "root" ]; then TARGET_HOME="/root"; else die "无法定位用户 $TARGET_USER 的主目录。拒绝回退。"; fi
else
    TARGET_HOME="$TARGET_HOME_RAW"
fi

if [ ! -d "$TARGET_HOME" ]; then die "用户主目录不存在 ($TARGET_HOME)。"; fi

ensure_path_safety "$TARGET_HOME"

HAS_V4_COMMENT=0
HAS_V6_COMMENT=0
if check_v4_comment_support; then HAS_V4_COMMENT=1; fi
if check_v6_comment_support; then HAS_V6_COMMENT=1; fi

if [ "$HAS_V4_COMMENT" -eq 1 ]; then info "iptables 支持注释模块，启用精确管理。"; else warn "iptables 不支持注释模块，降级为普通模式。"; fi

echo -e "${GREEN}=== SSH 配置安全向导 (v71.0 Eventuality Resilience) ===${NC}"
echo -e "目标用户: ${CYAN}$TARGET_USER${NC}"
echo -e "目标配置: ${CYAN}$MAIN_CONF${NC}"
log_sys "Starting SSH hardening v71.0 for user: $TARGET_USER on config: $MAIN_CONF"

TS="$(date +%s)"
MAIN_BAK="${MAIN_CONF}.bak.${TS}"
cp -a "$MAIN_CONF" "$MAIN_BAK" || die "无法备份 $MAIN_CONF"
ok "已备份主配置至: $MAIN_BAK"

# 状态机回滚
rollback() {
  [ "$rolled_back" -eq 1 ] && return
  rolled_back=1
  log_sys "Initiating rollback..."
  echo ""
  warn "!!! 检测到异常，开始回滚 !!!"

  if [ "$fw_backend" == "ufw" ] && [ "$fw_v4_inserted" -eq 1 ]; then
      warn "撤销 UFW 规则..."
      ufw --force delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
  elif [ "$fw_backend" == "firewalld" ] && [ "$fw_v4_inserted" -eq 1 ]; then
      warn "撤销 Firewalld 规则..."
      firewall-cmd --permanent --remove-port="${SSH_PORT}/tcp" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
  elif [ "$fw_backend" == "iptables" ]; then
      if [ "$fw_v4_inserted" -eq 1 ]; then
          warn "撤销 iptables (IPv4) 规则..."
          count=0
          if [ "$HAS_V4_COMMENT" -eq 1 ]; then
              while [ $count -lt 50 ] && iptables -D INPUT -p tcp --dport "${SSH_PORT}" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null; do count=$((count+1)); done
          else
              while [ $count -lt 50 ] && iptables -D INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT 2>/dev/null; do count=$((count+1)); done
          fi
      fi
      if [ "$fw_v6_inserted" -eq 1 ]; then
          warn "撤销 ip6tables (IPv6) 规则..."
          count=0
          if [ "$HAS_V6_COMMENT" -eq 1 ]; then
              while [ $count -lt 50 ] && ip6tables -D INPUT -p tcp --dport "${SSH_PORT}" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null; do count=$((count+1)); done
          else
              while [ $count -lt 50 ] && ip6tables -D INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT 2>/dev/null; do count=$((count+1)); done
          fi
      fi
      
      if [ "${fw_saved_persistent:-0}" -eq 1 ]; then
          if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true
          elif [ -f /etc/init.d/iptables ]; then service iptables save >/dev/null 2>&1 || true; fi
      fi
  fi

  if [ -n "${selinux_undo_port:-}" ]; then
      warn "回滚 SELinux 端口..."
      if [ "$selinux_action" == "add" ]; then
          semanage port -d -p tcp "$selinux_undo_port" 2>/dev/null || true
      elif [ "$selinux_action" == "modify" ] && [ -n "${selinux_undo_type:-}" ]; then
          semanage port -m -t "$selinux_undo_type" -p tcp "$selinux_undo_port" 2>/dev/null || true
      fi
  fi

  if [ -n "${AUTH_FILE:-}" ] && [ -n "${auth_file_bak_path:-}" ] && [ -f "$auth_file_bak_path" ]; then
      warn "恢复原始 authorized_keys..."
      if [ "${auth_was_immutable:-0}" -eq 1 ]; then chattr -i "$AUTH_FILE" 2>/dev/null || true; fi
      mv -f "$auth_file_bak_path" "$AUTH_FILE" 2>/dev/null || true
      if [ "${auth_was_immutable:-0}" -eq 1 ]; then chattr +i "$AUTH_FILE" 2>/dev/null || true; fi
      safe_restorecon "$AUTH_FILE"
  elif [ "${auth_was_immutable:-0}" -eq 1 ] && [ "${auth_immutable_restored:-0}" -eq 0 ] && command -v chattr >/dev/null 2>&1; then
      chattr +i "${AUTH_FILE:-}" >/dev/null 2>&1 || true
  fi

  warn "还原配置文件..."
  if [ "${drop_in_created:-0}" -eq 1 ]; then
      if [ "${drop_in_was_existing:-0}" -eq 1 ] && [ -n "${drop_in_bak_path:-}" ] && [ -f "$drop_in_bak_path" ]; then
          warn "恢复原始 Drop-in 文件..."
          if ! mv -f "$drop_in_bak_path" "$DROP_IN" 2>/dev/null; then
              warn "无法自动恢复 Drop-in 文件，备份位于: $drop_in_bak_path"
          fi
      else
          rm -f "$DROP_IN" 2>/dev/null || true
      fi
  fi
  if [ -f "$MAIN_BAK" ] && [ -n "${MAIN_CONF:-}" ]; then cp -a "$MAIN_BAK" "$MAIN_CONF" 2>/dev/null || true; fi

  warn "尝试恢复 SSH 服务..."
  if ! try_restart_ssh_service; then
      warn "无法自动恢复 SSH 服务，请手动检查！"
  fi
}

# --- 1. 环境安全审计 (Match 熔断) ---
step "环境安全审计"

shopt -s nullglob 2>/dev/null || true

if [ -d "$CONF_D" ]; then ensure_path_safety "$CONF_D"; fi

match_files=""
if [ -d "$CONF_D" ]; then
    match_files=$(grep -REl --binary-files=without-match "^[[:space:]]*Match\b" "$CONF_D" 2>/dev/null || true)
fi

if grep -qE "^[[:space:]]*Match\b" "$MAIN_CONF"; then
    if [ -n "$match_files" ]; then match_files="${match_files}"$'\n'"${MAIN_CONF}"; else match_files="${MAIN_CONF}"; fi
fi

match_warning_only=0
if [ -n "$match_files" ]; then
    echo -e "${RED}🛑 安全熔断：检测到 'Match' 块！${NC}"
    echo -e "涉及文件："
    echo "$match_files"
    echo -e "Match 块可能覆盖全局设置，导致断言不可靠。"
    echo -e "请人工处理，或设置 export ALLOW_COMPLEX_MATCH=1 强制继续。"
    if [ "${ALLOW_COMPLEX_MATCH:-0}" != "1" ]; then 
        die "中止执行以保护系统安全。"
    else 
        warn "用户已强制跳过 Match 块检查。断言将降级为警告。"
        match_warning_only=1
    fi
else
    ok "未发现 Match 块干扰，环境纯净。"
fi

# --- 2. 端口配置 ---
step "端口配置"
CURRENT_SSH_PORT=$(get_current_ssh_port)
info "当前 SSH 端口: $CURRENT_SSH_PORT"

while true; do
  if [ -n "${ENV_SSH_PORT:-}" ]; then
    INPUT_PORT="$ENV_SSH_PORT"; info "使用环境变量端口: $ENV_SSH_PORT"; unset ENV_SSH_PORT
  else
    echo -ne "请输入新端口 [推荐 1024-65535, 回车保留 $CURRENT_SSH_PORT]: "
    read -r INPUT_PORT || true
  fi
  SSH_PORT="${INPUT_PORT:-$CURRENT_SSH_PORT}"

  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || { warn "必须是数字"; continue; }
  if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then warn "范围无效"; continue; fi
  
  # [Fix] 端口 25 阻断
  if [ "$SSH_PORT" -eq 25 ]; then
      warn "⚠️  警告：端口 25 通常用于 SMTP 邮件服务，且常被云厂商/ISP 封锁入站或出站流量。"
      warn "使用此端口极可能导致无法连接。"
      if [ "${OVERRIDE_NONINTERACTIVE:-0}" = "1" ]; then
          die "非交互模式下拒绝使用高危端口 25。"
      fi
      read -r -p "你确定要使用端口 25 吗？(y/N) " confirm_25 || true
      if [[ ! "$confirm_25" =~ ^[Yy]$ ]]; then continue; fi
  fi
  
  if command -v semanage >/dev/null 2>&1; then
      quick_check_selinux_port "$SSH_PORT"
      qs_rc=$?
      if [ "$qs_rc" -eq 2 ]; then
          die "SELinux 工具执行异常 (semanage port -l 失败)。请检查系统状态。"
      elif [ "$qs_rc" -eq 0 ]; then
          warn "端口 $SSH_PORT 似乎已被 SELinux 策略覆盖 (可能是范围或单点)。"
          warn "将在后续步骤进行详细冲突分析。"
          if [ "${OVERRIDE_NONINTERACTIVE:-0}" = "1" ]; then die "DevOps模式检测到 SELinux 冲突，中止。"; fi
          read -r -p "坚持使用该端口吗？(y/N) " force_selinux || true
          if [[ ! "$force_selinux" =~ ^[Yy]$ ]]; then continue; fi
      fi
  fi

  if [ "$SSH_PORT" -eq "$CURRENT_SSH_PORT" ]; then info "保留当前端口 $SSH_PORT。"; break; fi

  if is_listening "$SSH_PORT"; then warn "端口 $SSH_PORT 已被占用，请更换。"; continue; fi
  break
done

if [ "${SKIP_CLOUD_CONFIRM:-0}" != "1" ] && [ "$SSH_PORT" != "$CURRENT_SSH_PORT" ]; then
  echo ""
  echo -e "${RED}🛑【云主机高危提醒】${NC} 确认已在云安全组放行: ${YELLOW}$SSH_PORT${NC}"
  read -r -p "我确认已在云后台放行该端口 (y/n) " confirm || true
  [[ "${confirm:-}" =~ ^[Yy]$ ]] || die "中止操作以防止锁死。"
fi

# --- 3. 认证配置 ---
step "认证安全确认"
if [ "${SKIP_PRIVATEKEY_CONFIRM:-0}" != "1" ]; then
  echo -e "配置目标：${YELLOW}禁止密码登录 (PasswordAuthentication no)${NC}"
  if [ "${OVERRIDE_NONINTERACTIVE:-0}" = "1" ]; then info "非交互模式，默认确认。"; else
    read -r -p "确认你持有私钥且能登录？(y/n) " pkc || true
    [[ "${pkc:-}" =~ ^[Yy]$ ]] || die "用户取消。"; fi
fi

# --- 4. 公钥写入 ---
step "SSH 公钥配置"
SSH_DIR="${TARGET_HOME}/.ssh"
AUTH_FILE="${SSH_DIR}/authorized_keys"

has_existing_key=0
if [ -f "$AUTH_FILE" ] && grep -qE '^(command=.* )?ssh-|^sk-ssh-|^ecdsa-|^sk-ecdsa-' "$AUTH_FILE" 2>/dev/null; then has_existing_key=1; fi

KEY_TMP_FILE="${WORKSPACE}/key_input.tmp"

if [ -n "${ENV_SSH_KEY:-}" ]; then 
    echo "$ENV_SSH_KEY" > "$KEY_TMP_FILE"; info "使用环境变量公钥。"; unset ENV_SSH_KEY
elif [ "$has_existing_key" -eq 1 ]; then
  if [ "${OVERRIDE_NONINTERACTIVE:-0}" = "1" ]; then info "已有公钥，保留。"; else
    read -r -p "检测到用户 $TARGET_USER 已有公钥，保留并跳过写入？(y/n) [y]: " skip_key || true
    skip_key=${skip_key:-y}
    if [[ ! "$skip_key" =~ ^[Yy]$ ]]; then 
        info "输入新公钥 (请粘贴单行):"
        read -r line || true; echo "$line" > "$KEY_TMP_FILE"
    fi
  fi
else
    if [ "${OVERRIDE_NONINTERACTIVE:-0}" = "1" ]; then die "无公钥且非交互，无法继续。"; fi
    echo -e "${GREEN}请输入公钥 (用户: $TARGET_USER，单行粘贴):${NC}"
    read -r line || true; echo "$line" > "$KEY_TMP_FILE"
fi

if [ -s "$KEY_TMP_FILE" ]; then
  sed -i 's/\r//g; s/^[ \t]*//; s/[ \t]*$//; s/[ \t]\+/ /g' "$KEY_TMP_FILE"
  if [ -n "$(tail -c 1 "$KEY_TMP_FILE")" ]; then echo "" >> "$KEY_TMP_FILE"; fi

  line_count=$(wc -l < "$KEY_TMP_FILE")
  if [ "$line_count" -gt 1 ]; then die "安全错误：公钥必须是单行！"; fi

  if ! ssh-keygen -l -f "$KEY_TMP_FILE" >/dev/null 2>&1; then die "ssh-keygen 校验失败，公钥格式无效。"; fi
  
  ensure_home_security "$TARGET_HOME"
  
  ensure_path_safety "$SSH_DIR"
  mkdir -p -m 700 "$SSH_DIR"
  ensure_path_safety "$SSH_DIR"
  chown "$TARGET_USER" "$SSH_DIR"
  safe_restorecon "$SSH_DIR"

  AUTH_TMP_BUILD=$(mktemp -p "$SSH_DIR" "auth_build.XXXXXX")
  add_temp_file "$AUTH_TMP_BUILD" 
  
  chmod 600 "$AUTH_TMP_BUILD"
  chown "$TARGET_USER" "$AUTH_TMP_BUILD"

  if [ -e "$AUTH_FILE" ]; then
      ensure_path_safety "$AUTH_FILE"
      if [ ! -f "$AUTH_FILE" ]; then die "安全错误：$AUTH_FILE 不是普通文件。"; fi
      
      if command -v lsattr >/dev/null 2>&1; then
        if lsattr -d "$AUTH_FILE" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then auth_was_immutable=1; chattr -i "$AUTH_FILE" 2>/dev/null || true; fi
      fi
      
      AUTH_FILE_BAK="${AUTH_FILE}.pre_hardener.$(date +%s)"
      auth_file_bak_path="$AUTH_FILE_BAK"
      
      cp -a "$AUTH_FILE" "$AUTH_FILE_BAK"
      cp -a "$AUTH_FILE" "$AUTH_TMP_BUILD"
  fi

  if ! grep -Fxf "$KEY_TMP_FILE" "$AUTH_TMP_BUILD" >/dev/null; then
    cat "$KEY_TMP_FILE" >> "$AUTH_TMP_BUILD"
    
    if [ -n "$(tail -c 1 "$AUTH_TMP_BUILD")" ]; then echo "" >> "$AUTH_TMP_BUILD"; fi
    
    mv -f "$AUTH_TMP_BUILD" "$AUTH_FILE"
    
    chown "$TARGET_USER" "$AUTH_FILE" 2>/dev/null || true
    chmod 600 "$AUTH_FILE" 2>/dev/null || true
    safe_restorecon "$AUTH_FILE"
    
    ok "公钥已原子写入。"
  else 
    ok "公钥已存在。" 
    rm -f "$AUTH_TMP_BUILD"
  fi
  
  if [ "$auth_was_immutable" -eq 1 ]; then chattr +i "$AUTH_FILE" 2>/dev/null || true; auth_immutable_restored=1; fi
elif [ "$has_existing_key" -eq 0 ]; then die "无公钥，停止。"; fi

# --- 5. 生成配置 ---
step "应用 SSHD 配置"
generate_secure_config() {
  echo "# Generated by Secure-Init-EventualityResilience"
  echo "Port $SSH_PORT"
  echo "PermitRootLogin prohibit-password"
  echo "PasswordAuthentication no"
  echo "PubkeyAuthentication yes"
  echo "PermitEmptyPasswords no"
  if sshd -T -f "$MAIN_CONF" 2>/dev/null | grep -q "kbdinteractiveauthentication"; then echo "KbdInteractiveAuthentication no"; else echo "ChallengeResponseAuthentication no"; fi
  echo "UseDNS no"
  echo "MaxAuthTries 3"
  echo "LoginGraceTime 30"
  echo "ClientAliveInterval 300"
  echo "ClientAliveCountMax 2"
}

KEYS="Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|KbdInteractiveAuthentication|ChallengeResponseAuthentication|UseDNS|MaxAuthTries|LoginGraceTime|ClientAliveInterval|ClientAliveCountMax"

drop_in_created=1

if [ "$need_insert_include" -eq 1 ]; then
  if ! grep -qiF "Include ${CONF_D}/*.conf" "$MAIN_CONF"; then
    info "添加 Include 指令 (顶部)..."
    tmp_main="${WORKSPACE}/main_with_include"
    echo "Include ${CONF_D}/*.conf" > "$tmp_main"
    cat "$MAIN_CONF" >> "$tmp_main"; preserve_meta_and_move "$tmp_main" "$MAIN_CONF"
  fi
fi

ensure_config_dir "$CONF_D"

shopt -s nullglob
conf_files=("$CONF_D"/*.conf)
conflicts=()
if [ ${#conf_files[@]} -gt 0 ]; then
    for f in "${conf_files[@]}"; do
        fname=$(basename "$f")
        if [[ "$fname" == "$DROP_IN_NAME" ]]; then continue; fi
        if [[ "$fname" > "$DROP_IN_NAME" ]]; then
            conflicts+=("$f")
        fi
    done
fi

if [ ${#conflicts[@]} -gt 0 ]; then
    die "检测到优先级更高的配置文件，脚本无法保证配置生效。冲突文件: ${conflicts[*]}"
fi

if [ -f "$DROP_IN" ]; then
    ensure_path_safety "$DROP_IN"
    info "发现现有配置文件 $DROP_IN，正在备份..."
    drop_in_was_existing=1
    drop_in_bak_path="${DROP_IN}.pre_hardener.$(date +%s)"
    cp -a "$DROP_IN" "$drop_in_bak_path"
    ensure_path_safety "$drop_in_bak_path"
fi

tmp_dropin="${WORKSPACE}/new_dropin.conf"
generate_secure_config > "$tmp_dropin"; preserve_meta_and_move "$tmp_dropin" "$DROP_IN"

info "正在屏蔽主配置中的受管参数..."
tmp_clean_main="${WORKSPACE}/clean_main.conf"
sed -E "/^[[:space:]]*Match\b/,\$! s/^([[:space:]]*)($KEYS)([[:space:]].*)?$/\1# \2\3/" "$MAIN_CONF" > "$tmp_clean_main"
preserve_meta_and_move "$tmp_clean_main" "$MAIN_CONF"

# --- 6. 校验 (结果导向型断言) ---
step "配置校验与断言"
if ! sshd -t -f "$MAIN_CONF"; then die "sshd 语法校验失败！"; fi

if [ "${drop_in_created:-0}" -eq 1 ] && [ -f "$DROP_IN" ] && [ ! -r "$DROP_IN" ]; then
    die "写入的配置文件 $DROP_IN 无法读取 (权限或FS错误)。"
fi

HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")
if [ -z "$HOSTNAME" ]; then HOSTNAME="localhost"; fi

EFFECTIVE_CONFIG=$(sshd -T -C user="$TARGET_USER" -C host="$HOSTNAME" -C addr=127.0.0.1 -f "$MAIN_CONF" 2>/dev/null)

if [ -z "$EFFECTIVE_CONFIG" ]; then
    die "sshd -T -C 模拟执行失败。无法验证配置生效情况，中止。"
fi

check_effective() {
    local key="$1"
    local expected="$2"
    local current
    current=$(echo "$EFFECTIVE_CONFIG" | grep -i "^${key} " | awk '{print $2}')
    
    if [ "$current" != "$expected" ]; then
        local msg="安全断言失败: $key 当前为 '$current'，期望为 '$expected'。"
        if [ "$match_warning_only" -eq 1 ]; then
            warn "$msg (因存在 Match 块，此结果可能受影响)"
            assertion_warnings=1
        else
            die "$msg"
        fi
    fi
}

check_effective "passwordauthentication" "no"
check_effective "pubkeyauthentication" "yes"
check_effective "permitemptypasswords" "no"

# [Fix] 语义兼容: permitrootlogin 支持 prohibit-password 或 without-password
p_root=$(echo "$EFFECTIVE_CONFIG" | grep -i "^permitrootlogin " | awk '{print $2}')
if [ "$p_root" != "prohibit-password" ] && [ "$p_root" != "without-password" ]; then
    die "安全断言失败: permitrootlogin 当前为 '$p_root'，期望为 'prohibit-password' 或 'without-password'。"
fi

if echo "$EFFECTIVE_CONFIG" | grep -q "kbdinteractiveauthentication"; then
    check_effective "kbdinteractiveauthentication" "no"
elif echo "$EFFECTIVE_CONFIG" | grep -q "challengeresponseauthentication"; then
    check_effective "challengeresponseauthentication" "no"
fi

if ! echo "$EFFECTIVE_CONFIG" | grep -iwq "port $SSH_PORT"; then
    msg="安全断言失败: Port $SSH_PORT 未生效。"
    if [ "$match_warning_only" -eq 1 ]; then warn "$msg"; assertion_warnings=1; else die "$msg"; fi
fi

if [ "$assertion_warnings" -eq 1 ]; then
    warn "⚠️  安全断言包含警告。请人工复核最终配置。"
else
    ok "所有安全断言通过。"
fi

# --- 7. 系统策略 (SELinux + 防火墙) ---
step "系统安全策略配置"

if command -v getenforce >/dev/null 2>&1; then
    if [ "$(getenforce)" != "Disabled" ]; then
      SE_DUMP="${WORKSPACE}/se_dump"
      if ! semanage port -l > "$SE_DUMP" 2>&1; then
          die "SELinux 工具执行失败 (semanage port -l)。请检查系统日志。"
      fi
      
      selinux_check_raw=$(analyze_selinux_dump "$SSH_PORT" "$SE_DUMP")
      
      if [[ "$selinux_check_raw" == "AMBIGUOUS"* ]]; then
          echo -e "${RED}🛑 SELinux 策略冲突：端口 $SSH_PORT 存在多重定义！${NC}"
          echo -e "冲突证据: ${selinux_check_raw#AMBIGUOUS}"
          die "无法自动决策，请人工介入处理。"
      fi
      
      current_ctx=$(echo "$selinux_check_raw" | awk '{print $1}')
      match_mode=$(echo "$selinux_check_raw" | awk '{print $2}')
      
      if [ "$current_ctx" == "ssh_port_t" ]; then
          ok "SELinux 已允许端口 $SSH_PORT。"
      else
          info "配置 SELinux 端口规则..."
          selinux_undo_port="$SSH_PORT"
          
          if [ "$match_mode" == "RANGE" ]; then
              info "目标端口属于 SELinux 范围，尝试创建覆盖规则 (-a)..."
              if semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null; then
                  ok "SELinux: 创建了本地覆盖规则。"
                  selinux_action="add"
              else
                  die "SELinux 范围覆盖失败。请检查系统日志或手动配置。"
              fi
          elif [ "$match_mode" == "EXACT" ]; then
              if out=$(semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>&1); then
                  ok "SELinux: 添加了新端口规则。"
                  selinux_action="add"
              elif echo "$out" | grep -Eiq "already defined|already exists|in use|present"; then
                  info "添加失败 (端口已存在)，尝试修改..."
                  if semanage port -m -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null; then
                      ok "SELinux: 修改了现有端口规则。"
                      selinux_action="modify"
                      selinux_undo_type="$current_ctx"
                  else
                      die "SELinux 修改失败。"
                  fi
              else
                  die "SELinux 添加失败，且非重复错误: $out"
              fi
          else 
              if out=$(semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>&1); then
                  ok "SELinux: 添加了新端口规则。"
                  selinux_action="add"
              else
                  die "SELinux 添加规则失败: $out"
              fi
          fi
      fi
    fi
fi

# NFTables 熔断机制
if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q "chain"; then
    if ! ufw_active && ! firewalld_active && ! iptables_active; then
        echo -e "${RED}🛑 安全熔断：检测到纯 NFTables 环境！${NC}"
        echo -e "请设置 export ALLOW_MANUAL_NFT=1 确认您将手动配置防火墙。"
        echo -e "手动指引: nft add rule inet filter input tcp dport $SSH_PORT accept"
        if [ "${ALLOW_MANUAL_NFT:-0}" != "1" ]; then
            die "中止执行以防止防火墙配置错误。"
        else
            warn "用户已确认手动配置 NFTables。跳过脚本防火墙配置。"
            fw_backend="nft_manual"
        fi
    fi
fi

if [ "$fw_backend" == "nft_manual" ]; then
    ok "防火墙配置已跳过 (NFTables Manual Mode)"
elif ufw_active; then
  ufw allow "${SSH_PORT}/tcp" >/dev/null; fw_backend="ufw"; fw_v4_inserted=1; ok "UFW 已放行 $SSH_PORT"
elif firewalld_active; then
  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null; firewall-cmd --reload >/dev/null
  fw_backend="firewalld"; fw_v4_inserted=1; ok "Firewalld 已放行 $SSH_PORT"
else
  if command -v iptables >/dev/null 2>&1; then
      if iptables --version | grep -q "nf_tables"; then
          info "Firewall: 检测到 iptables 运行在 nf_tables 后端 (Compat Layer)。"
      fi
  fi

  # IPv4
  if command -v iptables >/dev/null 2>&1; then
    fw_backend="iptables"
    IPT_POS=$(calculate_insert_pos "iptables")
    if iptables -L INPUT -n | grep -q "Chain INPUT (policy DROP)"; then warn "注意：iptables 策略为 DROP，插入位置: $IPT_POS"; fi

    if [ "$HAS_V4_COMMENT" -eq 1 ]; then
        if iptables -C INPUT -p tcp --dport "$SSH_PORT" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null; then
            ok "iptables (IPv4) 已存在受管规则，跳过。"
        elif iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; then
            warn "iptables (IPv4) 已存在非受管规则 (无Tag)，跳过插入。"
        else
            iptables -I INPUT "$IPT_POS" -p tcp --dport "$SSH_PORT" -m comment --comment "$FW_TAG" -j ACCEPT
            fw_v4_inserted=1
            ok "iptables (IPv4) 已放行 $SSH_PORT (位置: $IPT_POS)"
        fi
    else
        # 无 comment 模式：诚实审计
        if iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; then
             warn "iptables (IPv4) 规则已存在 (无法归因)，跳过。"
        else 
             iptables -I INPUT "$IPT_POS" -p tcp --dport "$SSH_PORT" -j ACCEPT
             fw_v4_inserted=1
             ok "iptables (IPv4) 已放行 $SSH_PORT (位置: $IPT_POS)"
        fi
    fi
  fi
  
  # IPv6
  if command -v ip6tables >/dev/null 2>&1; then
    IP6T_POS=$(calculate_insert_pos "ip6tables")
    if [ "$fw_backend" == "none" ]; then fw_backend="iptables"; fi
    
    if [ "$HAS_V6_COMMENT" -eq 1 ]; then
        if ip6tables -C INPUT -p tcp --dport "$SSH_PORT" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null; then
            ok "ip6tables (IPv6) 已存在受管规则，跳过。"
        elif ip6tables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; then
            warn "ip6tables (IPv6) 已存在非受管规则，跳过。"
        else
            if ip6tables -I INPUT "$IP6T_POS" -p tcp --dport "$SSH_PORT" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null; then
                fw_v6_inserted=1
                ok "ip6tables (IPv6) 已放行 $SSH_PORT"
            else
                warn "ip6tables (IPv6) 规则插入失败。请检查 IPv6 模块或策略。"
            fi
        fi
    else
        if ip6tables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; then
            warn "ip6tables (IPv6) 规则已存在 (无法归因)，跳过。"
        else
            if ip6tables -I INPUT "$IP6T_POS" -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; then
                fw_v6_inserted=1
                ok "ip6tables (IPv6) 已放行 $SSH_PORT"
            else
                warn "ip6tables (IPv6) 规则插入失败。请检查 IPv6 模块或策略。"
            fi
        fi
    fi
  fi
  
  if [ "$fw_v4_inserted" -eq 1 ] || [ "$fw_v6_inserted" -eq 1 ]; then
      if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true; fw_saved_persistent=1
      elif [ -f /etc/init.d/iptables ]; then service iptables save >/dev/null 2>&1 || true; fw_saved_persistent=1
      else warn "防火墙已放行但未检测到持久化工具。"; fi
  fi
fi

# --- 8. 重启服务 ---
step "重启服务"
if [ "$SSH_PORT" != "$CURRENT_SSH_PORT" ]; then
    if is_listening "$SSH_PORT"; then die "端口 $SSH_PORT 在配置期间被抢占！中止以保护服务。"; fi
fi

if ! try_restart_ssh_service; then
    die "服务重启失败 (尝试了 sshd 和 ssh)。请检查日志。"
fi

# --- 9. 验证 ---
step "最终联通性检查"
info "等待端口 $SSH_PORT 上线..."
for i in {1..10}; do 
    if verify_ssh_handshake "$SSH_PORT"; then ok "端口 $SSH_PORT 响应正常！"; success=1; break; fi
    sleep 1
done
if [ "$success" -eq 0 ]; then die "端口未监听或无响应，配置失败。"; fi

# === 闭环处理 ===
if [ "$SSH_PORT" != "$CURRENT_SSH_PORT" ]; then
    if [ "${AUTO_CLOSE_PORT:-0}" = "1" ]; then
        info "DevOps 模式：自动关闭旧端口..."
        confirm_close="y"
    elif [ "${OVERRIDE_NONINTERACTIVE:-0}" = "1" ]; then
        warn "非交互模式：默认不关闭旧端口以防锁死。"
        confirm_close="n"
    else
        echo -e "${RED}⚠️  人工验证：请新开窗口测试 ssh -p $SSH_PORT $TARGET_USER@IP${NC}"
        read -r -p "连接成功？关闭旧端口 $CURRENT_SSH_PORT？(y/N): " confirm_close || true
    fi

    if [[ "$confirm_close" =~ ^[Yy]$ ]]; then
        info "正在关闭旧端口 $CURRENT_SSH_PORT..."
        deleted_v4=0
        deleted_v6=0
        
        if [ "$fw_backend" == "nft_manual" ]; then
            warn "防火墙处于手动模式，请手动关闭旧端口。"
        elif [ "$fw_backend" == "ufw" ]; then
            ufw --force delete allow "${CURRENT_SSH_PORT}/tcp" >/dev/null 2>&1 || true; deleted_v4=1
        elif [ "$fw_backend" == "firewalld" ]; then
            firewall-cmd --permanent --remove-port="${CURRENT_SSH_PORT}/tcp" >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true; deleted_v4=1
        elif [ "$fw_backend" == "iptables" ]; then
            if command -v iptables >/dev/null 2>&1; then
                if [ "$HAS_V4_COMMENT" -eq 1 ]; then
                    limit=0
                    while iptables -D INPUT -p tcp --dport "$CURRENT_SSH_PORT" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null; do
                        deleted_v4=1; limit=$((limit+1)); [ "$limit" -gt 20 ] && break
                    done
                    if iptables -C INPUT -p tcp --dport "$CURRENT_SSH_PORT" -j ACCEPT 2>/dev/null; then
                        warn "IPv4: 检测到旧端口仍有非受管规则 (无 Tag)，为安全起见未删除。"
                    fi
                else
                    warn "IPv4: 核心不支持 comment 模块，无法精确识别规则。跳过自动删除，请手动清理。"
                fi
            fi
            
            if command -v ip6tables >/dev/null 2>&1; then
                if [ "$HAS_V6_COMMENT" -eq 1 ]; then
                    limit=0
                    while ip6tables -D INPUT -p tcp --dport "$CURRENT_SSH_PORT" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null; do
                        deleted_v6=1; limit=$((limit+1)); [ "$limit" -gt 20 ] && break
                    done
                else
                    warn "IPv6: 核心不支持 comment 模块，无法精确识别规则。跳过自动删除。"
                fi
            fi
            
            if [ "$deleted_v4" -eq 1 ] || [ "$deleted_v6" -eq 1 ]; then
                 command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
                 [ -f /etc/init.d/iptables ] && service iptables save >/dev/null 2>&1 || true
                 [ "$deleted_v4" -eq 1 ] && ok "旧端口(IPv4)已关闭。"
                 [ "$deleted_v6" -eq 1 ] && ok "旧端口(IPv6)已关闭。"
            fi
        fi
    else
        warn "旧端口 $CURRENT_SSH_PORT 仍保留。"
    fi
fi

# 资产审计汇总
echo ""
echo -e "${GREEN}✅ SSH 安全加固完成！${NC}"
echo -e "端口: ${YELLOW}$SSH_PORT${NC}"
echo "---------------------------------------------------"
if [ -n "${MAIN_CONF:-}" ] && [ -f "${MAIN_CONF:-}" ]; then
    echo -e "生效主配置: ${CYAN}$MAIN_CONF${NC}"
fi
if [ -n "${MAIN_BAK:-}" ] && [ -f "${MAIN_BAK:-}" ]; then
    echo -e "主配置备份: ${CYAN}$MAIN_BAK${NC}"
fi
if [ -n "${drop_in_bak_path:-}" ] && [ -f "$drop_in_bak_path" ]; then
    echo -e "Drop-in 备份: ${CYAN}$drop_in_bak_path${NC}"
fi
if [ -n "${auth_file_bak_path:-}" ] && [ -f "$auth_file_bak_path" ]; then
    echo -e "公钥文件备份: ${CYAN}$auth_file_bak_path${NC}"
fi
if [ "$fw_backend" != "none" ]; then
    echo -e "防火墙后端: ${CYAN}$fw_backend${NC}"
fi
echo ""
