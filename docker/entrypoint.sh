#!/bin/bash
set -uo pipefail

SOCKS_PORT="${SOCKS_PORT:-1080}"
LINK="${LINK:-}"
NODE_INDEX="${NODE_INDEX:-0}"
DNS_SERVER="${DNS_SERVER:-1.1.1.1}"
SB_LOG_LEVEL="${SB_LOG_LEVEL:-warn}"
CONFIG=/tmp/sing-box.json
SB_LOG=/tmp/sing-box.log
NODES=/tmp/nodes.txt
list_nodes=0
sb_pid=""

usage(){
cat <<'USAGE'
IP quality check through a sing-box node.
通过 sing-box 节点运行 IP 质量体检。

  docker run --rm -it <image> <link> [options] [ip.sh args...]

<link>  node share link (vless/vmess/trojan/ss/hysteria2/tuic/anytls/socks5),
        a base64 node list, or a subscription URL. Also settable via $LINK.

Wrapper options 包装脚本参数:
  --node N        node to use from a multi-node subscription (default 0)
  --list-nodes    print the nodes of a subscription and exit
  --socks-port P  local sing-box listen port (default 1080)
  --dns ADDR      DoH resolver used through the node (default 1.1.1.1)
  --sb-log LEVEL  sing-box log level (default warn)
  --help          this text

Anything else is forwarded to ip.sh, e.g. -E -4 -j -f -o /out/report.ansi.

  docker run --rm -it <image> "vless://..." -E
  docker run --rm -it <image> "https://sub.example.com/link" --list-nodes
  docker run --rm -it <image> "https://sub.example.com/link" --node 3 -4
USAGE
}

die(){ echo "error: $*" >&2; exit 1; }

cleanup(){
  [[ -n $sb_pid ]] && kill "$sb_pid" 2>/dev/null
  wait "$sb_pid" 2>/dev/null
}
trap cleanup EXIT INT TERM

# The link comes first, or through $LINK; later arguments belong to ip.sh.
if [[ $# -gt 0 && -z $LINK && $1 != -* ]]; then
  LINK="$1"
  shift
fi

ipsh_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help) usage; exit 0 ;;
    --node) NODE_INDEX="${2:-}"; shift 2 ;;
    --node=*) NODE_INDEX="${1#*=}"; shift ;;
    --list-nodes) list_nodes=1; shift ;;
    --socks-port) SOCKS_PORT="${2:-}"; shift 2 ;;
    --socks-port=*) SOCKS_PORT="${1#*=}"; shift ;;
    --dns) DNS_SERVER="${2:-}"; shift 2 ;;
    --dns=*) DNS_SERVER="${1#*=}"; shift ;;
    --sb-log) SB_LOG_LEVEL="${2:-}"; shift 2 ;;
    --sb-log=*) SB_LOG_LEVEL="${1#*=}"; shift ;;
    *://*) [[ -z $LINK ]] && LINK="$1" || ipsh_args+=("$1"); shift ;;
    *) ipsh_args+=("$1"); shift ;;
  esac
done

[[ -z $LINK ]] && { usage; exit 1; }

# A subscription URL is fetched once, then every step works off the node list.
python3 /opt/ipquality/link2singbox.py "$LINK" --expand >"$NODES" || exit $?
node_count=$(wc -l <"$NODES")
nodes=$(cat "$NODES")

if [[ $list_nodes -eq 1 ]]; then
  exec python3 /opt/ipquality/link2singbox.py "$nodes" --list
fi

index=$NODE_INDEX
((index < 0)) && index=$((node_count + index))
((index < 0 || index >= node_count)) &&
  die "node index $NODE_INDEX is out of range, the source holds $node_count node(s)"
node_link=$(sed -n "$((index + 1))p" "$NODES")

bootstrap_dns=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)
[[ -z $bootstrap_dns || $bootstrap_dns == 127.0.0.1 ]] && bootstrap_dns="$DNS_SERVER"

ipv6_arg=()
[[ -f /proc/net/if_inet6 ]] || ipv6_arg=(--no-ipv6)

python3 /opt/ipquality/link2singbox.py "$node_link" \
  --listen-port "$SOCKS_PORT" "${ipv6_arg[@]}" \
  --dns "$DNS_SERVER" --bootstrap-dns "$bootstrap_dns" \
  --log-level "$SB_LOG_LEVEL" >"$CONFIG" || exit $?

node_label=$(python3 /opt/ipquality/link2singbox.py "$node_link" --name)
echo "Node 节点: $node_label ($(jq -r '.outbounds[0].type + " " + .outbounds[0].server' "$CONFIG"))"
echo "sing-box: $(sing-box version | awk 'NR==1 {print $3}')"

sing-box run -c "$CONFIG" >"$SB_LOG" 2>&1 &
sb_pid=$!

for _ in $(seq 1 50); do
  nc -z 127.0.0.1 "$SOCKS_PORT" 2>/dev/null && break
  kill -0 "$sb_pid" 2>/dev/null || break
  sleep 0.2
done

kill -0 "$sb_pid" 2>/dev/null || { cat "$SB_LOG" >&2; die "sing-box exited before it was ready"; }

# ip.sh reads the exit IP's reputation from DNS blocklists and judges unlock
# type with dig/nslookup, so the container has to resolve the way the node does.
printf 'nameserver 127.0.0.1\noptions timeout:3 attempts:2\n' >/etc/resolv.conf

proxy="socks5://localhost:$SOCKS_PORT"
exit_ip=""
for probe in https://icanhazip.com https://ipinfo.io/ip https://api.ipify.org; do
  answer=$(curl -fsS -x "$proxy" --max-time 15 "$probe" 2>/dev/null | tr -d '[:space:]')
  [[ $answer =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || $answer =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:]*$ ]] && {
    exit_ip="$answer"
    break
  }
done
[[ -z $exit_ip ]] && { cat "$SB_LOG" >&2; die "no traffic passes through the node"; }
nslookup -timeout=5 github.com 127.0.0.1 >/dev/null 2>&1 ||
  { cat "$SB_LOG" >&2; die "the node's DNS does not answer on 127.0.0.1:53"; }
echo "Egress 出口: $exit_ip"
echo

bash /opt/ipquality/ip.sh -n -x "$proxy" "${ipsh_args[@]}"
exit $?
