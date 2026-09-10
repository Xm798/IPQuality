#!/usr/bin/env python3
"""Turn proxy share links (or a subscription URL) into a sing-box client config."""

import argparse
import base64
import json
import sys
import urllib.request
from urllib.parse import parse_qs, unquote, urlparse

SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://",
    "tuic://", "socks5://", "socks://", "anytls://",
)


class LinkError(Exception):
    pass


def b64d(data):
    s = data.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sing-box"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def expand(source):
    """Resolve a node link, a newline/base64 node list, or a subscription URL into node links."""
    source = source.strip()
    if source.startswith(("http://", "https://")) and not source.startswith(SCHEMES):
        source = fetch(source)
    if not any(scheme in source for scheme in SCHEMES):
        try:
            source = b64d(source).decode("utf-8", "replace")
        except Exception:
            pass
    links = [line.strip() for line in source.splitlines() if line.strip().startswith(SCHEMES)]
    if not links:
        raise LinkError(
            "no supported node link found; Clash/YAML subscriptions are not supported, "
            "use a sing-box / v2ray style subscription or a raw share link"
        )
    return links


def q1(query, *names, default=None):
    for name in names:
        values = query.get(name)
        if values and values[0] != "":
            return values[0]
    return default


def truthy(value):
    return str(value).lower() in ("1", "true", "yes")


def split_hostport(hostport):
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = hostport.rpartition(":")
    # Hysteria2 allows a port hopping range such as "443,20000-30000".
    port = port.split(",")[0].split("-")[0]
    if not host or not port.isdigit():
        raise LinkError("cannot read host:port from %r" % hostport)
    return host, int(port)


def build_tls(query, server, forced=False):
    security = (q1(query, "security", default="") or "").lower()
    if not forced and security not in ("tls", "reality", "xtls"):
        return None
    tls = {"enabled": True}
    sni = q1(query, "sni", "peer")
    tls["server_name"] = sni or server
    if truthy(q1(query, "insecure", "allowInsecure", "allow_insecure", default="0")):
        tls["insecure"] = True
    alpn = q1(query, "alpn")
    if alpn:
        tls["alpn"] = [part for part in unquote(alpn).split(",") if part]
    fingerprint = q1(query, "fp")
    if fingerprint and fingerprint != "none":
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    public_key = q1(query, "pbk", "publicKey")
    if security == "reality" or public_key:
        if not public_key:
            raise LinkError("reality link is missing the pbk (public key) parameter")
        tls["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": q1(query, "sid", "shortId", default=""),
        }
        # REALITY handshakes only work through uTLS.
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return tls


def build_transport(query, network):
    network = (network or "tcp").lower()
    if network in ("", "tcp", "raw", "none"):
        return None
    if network == "ws":
        path = unquote(q1(query, "path", default="/") or "/")
        transport = {"type": "ws"}
        if "?ed=" in path:
            path, _, ed_query = path.partition("?")
            early_data = parse_qs(ed_query).get("ed", ["2048"])[0]
            transport["max_early_data"] = int(early_data)
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        transport["path"] = path or "/"
        host = q1(query, "host")
        if host:
            transport["headers"] = {"Host": unquote(host)}
        return transport
    if network == "grpc":
        return {"type": "grpc", "service_name": unquote(q1(query, "serviceName", "path", default="") or "")}
    if network in ("h2", "http"):
        transport = {"type": "http", "path": unquote(q1(query, "path", default="/") or "/")}
        host = q1(query, "host")
        if host:
            transport["host"] = [part for part in unquote(host).split(",") if part]
        return transport
    if network == "httpupgrade":
        transport = {"type": "httpupgrade", "path": unquote(q1(query, "path", default="/") or "/")}
        host = q1(query, "host")
        if host:
            transport["host"] = unquote(host)
        return transport
    raise LinkError("transport %r is not supported by sing-box" % network)


def attach(outbound, tls, transport):
    if tls:
        outbound["tls"] = tls
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vless(link):
    url = urlparse(link)
    query = parse_qs(url.query)
    outbound = {
        "type": "vless",
        "server": url.hostname,
        "server_port": url.port or 443,
        "uuid": unquote(url.username or ""),
    }
    flow = q1(query, "flow")
    if flow and flow != "none":
        outbound["flow"] = flow
    encoding = q1(query, "packetEncoding")
    if encoding:
        outbound["packet_encoding"] = encoding
    return attach(outbound, build_tls(query, url.hostname), build_transport(query, q1(query, "type")))


def parse_vmess(link):
    body = link[len("vmess://"):].split("#")[0]
    try:
        node = json.loads(b64d(body))
    except Exception as exc:
        raise LinkError("cannot decode vmess link: %s" % exc)
    host, port = node["add"], int(node["port"])
    outbound = {
        "type": "vmess",
        "server": host,
        "server_port": port,
        "uuid": node["id"],
        "security": node.get("scy") or node.get("security") or "auto",
        "alter_id": int(node.get("aid") or 0),
    }
    query = {}
    for src, dst in (("host", "host"), ("path", "path"), ("sni", "sni"), ("alpn", "alpn"),
                     ("fp", "fp"), ("serviceName", "serviceName")):
        if node.get(src):
            query[dst] = [str(node[src])]
    tls_on = str(node.get("tls", "")).lower() in ("tls", "reality", "true", "1")
    return attach(outbound, build_tls(query, host, forced=tls_on) if tls_on else None,
                  build_transport(query, node.get("net")))


def parse_trojan(link):
    url = urlparse(link)
    query = parse_qs(url.query)
    outbound = {
        "type": "trojan",
        "server": url.hostname,
        "server_port": url.port or 443,
        "password": unquote(url.username or ""),
    }
    return attach(outbound, build_tls(query, url.hostname, forced=True),
                  build_transport(query, q1(query, "type")))


def parse_ss(link):
    body = link[len("ss://"):]
    body = body.split("#")[0]
    query = {}
    if "?" in body:
        body, _, raw_query = body.partition("?")
        query = parse_qs(raw_query)
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        try:
            method, _, password = b64d(userinfo).decode("utf-8").partition(":")
        except Exception:
            method, _, password = unquote(userinfo).partition(":")
    else:
        decoded = b64d(body).decode("utf-8")
        userinfo, _, hostport = decoded.rpartition("@")
        method, _, password = userinfo.partition(":")
    host, port = split_hostport(hostport)
    outbound = {
        "type": "shadowsocks",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }
    plugin = q1(query, "plugin")
    if plugin:
        plugin = unquote(plugin)
        name, _, opts = plugin.partition(";")
        outbound["plugin"] = name
        if opts:
            outbound["plugin_opts"] = opts
    return outbound


def parse_hysteria2(link):
    url = urlparse(link)
    query = parse_qs(url.query)
    password = unquote(url.username or "")
    if url.password:
        password = "%s:%s" % (password, unquote(url.password))
    host, port = url.hostname, url.port or 443
    outbound = {"type": "hysteria2", "server": host, "server_port": port, "password": password}
    obfs = q1(query, "obfs")
    if obfs and obfs.lower() != "none":
        outbound["obfs"] = {
            "type": obfs,
            "password": unquote(q1(query, "obfs-password", "obfs_password", default="") or ""),
        }
    return attach(outbound, build_tls(query, host, forced=True), None)


def parse_tuic(link):
    url = urlparse(link)
    query = parse_qs(url.query)
    host, port = url.hostname, url.port or 443
    outbound = {
        "type": "tuic",
        "server": host,
        "server_port": port,
        "uuid": unquote(url.username or ""),
        "password": unquote(url.password or ""),
        "congestion_control": q1(query, "congestion_control", default="cubic"),
        "udp_relay_mode": q1(query, "udp_relay_mode", default="native"),
    }
    tls = build_tls(query, host, forced=True)
    tls.setdefault("alpn", ["h3"])
    return attach(outbound, tls, None)


def parse_anytls(link):
    url = urlparse(link)
    query = parse_qs(url.query)
    host, port = url.hostname, url.port or 443
    outbound = {
        "type": "anytls",
        "server": host,
        "server_port": port,
        "password": unquote(url.password or url.username or ""),
    }
    return attach(outbound, build_tls(query, host, forced=True), None)


def parse_socks(link):
    url = urlparse(link)
    outbound = {
        "type": "socks",
        "version": "5",
        "server": url.hostname,
        "server_port": url.port or 1080,
    }
    if url.username:
        outbound["username"] = unquote(url.username)
        outbound["password"] = unquote(url.password or "")
    return outbound


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
    "anytls": parse_anytls,
    "socks": parse_socks,
    "socks5": parse_socks,
}


def node_name(link):
    _, _, fragment = link.partition("#")
    if fragment:
        return unquote(fragment)
    if link.startswith("vmess://"):
        try:
            return json.loads(b64d(link[len("vmess://"):].split("#")[0])).get("ps", "")
        except Exception:
            return ""
    return ""


def parse_link(link):
    scheme = link.split("://", 1)[0].lower()
    parser = PARSERS.get(scheme)
    if parser is None:
        raise LinkError("unsupported protocol %r" % scheme)
    outbound = parser(link)
    outbound["tag"] = "proxy"
    return outbound


def make_config(outbound, listen_port, dns_port, dns_server, bootstrap_dns, log_level,
                listen_ipv6=True):
    bootstrap_cidr = bootstrap_dns + ("/128" if ":" in bootstrap_dns else "/32")
    inbounds = [{
        "type": "mixed",
        "tag": "in",
        "listen": "127.0.0.1",
        "listen_port": listen_port,
    }]
    if listen_ipv6:
        # curl picks the address family by resolving the proxy host, so "localhost"
        # has to answer on both stacks for `curl -6 -x socks5://localhost` to work.
        inbounds.append({
            "type": "mixed",
            "tag": "in6",
            "listen": "::1",
            "listen_port": listen_port,
        })
    inbounds.append({
        # Serves /etc/resolv.conf, so dig/nslookup see what the node sees.
        "type": "direct",
        "tag": "dns-in",
        "listen": "127.0.0.1",
        "listen_port": dns_port,
        "network": "udp",
    })
    return {
        "log": {"level": log_level, "timestamp": True},
        "dns": {
            "servers": [
                # The node's own hostname has to be resolved outside the tunnel.
                {"type": "udp", "tag": "local", "server": bootstrap_dns},
                {"type": "https", "tag": "remote", "server": dns_server, "detour": "proxy"},
            ],
            "final": "remote",
        },
        "inbounds": inbounds,
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"inbound": ["dns-in"], "action": "hijack-dns"},
                # Bootstrap lookups would deadlock if they went through the tunnel.
                {"ip_cidr": [bootstrap_cidr], "port": [53], "outbound": "direct"},
            ],
            "default_domain_resolver": {"server": "local"},
            "final": "proxy",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("link", help="node share link, node list, or subscription URL")
    parser.add_argument("--index", type=int, default=0, help="node to use when the source holds several")
    parser.add_argument("--listen-port", type=int, default=1080)
    parser.add_argument("--dns-port", type=int, default=53, help="local DNS listen port")
    parser.add_argument("--dns", default="1.1.1.1", help="DoH resolver reached through the node")
    parser.add_argument("--bootstrap-dns", default="1.1.1.1",
                        help="resolver used for the node's own hostname, outside the tunnel")
    parser.add_argument("--log-level", default="warn")
    parser.add_argument("--no-ipv6", action="store_true", help="skip the ::1 listener")
    parser.add_argument("--list", action="store_true", help="print index, name and protocol of every node")
    parser.add_argument("--expand", action="store_true", help="print every node link, one per line")
    parser.add_argument("--name", action="store_true", help="print the selected node's name")
    args = parser.parse_args()

    try:
        links = expand(args.link)
        if args.expand:
            print("\n".join(links))
            return 0
        if args.list:
            for index, link in enumerate(links):
                print("%d\t%s\t%s" % (index, node_name(link) or "-", link.split("://", 1)[0]))
            return 0
        if not -len(links) <= args.index < len(links):
            raise LinkError("node index %d is out of range, the source holds %d node(s)"
                            % (args.index, len(links)))
        link = links[args.index]
        if args.name:
            print(node_name(link) or "node #%d" % args.index)
            return 0
        outbound = parse_link(link)
    except LinkError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except Exception as exc:
        print("error: cannot parse link: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2

    json.dump(make_config(outbound, args.listen_port, args.dns_port, args.dns,
                          args.bootstrap_dns, args.log_level, not args.no_ipv6),
              sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
