#!/usr/bin/env bash
set -e
set -u
set -o pipefail

# ------------share--------------
invocation='echo "" && say_verbose "Calling: ${yellow:-}${FUNCNAME[0]} ${green:-}$*${normal:-}"'
exec 3>&1
if [ -t 1 ] && command -v tput >/dev/null; then
    ncolors=$(tput colors || echo 0)
    if [ -n "$ncolors" ] && [ $ncolors -ge 8 ]; then
        bold="$(tput bold || echo)"
        normal="$(tput sgr0 || echo)"
        black="$(tput setaf 0 || echo)"
        red="$(tput setaf 1 || echo)"
        green="$(tput setaf 2 || echo)"
        yellow="$(tput setaf 3 || echo)"
        blue="$(tput setaf 4 || echo)"
        magenta="$(tput setaf 5 || echo)"
        cyan="$(tput setaf 6 || echo)"
        white="$(tput setaf 7 || echo)"
    fi
fi

say_warning() {
    printf "%b\n" "${yellow:-}xi_singbox_installer: Warning: $1${normal:-}" >&3
}

say_err() {
    printf "%b\n" "${red:-}xi_singbox_installer: Error: $1${normal:-}" >&2
}

say() {
    # using stream 3 (defined in the beginning) to not interfere with stdout of functions
    # which may be used as return value
    printf "%b\n" "${cyan:-}xi_singbox_installer:${normal:-} $1" >&3
}

say_verbose() {
    if [ "$verbose" = true ]; then
        say "$1"
    fi
}

machine_has() {
    eval $invocation

    command -v "$1" >/dev/null 2>&1
    return $?
}

# args:
# remote_path - $1
get_http_header_curl() {
    eval $invocation

    local remote_path="$1"

    curl_options="-I -sSL --retry 5 --retry-delay 2 --connect-timeout 15 "
    curl $curl_options "$remote_path" 2>&1 || return 1
    return 0
}

# args:
# remote_path - $1
get_http_header_wget() {
    eval $invocation

    local remote_path="$1"
    local wget_options="-q -S --spider --tries 5 "
    # Store options that aren't supported on all wget implementations separately.
    local wget_options_extra="--waitretry 2 --connect-timeout 15 "
    local wget_result=''

    wget $wget_options $wget_options_extra "$remote_path" 2>&1
    wget_result=$?

    if [[ $wget_result == 2 ]]; then
        # Parsing of the command has failed. Exclude potentially unrecognized options and retry.
        wget $wget_options "$remote_path" 2>&1
        return $?
    fi

    return $wget_result
}

# Updates global variables $http_code and $download_error_msg
downloadcurl() {
    eval $invocation

    unset http_code
    unset download_error_msg
    local remote_path="$1"
    local out_path="${2:-}"
    local remote_path_with_credential="${remote_path}"
    local curl_options="--retry 20 --retry-delay 2 --connect-timeout 15 -sSL -f --create-dirs "
    local failed=false
    if [ -z "$out_path" ]; then
        curl $curl_options "$remote_path_with_credential" 2>&1 || failed=true
    else
        curl $curl_options -o "$out_path" "$remote_path_with_credential" 2>&1 || failed=true
    fi
    if [ "$failed" = true ]; then
        local response=$(get_http_header_curl $remote_path)
        http_code=$(echo "$response" | awk '/^HTTP/{print $2}' | tail -1)
        download_error_msg="Unable to download $remote_path."
        if [[ $http_code != 2* ]]; then
            download_error_msg+=" Returned HTTP status code: $http_code."
        fi
        say_verbose "$download_error_msg"
        return 1
    fi
    return 0
}

# Updates global variables $http_code and $download_error_msg
downloadwget() {
    eval $invocation

    unset http_code
    unset download_error_msg
    local remote_path="$1"
    local out_path="${2:-}"
    local remote_path_with_credential="${remote_path}"
    local wget_options="--tries 20 "
    # Store options that aren't supported on all wget implementations separately.
    local wget_options_extra="--waitretry 2 --connect-timeout 15 "
    local wget_result=''

    if [ -z "$out_path" ]; then
        wget -q $wget_options $wget_options_extra -O - "$remote_path_with_credential" 2>&1
        wget_result=$?
    else
        wget $wget_options $wget_options_extra -O "$out_path" "$remote_path_with_credential" 2>&1
        wget_result=$?
    fi

    if [[ $wget_result == 2 ]]; then
        # Parsing of the command has failed. Exclude potentially unrecognized options and retry.
        if [ -z "$out_path" ]; then
            wget -q $wget_options -O - "$remote_path_with_credential" 2>&1
            wget_result=$?
        else
            wget $wget_options -O "$out_path" "$remote_path_with_credential" 2>&1
            wget_result=$?
        fi
    fi

    if [[ $wget_result != 0 ]]; then
        local disable_feed_credential=false
        local response=$(get_http_header_wget $remote_path $disable_feed_credential)
        http_code=$(echo "$response" | awk '/^  HTTP/{print $2}' | tail -1)
        download_error_msg="Unable to download $remote_path."
        if [[ $http_code != 2* ]]; then
            download_error_msg+=" Returned HTTP status code: $http_code."
        fi
        say_verbose "$download_error_msg"
        return 1
    fi

    return 0
}

# args:
# remote_path - $1
# [out_path] - $2 - stdout if not provided
download() {
    eval $invocation

    local remote_path="$1"
    local out_path="${2:-}"

    if [[ "$remote_path" != "http"* ]]; then
        cp "$remote_path" "$out_path"
        return $?
    fi

    local failed=false
    local attempts=0
    while [ $attempts -lt 3 ]; do
        attempts=$((attempts + 1))
        failed=false
        if machine_has "curl"; then
            downloadcurl "$remote_path" "$out_path" || failed=true
        elif machine_has "wget"; then
            downloadwget "$remote_path" "$out_path" || failed=true
        else
            say_err "Missing dependency: neither curl nor wget was found."
            exit 1
        fi

        if [ "$failed" = false ] || [ $attempts -ge 3 ] || { [ ! -z $http_code ] && [ $http_code = "404" ]; }; then
            break
        fi

        say "Download attempt #$attempts has failed: $http_code $download_error_msg"
        say "Attempt #$((attempts + 1)) will start in $((attempts * 10)) seconds."
        sleep $((attempts * 10))
    done

    if [ "$failed" = true ]; then
        say_verbose "Download failed: $remote_path"
        return 1
    fi
    return 0
}
# ---------------------------------

remove() {
    eval $invocation

    say "Remove nat rules."
    for RULE in $(iptables -t nat -nL PREROUTING --line-numbers | grep "dpts:45000:50000" | awk '{print $1}' | tac); do
        iptables -t nat -D PREROUTING $RULE
    done
    for RULE in $(ip6tables -t nat -nL PREROUTING --line-numbers | grep "dpts:45000:50000" | awk '{print $1}' | tac); do
        ip6tables -t nat -D PREROUTING $RULE
    done

    containerId=$(docker ps -q --filter "name=^xi-sing-box$")
    if [ -n "$containerId" ]; then
        say "Remove old container xi-sing-box."
        docker stop xi-sing-box >/dev/null 2>&1
        docker rm xi-sing-box >/dev/null 2>&1
    fi
    say "Remove old files."
    rm -f $root_dir/docker-compose.yml
    rm -f $root_dir/info.txt
    rm -fr $root_dir/data
    rm -fr $root_dir/tls
}

precheck() {
    eval $invocation

    if ! machine_has "docker"; then
        say_err "Missing dependency: docker was not found, please install it first."
        exit 1
    fi

    containerId=$(docker ps -q --filter "name=^xi-sing-box$")
    if [ -n "$containerId" ]; then
        say_err "Container xi-sing-box already exists, you can use --reinstall to reinstall it."
        exit 1
    fi

    if [ -e "$root_dir/docker-compose.yml" ]; then
        say "docker-compose.yml already exists, launch it directly."
        runContainer
        exit 0
    fi
}

get_config_from_user() {
    eval $invocation

    # host
    if [ -z "$domain" ]; then
        read -p "请输入域名:" domain
    else
        say "domain: $domain"
    fi
}

generate_config() {
    eval $invocation

    # email
    if [ -z "$email" ]; then
        email="admin@xxx.com"
    else
        say "email: $email"
    fi

    # vless port
    if [ -z "$vless_port" ]; then
        vless_port=443
    else
        say "vless_port: $vless_port"
    fi

    # vless uuid
    if [ -z "$vless_uuid" ]; then
        vless_uuid=$(cat /proc/sys/kernel/random/uuid)
    else
        say "vless_uuid: $vless_uuid"
    fi

    # vless server name
    if [ -z "$vless_server_name" ]; then
        vless_server_name="www.microsoft.com"
    else
        say "vless_server_name: $vless_server_name"
    fi

    # vless private key
    reality_keypair=$(docker run --rm ghcr.io/sagernet/sing-box generate reality-keypair)
    vless_private_key=$(echo "$reality_keypair" | awk '/PrivateKey:/ {print $2}')
    vless_public_key=$(echo "$reality_keypair" | awk '/PublicKey:/ {print $2}')

    # vless short id
    vless_short_id=$(openssl rand -hex 8)

    # hysteria port
    if [ -z "$hysteria_port" ]; then
        hysteria_port=$(shuf -i 35000-40000 -n 1)
    else
        say "hysteria_port: $hysteria_port"
    fi

    # hysteria up mbps
    if [ -z "$hysteria_up_mbps" ]; then
        hysteria_up_mbps=500
    else
        say "hysteria_up_mbps: $hysteria_up_mbps"
    fi

    # hysteria down mbps
    if [ -z "$hysteria_down_mbps" ]; then
        hysteria_down_mbps=500
    else
        say "hysteria_down_mbps: $hysteria_down_mbps"
    fi

    # hysteria obfs
    if [ -z "$hysteria_obfs" ]; then
        hysteria_obfs=$(cat /proc/sys/kernel/random/uuid)
    else
        say "hysteria_obfs: $hysteria_obfs"
    fi

    # hysteria auth str
    if [ -z "$hysteria_auth_str" ]; then
        hysteria_auth_str=$(cat /proc/sys/kernel/random/uuid)
    else
        say "hysteria_auth_str: $hysteria_auth_str"
    fi

}

generate_file() {
    eval $invocation

    if [ $(ip link | grep -o 'WARP:') ]; then
        outbound="warp"
    fi

    mkdir -p data
    cat >$root_dir/data/config.json <<-EOF
{
  "log": {
    "level": "info",
    "output": "/data/sing-box.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "8.8.8.8",
        "detour": "direct"
      },
      {
        "tag": "block",
        "address": "rcode://success"
      }
    ],
    "rules": [
      {
        "geosite": "cn",
        "server": "local"
      },
      {
        "geosite": "category-ads-all",
        "server": "block",
        "disable_cache": true
      }
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": ${vless_port},
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "${vless_uuid}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${vless_server_name}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${vless_server_name}",
            "server_port": 443
          },
          "private_key": "${vless_private_key}",
          "short_id": [
            "${vless_short_id}"
          ]
        }
      }
    },
    {
      "type": "hysteria",
      "tag": "hysteria-in",
      "listen": "::",
      "listen_port": ${hysteria_port},
      "tcp_fast_open": false,
      "udp_fragment": true,
      "sniff": true,
      "sniff_override_destination": true,
      "proxy_protocol": false,
      "proxy_protocol_accept_no_header": false,
      "up_mbps": ${hysteria_up_mbps},
      "down_mbps": ${hysteria_down_mbps},
      "obfs": "${hysteria_obfs}",
      "users": [
        {
          "auth_str": "${hysteria_auth_str}"
        }
      ],
      "recv_window_conn": 15728640,
      "recv_window_client": 67108864,
      "max_conn_client": 2048,
      "disable_mtu_discovery": false,
      "tls": {
        "enabled": true,
        "server_name": "${domain}",
        "alpn": [
          "h3"
        ],
        "min_version": "1.2",
        "max_version": "1.3",
        "certificate_path": "",
        "key_path": "",
        "acme": {
          "domain": [
            "${domain}"
          ],
          "data_directory": "/tls",
          "default_server_name": "",
          "email": "${email}",
          "provider": "letsencrypt"
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "direct",
      "tag": "warp",
      "bind_interface": "WARP"
    }
  ],
  "route": {
    "geoip": {
      "path": "/data/geoip.db",
      "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
      "download_detour": "direct"
    },
    "geosite": {
      "path": "/data/geosite.db",
      "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
      "download_detour": "direct"
    },
    "rules": [
      {
        "geosite": [
          "openai",
          "netflix",
          "cn"
        ],
        "geoip": [
          "cn"
        ],
        "outbound": "${outbound}"
      },
      {
        "geosite": "category-ads-all",
        "outbound": "block"
      }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF

    cat >$root_dir/data/entry.sh <<-'EOF'
#!/bin/bash
set -e

configFilePath="/data/config.json"
logFilePath="/data/sing-box.json"

echo "entry"
sing-box version

# https://sing-box.sagernet.org/configuration/
echo -e "\nconfig:"
sing-box check -c $configFilePath || cat $configFilePath
sing-box format -c /data/config.json -w
cat $configFilePath

echo -e "\nstarting"
sing-box run -c $configFilePath
tail -f $logFilePath
EOF

    cat >$root_dir/docker-compose.yml <<-'EOF'
version: '3'

services:
  sing-box:
    image: ghcr.io/sagernet/sing-box
    container_name: xi-sing-box
    restart: unless-stopped
    network_mode: "host"
    volumes:
      - ./data:/data
      - ./tls:/tls
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    entrypoint: ["/bin/bash", "/data/entry.sh"]
EOF
}

hysteria_mport() {
    # IPv4
    iptables -t nat -A PREROUTING -i eth0 -p udp --dport 45000:50000 -j DNAT --to-destination :$hysteria_port
    # IPv6
    ip6tables -t nat -A PREROUTING -i eth0 -p udp --dport 45000:50000 -j DNAT --to-destination :$hysteria_port
}

# 运行容器
runContainer() {
    eval $invocation

    say "Try to run docker container:"
    {
        docker compose version >/dev/null 2>&1 && docker compose pull && docker compose -f $root_dir/docker-compose.yml up -d
    } || {
        docker-compose version >/dev/null 2>&1 && docker-compose pull && docker-compose -f $root_dir/docker-compose.yml up -d
    }
}

# 检查容器运行状态
check_result() {
    eval $invocation

    docker ps --filter "name=xi-sing-box"

    containerId=$(docker ps -q --filter "name=^xi-sing-box$")
    if [ -n "$containerId" ]; then
        vless_url="vless://$vless_uuid@$domain:$vless_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$vless_server_name&fp=random&pbk=$vless_public_key&sid=$vless_short_id&type=tcp#vless-$domain"
        # hysteria_url="hysteria://$domain:$hysteria_port?mport=45000-50000&protocol=udp&auth=$hysteria_auth_str&obfsParam=$hysteria_obfs&peer=$domain&insecure=0&upmbps=$hysteria_up_mbps&downmbps=$hysteria_down_mbps&alpn=h3#Hys-$domain"
        hysteria_url="hysteria://$domain:$hysteria_port?protocol=udp&auth=$hysteria_auth_str&obfsParam=$hysteria_obfs&peer=$domain&insecure=0&upmbps=$hysteria_up_mbps&downmbps=$hysteria_down_mbps&alpn=h3#Hys-$domain"

        echo ""
        echo "==============================================="
        echo "Congratulations! 恭喜！"
        echo "创建并运行xi-sing-box容器成功。"
        echo ""
        echo "请使用客户端尝试连接你的节点进行测试"
        echo "如果异常，请运行'docker logs -f xi-sing-box'来追踪容器运行日志, 随后可以点击 Ctrl+c 退出日志追踪"
        echo ""
        echo "vless节点如下："
        echo $vless_url
        echo ""
        echo "hysteria节点如下："
        echo $hysteria_url
        echo ""
        echo "以上节点信息已保存到 $root_dir/info.txt"
        echo "Enjoy it~"
        echo "==============================================="

        cat >$root_dir/info.txt <<-EOF
$vless_url
$hysteria_url
EOF
    else
        echo ""
        echo "请查看运行日志，确认容器是否正常运行，点击 Ctrl+c 退出日志追踪"
        echo ""
        docker logs -f sing-box
    fi
}

cat <<'EOF'
 __   _______      _____ _____ _   _  _____ ____   ______   __
 \ \ / /_   _|    / ____|_   _| \ | |/ ____|  _ \ / __ \ \ / /
  \ V /  | |_____| (___   | | |  \| | |  __| |_) | |  | \ V / 
   > <   | |______\___ \  | | | . ` | | |_ |  _ <| |  | |> <  
  / . \ _| |_     ____) |_| |_| |\  | |__| | |_) | |__| / . \ 
 /_/ \_\_____|   |_____/|_____|_| \_|\_____|____/ \____/_/ \_\
 
EOF

root_dir=$(
    cd $(dirname $0)
    pwd
)
# ------------vars-----------、
vless_port=""
vless_uuid=""
vless_server_name=""
vless_private_key=""
vless_public_key=""
vless_short_id=""

hysteria_port=""
hysteria_up_mbps=""
hysteria_down_mbps=""
hysteria_obfs=""
hysteria_auth_str=""

outbound="direct"
warp_private_key=""
warp_public_key=""
warp_short_id=""

domain=""
email=""

verbose=false
# --------------------------

# read params from init cmd
while [ $# -ne 0 ]; do
    name="$1"
    case "$name" in
    --vless_port)
        shift
        vless_port="$1"
        ;;
    --vless_uuid)
        shift
        vless_uuid="$1"
        ;;
    --vless_server_name)
        shift
        vless_server_name="$1"
        ;;
    --hysteria_port)
        shift
        hysteria_port="$1"
        ;;
    --hysteria_up_mbps)
        shift
        hysteria_up_mbps="$1"
        ;;
    --hysteria_down_mbps)
        shift
        hysteria_down_mbps="$1"
        ;;
    --hysteria_obfs)
        shift
        hysteria_obfs="$1"
        ;;
    --hysteria_auth_str)
        shift
        hysteria_auth_str="$1"
        ;;
    -d | --domain | -[Dd]omain)
        shift
        domain="$1"
        ;;
    -m | --mail | -[Mm]ail)
        shift
        email="$1"
        ;;
    --reinstall)
        remove
        ;;
    --remove)
        remove
        exit 0
        ;;
    --verbose | -[Vv]erbose)
        verbose=true
        ;;
    -? | --? | -h | --help | -[Hh]elp)
        script_name="$(basename "$0")"
        echo "Sing-box in Docker"
        echo "Usage: $script_name [options]"
        echo "       $script_name -h|-?|--help"
        echo ""
        exit 0
        ;;
    *)
        say_err "Unknown argument \`$name\`"
        exit 1
        ;;
    esac
    shift
done

main() {
    precheck

    get_config_from_user
    generate_config

    generate_file

    hysteria_mport
    runContainer
    check_result
}

main
