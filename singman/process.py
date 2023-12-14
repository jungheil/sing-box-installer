import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from singman.config_parse import (
    InboundConfig,
    OutboundConfig,
    SingboxClientConfig,
    SingboxConfig,
    parse_client_config,
    parse_server_config,
)
from singman.generator import cloudflare_warp_generator, proto_config_registry
from singman.utils import input_args

src_root = Path(__file__).parent


def singman_init(path: str) -> None:
    root_path = Path(path)
    root_path.mkdir(parents=True, exist_ok=True)
    (root_path / "data").mkdir(parents=True, exist_ok=True)

    if not (root_path / "docker-compose.yml").is_file():
        (root_path / "docker-compose.yml").write_text(
            (src_root / "template" / "docker-compose.yml").read_text()
        )

    if not (root_path / "data" / "config.json").is_file():
        (root_path / "data" / "config.json").write_text(
            (src_root / "template" / "server.json").read_text()
        )

    if not (root_path / "data" / "client_config.json").is_file():
        (root_path / "data" / "client_config.json").write_text(
            SingboxClientConfig(outbounds=[]).model_dump_json(exclude_none=True)
        )

    if not (root_path / "data" / "entry.sh").is_file():
        (root_path / "data" / "entry.sh").write_text(
            (src_root / "template" / "entry.sh").read_text()
        )


def get_proto_config(
    server_conf: SingboxConfig, client_conf: SingboxClientConfig
) -> Tuple[List[InboundConfig], List[OutboundConfig]]:
    def _get_tag(conf: Union[InboundConfig, OutboundConfig]) -> str:
        if conf.tag is None:
            return ""
        if conf.tag.split("-")[-1] in ["in", "out"]:
            return "-".join(conf.tag.split("-")[:-1])
        return conf.tag

    conf_type = ["vless", "vmess", "trojan", "hysteria2"]
    all_server = [i for i in server_conf.inbounds if i.type in conf_type]
    all_client = [i for i in client_conf.outbounds if i.type in conf_type]
    server_tag = set(map(lambda x: _get_tag(x), all_server))
    client_tag = set(map(lambda x: _get_tag(x), all_client))
    assert len(all_server) == len(server_tag) and len(all_client) == len(
        client_tag
    ), "tag must be unique in server and client config"

    available_tag = server_tag & client_tag

    available_server_conf = [i for i in all_server if _get_tag(i) in available_tag]
    ignore_server_conf = [i for i in all_server if _get_tag(i) not in available_tag]

    client_tag_map = dict((_get_tag(i), i) for i in all_client)
    available_client_conf = [client_tag_map[_get_tag(i)] for i in available_server_conf]
    ignore_client_conf = [i for i in all_client if _get_tag(i) not in available_tag]

    if len(ignore_server_conf) > 0:
        print("WARNING: The following server config will be ignored:")
        for i in ignore_server_conf:
            print(i.model_dump_json(exclude_none=True))
    if len(ignore_client_conf) > 0:
        print("WARNING: The following client config will be ignored:")
        for i in ignore_client_conf:
            print(i.model_dump_json(exclude_none=True))

    return available_server_conf, available_client_conf


def singman_parse(
    server_config_path: str, client_config_path: str
) -> Tuple[SingboxConfig, SingboxClientConfig]:
    server_config = parse_server_config(server_config_path)
    client_config = parse_client_config(client_config_path)

    return server_config, client_config


def singman_add_server(
    server_conf: SingboxConfig, client_conf: SingboxClientConfig, **kwargs
):
    node_name = kwargs.get("node_name", None)
    print("select server type:")
    proto_idx_map: Dict[int, str] = dict(
        (i, key) for i, key in enumerate(proto_config_registry.data_dict)
    )
    print("0: return to menu")
    for i, key in proto_idx_map.items():
        print(f"{i+1}: {key}")
    proto_idx = int(input("> "))
    if proto_idx == 0:
        return
    try:
        proto_config_generator = proto_config_registry.get(proto_idx_map[proto_idx - 1])
    except KeyError:
        raise NotImplementedError
    inbound_conf, outbound_conf = proto_config_generator(node_name=node_name)

    server_conf.inbounds.append(inbound_conf)
    client_conf.outbounds.append(outbound_conf)


def singman_del_proto(server_conf: SingboxConfig, client_conf: SingboxClientConfig):
    inbound_conf, outbound_conf = get_proto_config(server_conf, client_conf)
    print("Select the index to delete:")
    print("[0]: return to menu")
    for i, c in enumerate(inbound_conf):
        print(f"[{i+1}]: ", c.model_dump_json(exclude_none=True))
    idx = int(input("> "))
    if idx == 0:
        return
    try:
        server_conf.inbounds.remove(inbound_conf[idx - 1])
        client_conf.outbounds.remove(outbound_conf[idx - 1])
    except IndexError:
        print("Index out of range")


def singman_save_config(
    server_conf: SingboxConfig, client_conf: SingboxClientConfig, **kwargs
):
    node_name = kwargs.get("node_name", None)
    Path(server_conf._config_path).write_text(
        server_conf.model_dump_json(exclude_none=True)
    )
    Path(client_conf._config_path).write_text(
        client_conf.model_dump_json(exclude_none=True)
    )
    if node_name is not None:
        singman_uploud_config(client_conf=client_conf, node_name=node_name)


def singman_show_config(server_conf: SingboxConfig, client_conf: SingboxClientConfig):
    inbound_conf, _ = get_proto_config(server_conf, client_conf)
    for i, c in enumerate(inbound_conf):
        print(f"[{i+1}]: ", c.model_dump_json(exclude_none=True))


@input_args(
    "warp_file", str, "input warp config file path", "/opt/warp-go/singbox.json"
)
def singman_add_cloudflare_warp(server_conf: SingboxConfig, warp_file: str):
    if not Path(warp_file).is_file():
        print("warp config file not exists, ignored")
        return
    if any(map(lambda x: "warp" in x.tag, server_conf.outbounds)):
        print("warp config already exists, ignored")
        return
    warp_inbound_config = cloudflare_warp_generator(warp_file)
    warp_tag = warp_inbound_config.tag
    server_conf.outbounds.append(warp_inbound_config)
    warp_outbound_rule = set(
        [
            "geoip-cn",
            "geosite-cn",
            "geosite-openai",
            "geosite-disney",
            "geosite-netflix",
        ]
    )
    for i in server_conf.route.rules:
        if i.rule_set is None:
            continue
        if set(i.rule_set).intersection(warp_outbound_rule):
            i.outbound = warp_tag


@input_args("domain", str, "input domain", default="")
@input_args("token", str, "input token", default="", is_pass=True)
def singman_uploud_config(
    client_conf: SingboxClientConfig,
    node_name: Optional[str] = None,
    domain: str = "",
    token: str = "",
):
    if node_name is None:
        return
    if len(domain.rstrip()) == 0:
        return
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "https://" + domain
    url = domain + "/proxyData/" + node_name + "?token=" + token

    data = client_conf.model_dump_json(exclude_none=True)

    req = urllib.request.Request(
        url,
        data=data.encode("utf-8"),
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1941.0 Safari/537.36",
        },
    )
    try:
        response = urllib.request.urlopen(req)
    except IndexError as e:
        print("upload failed")
        print(e)
        return

    if response.status != 200:
        print("upload failed")
        return


def singman_menu(
    server_conf: SingboxConfig, client_conf: SingboxClientConfig, **kwargs
):
    node_name = kwargs.get("node_name", None)

    print("==========Singman Menu==========")
    print("input 0 to save and exit")
    print("input 1 to show proto config")
    print("input 2 to add proto config")
    print("input 3 to delete proto config")
    print("input 4 to add cloudflare warp config")

    try:
        option = int(input("> "))
    except ValueError:
        print("Invalid option")
        return
    if option == 0:
        singman_save_config(server_conf, client_conf, node_name=node_name)
        exit()
    elif option == 1:
        singman_show_config(server_conf, client_conf)
    elif option == 2:
        singman_add_server(server_conf, client_conf, node_name=node_name)
    elif option == 3:
        singman_del_proto(server_conf, client_conf)
    elif option == 4:
        singman_add_cloudflare_warp(server_conf)
    else:
        print("Invalid option")
