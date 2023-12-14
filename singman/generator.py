import json
import random
import secrets
import uuid
from typing import Any, Dict, Optional

from singman.config_parse import (
    Hy2InboundConfig,
    Hy2OutboundConfig,
    MultiplexConfig,
    TLSConfig,
    VlessInboundConfig,
    VlessOutboundConfig,
    WireguardOutboundConfig,
    parse_server_config,
)
from singman.utils import Registry, generate_reality_key, input_args

proto_config_registry = Registry()


@proto_config_registry.register("vless_reality_vision")
@input_args("domain", str, "input domain", default="www.example.com")
@input_args("port", int, "input port", default=443)
@input_args(
    "reality_server_name", str, "input reality server name", default="update.microsoft"
)
def vless_reality_vision_generator(
    domain: str,
    port: Optional[int] = 443,
    reality_server_name: Optional[str] = "update.microsoft",
    node_name: Optional[str] = None,
    **kwargs: Dict[str, Any],
):
    sniff = kwargs.get("sniff", True)
    domain_strategy = kwargs.get("domain_strategy", "prefer_ipv4")
    port = port or random.randint(35000, 39999)

    tag = f"vless-reality-vision-{secrets.token_hex(nbytes=4)}"
    if node_name is not None:
        tag = f"{node_name}-{tag}"
    user_uuid = str(uuid.uuid4())
    reality_private_key, reality_public_key = generate_reality_key()
    reality_short_id = secrets.token_hex(nbytes=8)

    server_config: VlessInboundConfig = VlessInboundConfig(
        tag=tag + "-in",
        listen="::",
        listen_port=port,
        sniff=sniff,
        sniff_override_destination=True,
        users=[
            VlessInboundConfig.UserConfig(  # type: ignore
                name="", uuid=user_uuid, flow="xtls-rprx-vision"
            )
        ],
        tls=TLSConfig(
            enabled=True,
            server_name=reality_server_name,
            reality=TLSConfig.RealityConfig(
                enabled=True,
                handshake=TLSConfig.RealityConfig.HandshakeConfig(
                    server=reality_server_name,
                    server_port=443,
                ),
                private_key=reality_private_key,
                short_id=reality_short_id,
            ),
        ),
    )
    client_config = VlessOutboundConfig(
        tag=tag + "-out",
        server=domain,
        server_port=port,
        uuid=user_uuid,
        flow="xtls-rprx-vision",
        packet_encoding="xudp",
        domain_strategy=domain_strategy,
        tls=TLSConfig(
            enabled=True,
            server_name=reality_server_name,
            reality=TLSConfig.RealityConfig(
                enabled=True,
                public_key=reality_public_key,
                short_id=reality_short_id,
            ),
            utls=TLSConfig.UtlsConfig(enabled=True, fingerprint="chrome"),
        ),
    )  # type: ignore
    return server_config, client_config


@proto_config_registry.register("vless_reality_brutal")
@input_args("domain", str, "input domain", default="www.example.com")
@input_args("port", int, "input port", default=443)
@input_args(
    "reality_server_name", str, "input reality server name", default="update.microsoft"
)
def vless_reality_brutal_generator(
    domain: str,
    port: Optional[int] = 443,
    reality_server_name: Optional[str] = "update.microsoft",
    node_name: Optional[str] = None,
    **kwargs: Dict[str, Any],
):
    sniff = kwargs.get("sniff", True)
    domain_strategy = kwargs.get("domain_strategy", "prefer_ipv4")
    port = port or random.randint(35000, 39999)

    tag = f"vless-reality-brutal-{secrets.token_hex(nbytes=4)}"
    if node_name is not None:
        tag = f"{node_name}-{tag}"
    user_uuid = str(uuid.uuid4())
    reality_private_key, reality_public_key = generate_reality_key()
    reality_short_id = secrets.token_hex(nbytes=8)

    server_config: VlessInboundConfig = VlessInboundConfig(
        tag=tag + "-in",
        listen="::",
        listen_port=port,
        sniff=sniff,
        sniff_override_destination=True,
        users=[VlessInboundConfig.UserConfig(name="", uuid=user_uuid)],  # type: ignore
        tls=TLSConfig(
            enabled=True,
            server_name=reality_server_name,
            reality=TLSConfig.RealityConfig(
                enabled=True,
                handshake=TLSConfig.RealityConfig.HandshakeConfig(
                    server=reality_server_name,
                    server_port=443,
                ),
                private_key=reality_private_key,
                short_id=reality_short_id,
            ),
        ),
        multiplex=MultiplexConfig(
            enabled=True,
            padding=True,
            brutal=MultiplexConfig.TCPBrutalConfig(
                enabled=True, up_mbps=50, down_mbps=50
            ),
        ),
    )

    client_config = VlessOutboundConfig(
        tag=tag + "-out",
        server=domain,
        server_port=port,
        uuid=user_uuid,
        packet_encoding="xudp",
        domain_strategy=domain_strategy,
        tls=TLSConfig(
            enabled=True,
            server_name=reality_server_name,
            reality=TLSConfig.RealityConfig(
                enabled=True,
                public_key=reality_public_key,
                short_id=reality_short_id,
            ),
            utls=TLSConfig.UtlsConfig(enabled=True, fingerprint="chrome"),
        ),
        multiplex=MultiplexConfig(
            enabled=True,
            protocol="h2mux",
            max_connections=4,
            min_streams=4,
            padding=True,
            brutal=MultiplexConfig.TCPBrutalConfig(
                enabled=True, up_mbps=50, down_mbps=50
            ),
        ),
    )  # type: ignore
    return server_config, client_config


@proto_config_registry.register("hysteria2")
@input_args("domain", str, "input domain", default="www.example.com")
@input_args("port", int, "input port", default=random.randint(35000, 39999))
@input_args("masquerade", str, "input masquerade", default="https://update.microsoft")
def hysteria2_generator(
    domain: str,
    port: Optional[int] = 443,
    masquerade: str = "https://update.microsoft",
    node_name: Optional[str] = None,
    **kwargs: Dict[str, Any],
):
    domain_strategy = kwargs.get("domain_strategy", "prefer_ipv4")
    port = port or random.randint(35000, 39999)
    tag = f"hysteria2-{secrets.token_hex(nbytes=4)}"
    if node_name is not None:
        tag = f"{node_name}-{tag}"
    password = secrets.token_hex(nbytes=16)

    server_config = Hy2InboundConfig(
        type="hysteria2",
        tag=tag + "-in",
        listen="::",
        listen_port=port,
        users=[Hy2InboundConfig.UserConfig(password=password)],
        tls=TLSConfig(
            enabled=True,
            server_name=domain,
            alpn=["h3"],
            acme=TLSConfig.AcmeConfig(
                domain=domain,
                data_directory="/tls",
                email="admin@xxx.xxx",
                provider="letsencrypt",
            ),
        ),
        masquerade=masquerade,
    )  # type: ignore
    client_config = Hy2OutboundConfig(
        tag=tag + "-out",
        server=domain,
        server_port=port,
        password=password,
        down_mbps=50,
        up_mbps=50,
        domain_strategy=domain_strategy,
        tls=TLSConfig(enabled=True, server_name=domain, alpn=["h3"]),
    )  # type: ignore
    return server_config, client_config


def cloudflare_warp_generator(
    json_file: Optional[str] = None,
) -> WireguardOutboundConfig:
    if json_file is not None:
        warp_config = json.load(open(json_file, "r"))

        config = WireguardOutboundConfig.model_validate(warp_config["outbounds"][0])
        config.tag = f"warp-{secrets.token_hex(nbytes=4)}-out"
    else:
        raise NotImplementedError
    return config
