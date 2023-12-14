import json
from enum import Enum
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, SerializeAsAny

from singman.utils import Registry

inbound_registry = Registry()
outbound_registry = Registry()


class LogConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disabled: Optional[bool] = None
    level: Optional[str] = None
    output: Optional[str] = None
    timestamp: Optional[bool] = None


class DNSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class ServerConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        tag: Optional[str]
        address: str
        address_resolver: Optional[str] = None
        address_strategy: Optional[str] = None
        strategy: Optional[str] = None
        detour: Optional[str] = None

    class RuleConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        rule_set: Optional[Union[List[str], str]] = None
        server: Optional[str] = None
        disable_cache: Optional[bool] = None
        rewrite_ttl: Optional[int] = None
        clash_mode: Optional[str] = None
        outbound: Optional[str] = None
        domain: Optional[Union[List[str], str]] = None
        type: Optional[str] = None
        mode: Optional[str] = None
        invert: Optional[bool] = None
        rules: Optional[List["RuleConfig"]] = None

    class FakeipConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        enabled: Optional[bool] = None
        inet4_range: Optional[str] = None
        inet6_range: Optional[str] = None

    servers: Optional[List[ServerConfig]] = None
    rules: Optional[List[RuleConfig]] = None
    final: Optional[str] = None
    strategy: Optional[str] = None
    disable_cache: Optional[bool] = None
    disable_expire: Optional[bool] = None
    independent_cache: Optional[bool] = None
    reverse_mapping: Optional[bool] = None
    fakeip: Optional[FakeipConfig] = None


class RouteConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class RuleConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        outbound: Optional[str] = None
        protocol: Optional[str] = None
        ip_is_private: Optional[bool] = None
        rule_set: Optional[Union[List[str], str]] = None
        network: Optional[str] = None
        port: Optional[int] = Field(None, ge=1, le=65535)
        domain: Optional[List[str]] = None
        clash_mode: Optional[str] = None
        type: Optional[str] = None
        mode: Optional[str] = None
        invert: Optional[bool] = None
        rules: Optional[List["RuleConfig"]] = None

    class RuleSetConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        tag: str
        type: str
        format: str
        url: str
        download_detour: Optional[str] = None

    rules: Optional[List[RuleConfig]] = None
    rule_set: Optional[List[RuleSetConfig]] = None
    final: Optional[str] = None
    auto_detect_interface: Optional[bool] = None
    override_android_vpn: Optional[bool] = None
    default_interface: Optional[str] = None
    default_mark: Optional[int] = None


class ExperimentalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class CacheFileConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        enabled: Optional[bool] = None
        path: Optional[str] = None
        cache_id: Optional[str] = None
        store_fakeip: Optional[bool] = None

    class ClashAPIConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        external_controller: Optional[str] = None
        external_ui: Optional[str] = None
        external_ui_download_url: Optional[str] = None
        external_ui_download_detour: Optional[str] = None
        secret: Optional[str] = None
        default_mode: Optional[str] = None
        store_mode: Optional[bool] = None
        store_selected: Optional[bool] = None
        store_fakeip: Optional[bool] = None
        cache_file: Optional[str] = None
        cache_id: Optional[str] = None

    cache_file: Optional[CacheFileConfig] = None
    clash_api: Optional[ClashAPIConfig] = None


class ListenFieldsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    listen: str
    listen_port: Optional[int] = Field(None, ge=1, le=65535)
    tcp_fast_open: Optional[bool] = None
    tcp_multi_path: Optional[bool] = None
    udp_fragment: Optional[bool] = None
    udp_timeout: Optional[str] = None
    detour: Optional[str] = None
    sniff: Optional[bool] = None
    sniff_override_destination: Optional[bool] = None
    sniff_timeout: Optional[str] = None
    domain_strategy: Optional[str] = None
    udp_disable_domain_unmapping: Optional[bool] = None


class DialFieldsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detour: Optional[str] = None
    bind_interface: Optional[str] = None
    inet4_bind_address: Optional[str] = None
    inet6_bind_address: Optional[str] = None
    routing_mark: Optional[int] = None
    reuse_addr: Optional[bool] = None
    connect_timeout: Optional[str] = None
    tcp_fast_open: Optional[bool] = None
    tcp_multi_path: Optional[bool] = None
    udp_fragment: Optional[bool] = None
    domain_strategy: Optional[str] = None
    fallback_delay: Optional[str] = None


class TLSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class ECHConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        enabled: Optional[bool] = None
        pq_signature_schemes_enabled: Optional[bool] = None
        dynamic_record_sizing_disabled: Optional[bool] = None
        key: Optional[List[str]] = None
        key_path: Optional[str] = None

    class AcmeConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        domain: Optional[str] = None
        data_directory: Optional[str] = None
        email: Optional[str] = None
        provider: Optional[str] = None

    class RealityConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")

        class HandshakeConfig(BaseModel):
            model_config = ConfigDict(extra="forbid")
            server: Optional[str] = None
            server_port: Optional[int] = Field(None, ge=1, le=65535)

        enabled: Optional[bool] = None
        handshake: Optional[HandshakeConfig] = None
        private_key: Optional[str] = None
        public_key: Optional[str] = None
        short_id: Optional[str] = None

    class UtlsConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        enabled: Optional[bool] = None
        fingerprint: Optional[str] = None

    enabled: Optional[bool] = None
    server_name: Optional[str] = None
    alpn: Optional[Union[List[str], str]] = None
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    certificate: Optional[List[str]] = None
    certificate_path: Optional[str] = None
    key: Optional[List[str]] = None
    key_path: Optional[str] = None
    ech: Optional[ECHConfig] = None
    acme: Optional[AcmeConfig] = None
    reality: Optional[RealityConfig] = None
    utls: Optional[UtlsConfig] = None


class UDPOverTCPConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: Optional[bool] = None
    version: Optional[int] = None


class MultiplexConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class TCPBrutalConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        enabled: Optional[bool] = None
        up_mbps: Optional[int] = None
        down_mbps: Optional[int] = None

    enabled: Optional[bool] = None
    protocol: Optional[str] = None
    max_connections: Optional[int] = None
    min_streams: Optional[int] = None
    max_streams: Optional[int] = None
    padding: Optional[bool] = None
    brutal: Optional[TCPBrutalConfig] = None


class V2RayTransportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Optional[str] = None
    host: Optional[List[str]] = None
    path: Optional[str] = None
    method: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


class InboundConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    tag: Optional[str] = None


class OutboundConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    tag: Optional[str] = None


@inbound_registry.register("direct")
class DirectInboundConfig(InboundConfig, ListenFieldsConfig):
    model_config = ConfigDict(extra="forbid")
    type: str = "direct"
    network: Optional[str] = None
    override_address: Optional[str] = None
    override_port: Optional[int] = Field(None, ge=1, le=65535)


@inbound_registry.register("mixed")
class MixedInboundConfig(InboundConfig, ListenFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class UserConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        username: Optional[str] = None
        password: Optional[str] = None

    type: str = "mixed"
    users: Optional[List[UserConfig]] = None
    set_system_proxy: Optional[bool] = None


@inbound_registry.register("vless")
class VlessInboundConfig(InboundConfig, ListenFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class UserConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        name: Optional[str] = None
        uuid: str
        flow: Optional[str] = None

    type: str = "vless"
    users: List[UserConfig]
    tls: Optional[TLSConfig] = None
    multiplex: Optional[MultiplexConfig] = None
    transport: Optional[V2RayTransportConfig] = None


@inbound_registry.register("vmess")
class VmessInboundConfig(InboundConfig, ListenFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class UserConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        name: Optional[str] = None
        uuid: str
        alter_id: int = Field(0, ge=0)

    type: str = "vmess"
    users: List[UserConfig]
    tls: Optional[TLSConfig] = None
    multiplex: Optional[MultiplexConfig] = None
    transport: Optional[V2RayTransportConfig] = None


@inbound_registry.register("hysteria2")
class Hy2InboundConfig(InboundConfig, ListenFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class ObfsConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        type: Optional[str] = None
        password: Optional[str] = None

    class UserConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        name: Optional[str] = None
        password: Optional[str] = None

    type: str = "hysteria2"
    up_mbps: Optional[int] = None
    down_mbps: Optional[int] = None
    obfs: Optional[ObfsConfig] = None
    users: Optional[List[UserConfig]] = None
    ignore_client_bandwidth: Optional[bool] = None
    tls: TLSConfig
    masquerade: Optional[str] = None
    brutal_debug: Optional[bool] = None


@inbound_registry.register("shadowtls")
class ShadowTLSInboundConfig(InboundConfig, ListenFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class UserConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        name: Optional[str] = None
        password: Optional[str] = None

    class HandshakeConfig(DialFieldsConfig):
        model_config = ConfigDict(extra="forbid")
        server: str
        server_port: int = Field(..., ge=1, le=65535)

    type: str = "shadowtls"
    version: Optional[int] = None
    password: Optional[str] = None
    users: Optional[UserConfig] = None
    handshake: HandshakeConfig
    handshake_for_server_name: Optional[Dict[str, HandshakeConfig]]
    strict_mode: Optional[bool] = None


@outbound_registry.register("shadowtls")
class ShadowTLSOutboundConfig(OutboundConfig, DialFieldsConfig):
    type: str = "shadowtls"
    server: str
    server_port: int = Field(..., ge=1, le=65535)
    version: int = 3
    password: Optional[str] = None
    tls: Optional[TLSConfig] = None


class NetworkEnum(str, Enum):
    TCP = "tcp"
    UDP = "udp"


@outbound_registry.register("direct")
class DirectOutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")
    type: str = "direct"
    override_address: Optional[str] = None
    override_port: Optional[int] = Field(None, ge=1, le=65535)
    proxy_protocol: Optional[int] = None


@outbound_registry.register("block")
class BlockOutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")
    type: str = "block"


@outbound_registry.register("dns")
class DNSOutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")
    type: str = "dns"


@outbound_registry.register("socks")
class SocksOutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class VersionEnum(str, Enum):
        V4 = "4"
        V4A = "4a"
        V5 = "5"

    type: str = "socks"
    server: str
    server_port: int = Field(..., ge=1, le=65535)
    version: Optional[VersionEnum] = None
    username: Optional[str] = None
    password: Optional[str] = None
    network: Optional[str] = None
    udp_over_tcp: Optional[UDPOverTCPConfig] = None


@outbound_registry.register("shadowsocks")
class HttpOutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    type: str = "http"
    server: str
    server_port: int = Field(..., ge=1, le=65535)
    username: Optional[str] = None
    password: Optional[str] = None
    path: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    tls: Optional[TLSConfig] = None


@outbound_registry.register("vmess")
class VmessOutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class SecurityEnum(str, Enum):
        AUTO = "auto"
        NONE = "none"
        ZERO = "zero"
        AES_128_GCM = "aes-128-gcm"
        CHACHA20_POLY1305 = "chacha20-poly1305"

    type: str = "vmess"
    server: str
    server_port: int = Field(..., ge=1, le=65535)
    uuid: str
    security: Optional[SecurityEnum] = None
    alter_id: int = Field(0, ge=0)
    global_padding: Optional[bool] = None
    authenticated_length: Optional[bool] = None
    network: Optional[NetworkEnum] = None
    tls: Optional[TLSConfig] = None
    packet_encoding: Optional[str] = None
    transport: Optional[V2RayTransportConfig] = None
    multiplex: Optional[MultiplexConfig] = None


@outbound_registry.register("vless")
class VlessOutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")
    type: str = "vless"
    server: str
    server_port: int = Field(..., ge=1, le=65535)
    uuid: str
    flow: Optional[str] = None
    network: Optional[NetworkEnum] = None
    tls: Optional[TLSConfig] = None
    packet_encoding: Optional[str] = None
    multiplex: Optional[MultiplexConfig] = None
    transport: Optional[V2RayTransportConfig] = None


@outbound_registry.register("wireguard")
class WireguardOutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class PeerConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        server: Optional[str] = None
        server_port: Optional[int] = Field(None, ge=1, le=65535)
        public_key: Optional[str] = None
        pre_shared_key: Optional[str] = None
        allowed_ips: Optional[List[str]] = None
        reserved: Optional[Union[List[int], str]] = None

    type: str = "wireguard"
    server: Optional[str] = None
    server_port: Optional[int] = Field(None, ge=1, le=65535)
    system_interface: Optional[bool] = None
    interface_name: Optional[str] = None
    local_address: Optional[List[str]] = None
    private_key: Optional[str] = None
    peers: Optional[List[PeerConfig]] = None
    peer_public_key: Optional[str] = None
    pre_shared_key: Optional[str] = None
    reserved: Optional[Union[List[int], str]] = None
    workers: Optional[int] = None
    mtu: Optional[int] = None
    network: Optional[NetworkEnum] = None


@outbound_registry.register("hysteria2")
class Hy2OutboundConfig(OutboundConfig, DialFieldsConfig):
    model_config = ConfigDict(extra="forbid")

    class ObfsConfig(BaseModel):
        model_config = ConfigDict(extra="forbid")
        type: Optional[str] = None
        password: Optional[str] = None

    type: str = "hysteria2"
    server: str
    server_port: int = Field(..., ge=1, le=65535)
    up_mbps: Optional[int] = None
    down_mbps: Optional[int] = None
    obfs: Optional[ObfsConfig] = None
    password: Optional[str] = None
    network: Optional[NetworkEnum] = None
    tls: Optional[TLSConfig] = None
    brutal_debug: Optional[bool] = None


@outbound_registry.register("selector")
class SelectorOutboundConfig(OutboundConfig):
    model_config = ConfigDict(extra="forbid")
    type: str = "selector"
    outbounds: List[str]
    default: Optional[str] = None
    interrupt_exist_connections: Optional[bool] = None


class SingboxConfig(BaseModel):
    _config_path: str = None
    model_config = ConfigDict(extra="forbid")
    log: LogConfig
    dns: DNSConfig
    route: RouteConfig
    experimental: Optional[ExperimentalConfig] = None
    inbounds: List[SerializeAsAny[InboundConfig]]
    outbounds: List[SerializeAsAny[OutboundConfig]]


class SingboxClientConfig(BaseModel):
    _config_path: str = None
    outbounds: List[SerializeAsAny[OutboundConfig]]


def parse_server_config(json_file: str) -> SingboxConfig:
    config = SingboxConfig.model_validate(
        json.load(open(json_file, "r", encoding="utf-8"))
    )

    for inbound in config.inbounds:
        ProtoInboundConfig = inbound_registry.get(inbound.type)
        if ProtoInboundConfig is not None:
            inbound.model_config = ProtoInboundConfig.model_validate(
                inbound.model_dump()
            )

    for outbound in config.outbounds:
        ProtoOutboundConfig = outbound_registry.get(outbound.type)
        if ProtoOutboundConfig is not None:
            outbound.model_config = ProtoOutboundConfig.model_validate(
                outbound.model_dump()
            )

    config._config_path = json_file
    return config


def parse_client_config(json_file: str) -> SingboxClientConfig:
    config = SingboxClientConfig.model_validate(
        json.load(open(json_file, "r", encoding="utf-8"))
    )

    for outbound in config.outbounds:
        ProtoOutboundConfig = outbound_registry.get(outbound.type)
        if ProtoOutboundConfig is not None:
            outbound.model_config = ProtoOutboundConfig.model_validate(
                outbound.model_dump()
            )

    config._config_path = json_file
    return config
