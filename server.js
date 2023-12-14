/**
 ** 使用说明：
 *  1. 设置 Environment Variables：
 *     TOKEN, TGBotToken, TGChatID
 *  2. 新建并设置 KV Namespace Bindings：
 *     proxyData
 */

const CLIENTCONFIG = {
  log: { level: "debug", timestamp: true },
  experimental: {
    clash_api: {
      external_controller: "127.0.0.1:9090",
      external_ui: "ui",
      secret: "",
      default_mode: "rule",
    },
    cache_file: { enabled: true, store_fakeip: false },
  },
  dns: {
    servers: [
      {
        tag: "proxyDns",
        address: "https://8.8.8.8/dns-query",
        detour: "proxy",
      },
      {
        tag: "localDns",
        address: "https://223.5.5.5/dns-query",
        detour: "direct",
      },
      { tag: "block", address: "rcode://success" },
    ],
    rules: [
      { outbound: "any", server: "localDns", disable_cache: true },
      { clash_mode: "direct", server: "localDns" },
      { clash_mode: "global", server: "proxyDns" },
      {
        type: "logical",
        mode: "and",
        rules: [
          {
            rule_set: "geosite-geolocation-!cn",
            invert: true,
          },
          {
            rule_set: ["geosite-cn", "geosite-category-companies@cn"],
          },
        ],
        server: "localDns",
      },
      {
        domain: ["ghproxy.com", "cdn.jsdelivr.net", "testingcf.jsdelivr.net"],
        server: "localDns",
      },
      { rule_set: "geosite-category-ads-all", server: "block" },
      { rule_set: "geosite-geolocation-!cn", server: "proxyDns" },
    ],
    strategy: "prefer_ipv4",
  },
  inbounds: [
    {
      type: "tun",
      inet4_address: "172.19.0.1/30",
      inet6_address: "fdfe:dcba:9876::1/126",
      inet6_route_exclude_address: ["fc00::/7"],
      mtu: 9000,
      auto_route: true,
      strict_route: true,
      sniff: true,
      endpoint_independent_nat: false,
      stack: "system",
      platform: {
        http_proxy: {
          enabled: true,
          server: "127.0.0.1",
          server_port: 2080,
        },
      },
    },
    {
      type: "mixed",
      listen: "127.0.0.1",
      listen_port: 2080,
      sniff: true,
      users: [],
    },
  ],
  outbounds: [
    { tag: "proxy", type: "selector", outbounds: ["auto", "direct"] },
    {
      tag: "🤖 OpenAI",
      type: "selector",
      outbounds: ["proxy", "direct"],
    },
    {
      tag: "🌌 Google",
      type: "selector",
      outbounds: ["proxy", "direct"],
    },
    {
      tag: "📟 Telegram",
      type: "selector",
      outbounds: ["proxy", "direct"],
    },
    {
      tag: "🐦 Twitter",
      type: "selector",
      outbounds: ["proxy", "direct"],
    },
    {
      tag: "👤 Facebook",
      type: "selector",
      outbounds: ["proxy", "direct"],
    },
    {
      tag: "🧩 Microsoft",
      type: "selector",
      outbounds: ["proxy", "direct"],
    },
    {
      tag: "🛍️ Amazon",
      type: "selector",
      outbounds: ["direct", "proxy"],
    },
    { tag: "🍎 Apple", type: "selector", outbounds: ["direct", "proxy"] },
    {
      tag: "📺 Bilibili",
      type: "selector",
      outbounds: ["direct", "proxy"],
    },
    {
      tag: "🎬 MediaVideo",
      type: "selector",
      outbounds: ["proxy", "direct"],
    },
    { tag: "🎮 Game", type: "selector", outbounds: ["direct", "proxy"] },
    { tag: "🌏 !cn", type: "selector", outbounds: ["proxy", "direct"] },
    { tag: "🌏 cn", type: "selector", outbounds: ["direct", "proxy"] },
    {
      tag: "🛑 AdBlock",
      type: "selector",
      outbounds: ["block", "direct"],
    },
    {
      tag: "auto",
      type: "urltest",
      outbounds: [],
      url: "http://www.gstatic.com/generate_204",
      interval: "10m",
      tolerance: 50,
    },
    { type: "direct", tag: "direct" },
    { type: "dns", tag: "dns-out" },
    { type: "block", tag: "block" },
  ],
  route: {
    auto_detect_interface: true,
    final: "proxy",
    rules: [
      {
        type: "logical",
        mode: "or",
        rules: [
          {
            protocol: "dns",
          },
          {
            port: 53,
          },
        ],
        outbound: "dns-out",
      },
      { network: "udp", port: 443, outbound: "block" },
      { rule_set: "geosite-category-ads-all", outbound: "🛑 AdBlock" },
      {
        domain: [
          "mousegesturesapi.com",
          "cf-se.com",
          "googleads.g.doubleclick.net",
          "adservice.google.com",
          "appcenter.ms",
          "app-measurement.com",
          "firebase.io",
          "crashlytics.com",
          "google-analytics.com",
        ],
        outbound: "🛑 AdBlock",
      },
      { clash_mode: "direct", outbound: "direct" },
      { clash_mode: "global", outbound: "proxy" },
      { rule_set: "geosite-openai", outbound: "🤖 OpenAI" },
      { rule_set: "geosite-github", outbound: "🌌 Google" },
      {
        rule_set: ["geoip-google", "geosite-google", "geosite-youtube"],
        outbound: "🌌 Google",
      },
      {
        rule_set: ["geoip-telegram", "geosite-telegram"],
        outbound: "📟 Telegram",
      },
      { rule_set: "geoip-twitter", outbound: "🐦 Twitter" },
      { rule_set: "geosite-twitter", outbound: "🐦 Twitter" },
      {
        rule_set: ["geoip-facebook", "geosite-facebook", "geosite-instagram"],
        outbound: "👤 Facebook",
      },
      { rule_set: "geosite-amazon", outbound: "🛍️ Amazon" },
      { rule_set: "geosite-apple", outbound: "🍎 Apple" },
      { rule_set: "geosite-microsoft", outbound: "🧩 Microsoft" },
      { rule_set: "geosite-category-games", outbound: "🎮 Game" },
      { rule_set: "geosite-bilibili", outbound: "📺 Bilibili" },
      {
        rule_set: [
          "geoip-netflix",
          "geosite-tiktok",
          "geosite-netflix",
          "geosite-hbo",
          "geosite-disney",
          "geosite-primevideo",
        ],
        outbound: "🎬 MediaVideo",
      },
      { rule_set: "geosite-geolocation-!cn", outbound: "🌏 !cn" },
      { ip_is_private: true, outbound: "🌏 cn" },
      {
        type: "logical",
        mode: "and",
        rules: [
          {
            rule_set: "geosite-geolocation-!cn",
            invert: true,
          },
          {
            rule_set: [
              "geoip-cn",
              "geosite-cn",
              "geosite-category-companies@cn",
            ],
          },
        ],
        outbound: "🌏 cn",
      },
    ],
    rule_set: [
      {
        tag: "geoip-google",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/google.srs",
        download_detour: "direct",
      },
      {
        tag: "geoip-telegram",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/telegram.srs",
        download_detour: "direct",
      },
      {
        tag: "geoip-twitter",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/twitter.srs",
        download_detour: "direct",
      },
      {
        tag: "geoip-facebook",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/facebook.srs",
        download_detour: "direct",
      },
      {
        tag: "geoip-netflix",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/netflix.srs",
        download_detour: "direct",
      },
      {
        tag: "geoip-cn",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-openai",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-youtube",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/youtube.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-google",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/google.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-github",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/github.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-telegram",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/telegram.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-twitter",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/twitter.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-facebook",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/facebook.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-instagram",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/instagram.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-amazon",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/amazon.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-apple",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/apple.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-microsoft",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/microsoft.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-category-games",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-games.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-bilibili",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/bilibili.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-tiktok",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/tiktok.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-netflix",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-hbo",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/hbo.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-disney",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/disney.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-primevideo",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/primevideo.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-cn",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cn.srs",
        download_detour: "direct",
      },
      {
        tag: "geosite-geolocation-!cn",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
        download_detour: "direct",
      },
      {
        type: "remote",
        tag: "geosite-category-companies@cn",
        format: "binary",
        url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-companies@cn.srs",
      },
      {
        tag: "geosite-category-ads-all",
        type: "remote",
        format: "binary",
        url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs",
        download_detour: "direct",
      },
    ],
  },
};

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const method = request.method;
  const url = new URL(request.url);
  const urlPath = url.pathname.split("/").filter((item) => {
    return item.trim() != "";
  });
  const token = url.searchParams.get("token");
  const body = await request.text();
  const ip = request.headers.get("CF-Connecting-IP");

  let ret;
  if (urlPath.length == 0) {
    let help_msg = {
      url: [
        {
          desc: "get sing-box config",
          url: "/getSingBox",
          method: "GET",
          params: "token",
        },
        {
          desc: "get share link",
          url: "/getLink",
          method: "GET",
          params: "token; b64 (0 or 1)",
        },
        {
          desc: "set proxy data",
          url: "/proxyData/{key}",
          method: "Post",
          params: "token",
          body: "{value}",
        },
      ],
    };
    ret = new Response(JSON.stringify(help_msg, null, 2), { status: 200 });
  } else if (token !== TOKEN) {
    ret = new Response("Invalid Token", { status: 403 });
  } else if (method == "GET") {
    if (urlPath[0] == "getSingBox") {
      templateURL = url.searchParams.get("templateURL");
      await getClientConfig(templateURL)
        .then((data) => {
          ret = new Response(data);
        })
        .catch((error) => {
          ret = new Response(error, { status: 500 });
        });
    } else if (urlPath[0] == "getLink") {
      b64 = url.searchParams.get("b64");
      await getClientLink(b64)
        .then((data) => {
          ret = new Response(data);
        })
        .catch((error) => {
          ret = new Response(error, { status: 500 });
        });
    } else {
      ret = new Response("404 Not Found", { status: 404 });
    }
  } else if (method == "POST") {
    if (urlPath[0] == "proxyData" && urlPath.length == 2) {
      let key = urlPath[1];
      await setProxyData(key, body)
        .then((msg) => {
          ret = new Response(msg);
        })
        .catch((error) => {
          ret = new Response(error, { status: 500 });
        });
    } else {
      ret = new Response("404 Not Found", { status: 404 });
    }
  } else {
    ret = new Response("404 Not Found", { status: 404 });
  }
  await sendTGMessage("Proxy Subscribe Trigger ", ip, await ret.clone().text());
  return ret;
}

async function setProxyData(key, data) {
  if (data.trim() == "") {
    await proxyData.delete(key);
    return "Delete Success";
  } else {
    data = JSON.parse(data);
    await proxyData.put(key, JSON.stringify(data));
    return "Put Success";
  }
}

async function getClientConfig(templateURL) {
  let inboundConfig = await getProxyConfig();
  let configTemplate = await getConfigTemplate(templateURL);
  let config = configGenerator(inboundConfig, configTemplate);
  return JSON.stringify(config);
}

async function getConfigTemplate(templateURL) {
  let ret;
  if (templateURL) {
    await fetch(templateURL).then((response) => {
      ret = response.json();
    });
  } else {
    ret = CLIENTCONFIG;
  }
  return ret;
}

async function getClientLink(b64) {
  let inboundConfig = await getProxyConfig();
  let linkList = inboundConfig
    .map((conf) => {
      return getLink(conf);
    })
    .filter((link) => {
      return link;
    });
  let links = linkList.join("\n");
  if (b64) {
    links = btoa(links);
  }
  return links;
}

async function getProxyConfig() {
  let inboundConfig = [];
  let data_list = await proxyData.list();
  for (var k in data_list.keys) {
    let proxyNode = data_list.keys[k].name;
    let proxyConfig = await proxyData.get(proxyNode, { type: "json" });
    inboundConfig.push(...proxyConfig.outbounds);
  }
  return inboundConfig;
}
function configGenerator(inboundConfig, configTemplate) {
  var tag = inboundConfig.map((item) => item.tag);
  configTemplate.outbounds.push(...inboundConfig);
  configTemplate.outbounds.forEach((item) => {
    if (
      item.type === "selector" ||
      (item.type == "urltest" && item.tag !== "direct")
    ) {
      item.outbounds.push(...tag);
    }
  });
  return configTemplate;
}

function getLink(conf) {
  let type = conf.type;
  if (type == "vless") {
    return getVlessLink(conf);
  } else if (type == "hysteria2") {
    return getHysteria2Link(conf);
  } else return null;
}

function getVlessLink(conf) {
  let protocol = "vless";
  let uuid = conf.uuid;
  let remote_host = getServerName(conf.server);
  let remote_port = conf.server_port;
  let descriptive_text = conf.tag;
  let param = [];
  if (conf.flow) {
    param.push("flow=" + conf.flow);
  }
  if (conf?.transport?.type) {
    if (conf.transport.headers) {
      if (conf.transport.headers?.Host[0]) {
        param.push("host=" + conf.transport.headers.Host[0]);
      }
      if (conf.transport.type == "http") {
        param.push("type=" + "tcp");
      } else {
        param.push("type=" + conf.transport.type);
      }
    } else {
      param.push("type=" + conf.transport.type);

      if (conf.transport.host) {
        param.push("host=" + conf.transport.host);
      }
    }
    if (conf.transport.path) {
      if (
        conf.transport.early_data_header_name &&
        conf.transport.max_early_data
      ) {
        param.push(
          "path=" +
            conf.transport.path +
            "?" +
            "ed=" +
            conf.transport.max_early_data
        );
      } else {
        param.push("path=" + conf.transport.path);
      }
    }
  }
  if (conf?.tls?.enabled) {
    param.push("security=tls");
    if (conf.tls.server_name) {
      param.push("sni=" + conf.tls.server_name);
    }
    if (conf.tls.alpn) {
      param.push("alpn=" + conf.tls.alpn);
    }
    if (conf.tls.reality.enabled) {
      param.push("pbk=" + conf.tls.reality.public_key);
      param.push("sid=" + conf.tls.reality.short_id);
    }
  }
  if (conf?.tls?.utls?.enabled) {
    param.push("fp=" + conf.tls.utls.fingerprint);
  }
  let link = `${protocol}://${uuid}@${remote_host}:${remote_port}?${param.join(
    "&"
  )}#${descriptive_text}`;
  return link;
}

function getHysteria2Link(conf) {
  let tag = conf.tag;
  let auth = conf.password ? conf.password : "";
  let hostname = getServerName(conf.server);
  let port = conf.server_port;
  let param = [];
  if (conf?.obfs?.type) {
    param.push("obfs=" + conf.obfs.type);
  }
  if (conf?.obfs?.password) {
    param.push("obfs-password=" + conf.obfs.password);
  }
  if (conf?.tls?.insecure) {
    param.push("insecure=" + (conf.tls.insecure ? "1" : "0"));
  }
  if (conf?.tls?.server_name) {
    param.push("sni=" + conf.tls.server_name);
  }
  let link = `hysteria2://${auth}@${hostname}:${port}?${param.join(
    "&"
  )}#${tag}`;
  return link;
}

function getServerName(name) {
  if (name.includes(":")) {
    return "[" + name + "]";
  } else {
    return name;
  }
}

async function sendTGMessage(title, ip, data = "") {
  try {
    const OPT = {
      BotToken: TGBotToken,
      ChatID: TGChatID,
    };
  } catch (error) {
    return;
  }

  let msg = { title: title, ip: ip, location: "", data: data };

  await fetch(`http://ip-api.com/json/${ip}`)
    .then((response) => response.json())
    .then((data) => {
      console.log(data);
      msg["location"] = {
        Country: data.country,
        City: data.city,
        lat: data.lat,
        lon: data.lon,
        isp: data.isp,
      };
    });

  console.log(JSON.stringify(msg, null, 2));

  let url = "https://api.telegram.org/";
  url += "bot" + OPT.BotToken + "/sendMessage?";
  url += "chat_id=" + OPT.ChatID + "&";
  url += "text=" + encodeURIComponent(msg);

  return fetch(url, {
    method: "get",
    headers: {
      Accept: "text/html,application/xhtml+xml,application/xml;",
      "Accept-Encoding": "gzip, deflate, br",
      "User-Agent": "Mozilla/5.0 Chrome/90.0.4430.72",
    },
  });
}
