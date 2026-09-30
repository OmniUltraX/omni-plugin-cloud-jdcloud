/**
 * 京东云 L2（QuickJS）。JDCLOUD2-HMAC-SHA256 签名走 host.hmac + host.hash，
 * 网络走 host.netFetch。Plugin id: omni.cloud.jdcloud
 *
 * v0.1：compute（云主机）只读列表/详情 + addSsh；start/stop/reboot 预留未实现。
 */
var PLUGIN_ID = "omni.cloud.jdcloud";
var DEFAULT_REGION = "cn-north-1";
var VM_HOST = "vm.jdcloud-api.com";
var VM_BASE = "https://" + VM_HOST;
var PAGE_SIZE = 100;
var PAGE_MAX = 500;

var MANIFEST_REGIONS = [
  { regionId: "cn-north-1", localName: "华北-北京" },
  { regionId: "cn-east-1", localName: "华东-宿迁" },
  { regionId: "cn-east-2", localName: "华东-上海" },
  { regionId: "cn-south-1", localName: "华南-广州" },
  { regionId: "ap-southeast-1", localName: "亚太-曼谷" },
];

function asObj(v) {
  if (v && typeof v === "object") return v;
  try {
    return JSON.parse(String(v || "{}"));
  } catch (e) {
    return {};
  }
}

function str(v) {
  if (v == null) return "";
  return String(v);
}

function jstr(v, keys) {
  if (!v || typeof v !== "object") return "";
  for (var i = 0; i < keys.length; i++) {
    var x = v[keys[i]];
    if (x == null) continue;
    if (typeof x === "string" || typeof x === "number" || typeof x === "boolean") return String(x);
  }
  return "";
}

function jarr(v, keys) {
  if (!v || typeof v !== "object") return [];
  for (var i = 0; i < keys.length; i++) {
    var x = v[keys[i]];
    if (Array.isArray(x)) return x;
  }
  return [];
}

function hmac(spec) {
  return host.hmac(JSON.stringify(spec));
}

function hashHex(alg, data) {
  return host.hash(JSON.stringify({ alg: alg, data: data, encoding: "hex" }));
}

function hmacUtf8(alg, key, data) {
  return hmac({ alg: alg, key: key, data: data, encoding: "hex" });
}

function hmacHexKey(alg, keyHex, data) {
  return hmac({
    alg: alg,
    key: keyHex,
    data: data,
    encoding: "hex",
    keyEncoding: "hex",
  });
}

function pad2(n) {
  return n < 10 ? "0" + n : String(n);
}

function utcParts(ms) {
  var d = new Date(ms);
  return {
    y: d.getUTCFullYear(),
    m: pad2(d.getUTCMonth() + 1),
    d: pad2(d.getUTCDate()),
    h: pad2(d.getUTCHours()),
    min: pad2(d.getUTCMinutes()),
    s: pad2(d.getUTCSeconds()),
  };
}

function jdcloudDate(ms) {
  var p = utcParts(ms);
  return p.y + p.m + p.d + "T" + p.h + p.min + p.s + "Z";
}

function scopeDate(ms) {
  var p = utcParts(ms);
  return p.y + p.m + p.d;
}

function uriEncode(s, encodeSlash) {
  var out = encodeURIComponent(str(s))
    .replace(/!/g, "%21")
    .replace(/'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A");
  if (!encodeSlash) out = out.replace(/%2F/g, "/");
  return out;
}

function canonicalUri(path) {
  var raw = str(path || "/");
  if (raw.charAt(0) !== "/") raw = "/" + raw;
  if (raw === "/") return "/";
  var parts = raw.split("/");
  var enc = [];
  for (var i = 0; i < parts.length; i++) {
    if (!parts[i]) continue;
    enc.push(uriEncode(parts[i], true));
  }
  return "/" + enc.join("/");
}

function canonicalQuery(query) {
  query = query && typeof query === "object" ? query : {};
  var keys = [];
  for (var k in query) {
    if (!Object.prototype.hasOwnProperty.call(query, k)) continue;
    if (query[k] == null) continue;
    keys.push(k);
  }
  keys.sort();
  var parts = [];
  for (var i = 0; i < keys.length; i++) {
    parts.push(uriEncode(keys[i], true) + "=" + uriEncode(str(query[keys[i]]), true));
  }
  return parts.join("&");
}

function buildQuery(query) {
  var qs = canonicalQuery(query);
  return qs ? "?" + qs : "";
}

function makeNonce() {
  var hex = "0123456789abcdef";
  var s = "";
  for (var i = 0; i < 36; i++) {
    if (i === 8 || i === 13 || i === 18 || i === 23) s += "-";
    else if (i === 14) s += "4";
    else if (i === 19) s += hex[(Math.random() * 4) | 8];
    else s += hex[(Math.random() * 16) | 0];
  }
  return s;
}

function maskAccessKey(ak) {
  var s = str(ak).trim();
  if (!s) return "";
  if (s.length <= 10) return s.slice(0, 2) + "••••";
  return s.slice(0, 6) + "••••" + s.slice(-4);
}

function fieldMap(pairs) {
  var out = {};
  for (var i = 0; i < pairs.length; i++) {
    var k = pairs[i][0];
    var v = str(pairs[i][1]).trim();
    if (v) out[k] = v;
  }
  return out;
}

function uniqueRegions(ids) {
  var out = [];
  var seen = {};
  for (var i = 0; i < ids.length; i++) {
    var id = str(ids[i]).trim();
    if (!id || seen[id]) continue;
    seen[id] = true;
    out.push(id);
  }
  return out;
}

function credsOf(args) {
  var raw = args.credentials || args.creds || args;
  var id = str(raw.accessKeyId || args.accessKeyId).trim();
  var secret = str(raw.accessKeySecret || args.accessKeySecret).trim();
  if (!id || !secret) throw new Error("缺少 AccessKey Id / AccessKey Secret");
  var regions = raw.regions || args.regions || [];
  if (!Array.isArray(regions)) regions = [];
  var region = str(raw.region || args.region || "").trim();
  return { accessKeyId: id, accessKeySecret: secret, region: region, regions: regions };
}

function regionOfCreds(creds) {
  return str(creds.region).trim() || DEFAULT_REGION;
}

function withRegion(creds, region) {
  return {
    accessKeyId: creds.accessKeyId,
    accessKeySecret: creds.accessKeySecret,
    region: region,
    regions: creds.regions,
  };
}

function regionsToScan(creds, filter) {
  var listed = uniqueRegions((filter && filter.regions) || []);
  if (listed.length) return listed;
  var configured = uniqueRegions(creds.regions || []);
  if (configured.length) return configured;
  return [regionOfCreds(creds)];
}

/**
 * JDCLOUD2-HMAC-SHA256（对齐 AWS SigV4 形态；派生钥前缀 JDCLOUD2 / jdcloud2_request）。
 */
function jdSignedRequest(creds, service, region, method, path, query, body) {
  method = str(method || "GET").toUpperCase();
  path = path || "/";
  query = query && typeof query === "object" ? query : {};
  body = body == null ? "" : str(body);
  var signRegion = str(region || DEFAULT_REGION).trim() || DEFAULT_REGION;
  var hostName = service + ".jdcloud-api.com";
  var now = Date.now();
  var amz = jdcloudDate(now);
  var date = scopeDate(now);
  var nonce = makeNonce();
  var headers = {
    Host: hostName,
    "Content-Type": "application/json",
    "x-jdcloud-date": amz,
    "x-jdcloud-nonce": nonce,
  };
  var signedNames = ["content-type", "host", "x-jdcloud-date", "x-jdcloud-nonce"];
  var canonicalHeaders =
    "content-type:application/json\n" +
    "host:" +
    hostName +
    "\n" +
    "x-jdcloud-date:" +
    amz +
    "\n" +
    "x-jdcloud-nonce:" +
    nonce +
    "\n";
  var signedHeaders = signedNames.join(";");
  var payloadHash = hashHex("sha256", body);
  var canonicalRequest =
    method +
    "\n" +
    canonicalUri(path) +
    "\n" +
    canonicalQuery(query) +
    "\n" +
    canonicalHeaders +
    "\n" +
    signedHeaders +
    "\n" +
    payloadHash;
  var credentialScope = date + "/" + signRegion + "/" + service + "/jdcloud2_request";
  var stringToSign =
    "JDCLOUD2-HMAC-SHA256\n" +
    amz +
    "\n" +
    credentialScope +
    "\n" +
    hashHex("sha256", canonicalRequest);
  var secretDate = hmacUtf8("sha256", "JDCLOUD2" + creds.accessKeySecret, date);
  var secretRegion = hmacHexKey("sha256", secretDate, signRegion);
  var secretService = hmacHexKey("sha256", secretRegion, service);
  var secretSigning = hmacHexKey("sha256", secretService, "jdcloud2_request");
  var signature = hmacHexKey("sha256", secretSigning, stringToSign);
  headers.Authorization =
    "JDCLOUD2-HMAC-SHA256 Credential=" +
    creds.accessKeyId +
    "/" +
    credentialScope +
    ", SignedHeaders=" +
    signedHeaders +
    ", Signature=" +
    signature;
  var spec = {
    url: "https://" + hostName + path + buildQuery(query),
    method: method,
    headers: headers,
  };
  if (body && method !== "GET" && method !== "HEAD") spec.body = body;
  var text = host.netFetch(JSON.stringify(spec));
  return text || "";
}

function parseJdError(body) {
  if (!body || typeof body !== "object") return null;
  var err = body.error;
  if (!err || typeof err !== "object") return null;
  var code = jstr(err, ["code", "status"]);
  var message = jstr(err, ["message", "messageId", "status"]);
  if (!code && !message) return null;
  return { code: code, message: message || code };
}

function parseJsonBody(text, path) {
  if (!text) return {};
  var trimmed = str(text).replace(/^\s+/, "");
  if (trimmed.charAt(0) !== "{" && trimmed.charAt(0) !== "[") {
    throw new Error("京东云 " + path + " 响应非 JSON");
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error("京东云 " + path + " 响应无法解析");
  }
}

function vmRequest(creds, method, path, query, body) {
  var region = regionOfCreds(creds);
  var text = jdSignedRequest(creds, "vm", region, method, path, query || {}, body == null ? "" : body);
  var parsed = parseJsonBody(text, path);
  var err = parseJdError(parsed);
  if (err) {
    throw new Error(
      "京东云 " + path + " 失败: " + (err.code ? err.code + " " : "") + err.message,
    );
  }
  return parsed;
}

function vmGet(creds, path, query) {
  return vmRequest(creds, "GET", path, query || {}, "");
}

function mapStatus(raw) {
  var u = str(raw).trim().toLowerCase();
  if (u === "running" || u === "active") return "RUNNING";
  if (u === "stopped" || u === "shutdown") return "STOPPED";
  if (u === "pending" || u === "starting" || u === "creating" || u === "building") return "PENDING";
  if (u === "stopping") return "STOPPING";
  if (u === "restarting" || u === "rebooting") return "REBOOTING";
  if (u === "error" || u === "failed") return "ERROR";
  if (u === "deleted" || u === "terminated") return "DELETED";
  return str(raw).trim();
}

function mapCharge(item) {
  var charge = item && item.charge && typeof item.charge === "object" ? item.charge : {};
  var mode = jstr(charge, ["chargeMode", "charge_mode", "billingType"]);
  var u = mode.toLowerCase();
  if (u === "prepaid" || u === "prePaid" || u.indexOf("pre") === 0) return "prepaid";
  if (u === "postpaid" || u === "postPaid" || u.indexOf("post") === 0) return "postpaid";
  return mode;
}

function privateIpOf(item) {
  var direct = jstr(item, ["privateIpAddress", "privateIp"]);
  if (direct) return direct;
  var nic = item && item.primaryNetworkInterface;
  if (nic && typeof nic === "object") {
    var pip = nic.primaryIp || nic.privateIp || nic;
    if (pip && typeof pip === "object") {
      return jstr(pip, ["privateIpAddress", "privateIp", "elasticIpAddress"]);
    }
  }
  return "";
}

function publicIpOf(item) {
  var direct = jstr(item, ["elasticIpAddress", "publicIp", "publicIpAddress"]);
  if (direct) return direct;
  var nic = item && item.primaryNetworkInterface;
  if (nic && typeof nic === "object") {
    var eip = nic.elasticIpAddress || nic.elasticIp;
    if (typeof eip === "string") return eip;
    if (eip && typeof eip === "object") {
      return jstr(eip, ["elasticIpAddress", "elasticIp", "ipAddress"]);
    }
  }
  return "";
}

function displayName(name, fallback) {
  return str(name).trim() ? str(name).trim() : fallback;
}

function mapInstance(item, region) {
  var id = jstr(item, ["instanceId", "id"]);
  var image = item && item.image && typeof item.image === "object" ? item.image : {};
  return {
    id: id,
    name: displayName(jstr(item, ["instanceName", "name"]), id),
    capability: "compute",
    regionId: region || jstr(item, ["regionId", "region"]) || "",
    status: mapStatus(jstr(item, ["status", "state"])),
    fields: fieldMap([
      ["publicIp", publicIpOf(item)],
      ["privateIp", privateIpOf(item)],
      ["instanceType", jstr(item, ["instanceType", "instanceTypeName"])],
      ["zone", jstr(item, ["az", "availabilityZone", "zone"])],
      ["os", jstr(item, ["imageName", "platform", "osName", "osType"]) || jstr(image, ["name", "imageName", "platform"])],
      ["chargeType", mapCharge(item)],
      ["creationTime", jstr(item, ["createdTime", "launchTime", "createTime"])],
      ["vpcId", jstr(item, ["vpcId"])],
      ["subnetId", jstr(item, ["subnetId"])],
      ["imageId", jstr(item, ["imageId"]) || jstr(image, ["imageId", "id"])],
      ["cpu", jstr(item, ["cpu", "cpus"])],
      ["memory", jstr(item, ["memoryMB", "memorySize", "memory"])],
    ]),
  };
}

function fromRow(row, consoleUrl) {
  return {
    id: row.id,
    name: row.name,
    capability: row.capability,
    regionId: row.regionId || "",
    status: row.status || "",
    fields: row.fields || {},
    extra: null,
    consoleUrl: consoleUrl || null,
    related: [],
    rules: [],
    metricIds: [],
    logKinds: [],
    children: [],
  };
}

function instanceConsoleUrl(region, id) {
  return (
    "https://console.jdcloud.com/vm/instance/detail?id=" +
    encodeURIComponent(id) +
    "&regionId=" +
    encodeURIComponent(region || DEFAULT_REGION)
  );
}

function listInstancesInRegion(creds, region) {
  var scoped = withRegion(creds, region);
  var path = "/v1/regions/" + region + "/instances";
  var out = [];
  var page = 1;
  while (true) {
    var resp = vmGet(scoped, path, { pageNumber: page, pageSize: PAGE_SIZE });
    var result = resp.result && typeof resp.result === "object" ? resp.result : resp;
    var items = jarr(result, ["instances"]);
    out = out.concat(items);
    var total = Number(result.totalCount);
    if (!items.length || items.length < PAGE_SIZE) break;
    if (!isNaN(total) && total > 0 && out.length >= total) break;
    if (out.length >= PAGE_MAX) break;
    page += 1;
    if (page > 50) break;
  }
  if (out.length > PAGE_MAX) out.length = PAGE_MAX;
  return out;
}

function listRegional(creds, filter) {
  var regions = regionsToScan(creds, filter);
  var out = [];
  var lastErr = null;
  var ok = 0;
  for (var i = 0; i < regions.length; i++) {
    try {
      var items = listInstancesInRegion(creds, regions[i]);
      ok += 1;
      for (var k = 0; k < items.length; k++) out.push(mapInstance(items[k], regions[i]));
    } catch (e) {
      lastErr = e;
    }
  }
  if (!ok && lastErr) throw lastErr;
  return out;
}

function applyFilter(rows, filter) {
  filter = filter || {};
  var status = str(filter.status).trim();
  var query = str(filter.query).trim().toLowerCase();
  var out = [];
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (status && str(row.status).toLowerCase() !== status.toLowerCase()) continue;
    if (query) {
      var blob = (str(row.name) + " " + str(row.id) + " " + JSON.stringify(row.fields || {})).toLowerCase();
      if (blob.indexOf(query) < 0) continue;
    }
    out.push(row);
  }
  return out;
}

function testAccount(args) {
  var creds = credsOf(args);
  var region = uniqueRegions(creds.regions || [])[0] || DEFAULT_REGION;
  var path = "/v1/regions/" + region + "/instances";
  var resp = vmGet(withRegion(creds, region), path, { pageNumber: 1, pageSize: 1 });
  var result = resp.result && typeof resp.result === "object" ? resp.result : resp;
  var total = Number(result.totalCount);
  if (!isNaN(total) && total >= 0) {
    return { message: "凭证有效（" + region + " 云主机约 " + total + " 台）" };
  }
  return { message: "凭证有效（" + region + "）" };
}

function listRegions(args) {
  credsOf(args);
  var configured = args.configured || args.configuredRegions || args.regions || [];
  var items = MANIFEST_REGIONS.map(function (r) {
    return {
      regionId: r.regionId,
      localName: r.localName,
      capabilities: ["compute"],
    };
  });
  var wanted = uniqueRegions(configured);
  if (wanted.length) {
    var allow = {};
    for (var i = 0; i < wanted.length; i++) allow[wanted[i]] = true;
    var filtered = items.filter(function (row) {
      return allow[row.regionId];
    });
    for (var w = 0; w < wanted.length; w++) {
      var found = false;
      for (var f = 0; f < filtered.length; f++) {
        if (filtered[f].regionId === wanted[w]) {
          found = true;
          break;
        }
      }
      if (!found) filtered.push({ regionId: wanted[w], localName: "", capabilities: ["compute"] });
    }
    if (filtered.length) items = filtered;
  }
  return { items: items };
}

function getAccount(args) {
  var creds = credsOf(args);
  return {
    callerId: maskAccessKey(creds.accessKeyId),
    arn: PLUGIN_ID,
    currency: "CNY",
    availableAmount: "",
    cashAmount: "",
    creditAmount: "",
    balanceError: "京东云本期未接入账户余额查询",
  };
}

function listResources(args) {
  var creds = credsOf(args);
  var cap = str(args.capability || "compute").trim();
  var filter = args.filter || {};
  if (cap !== "compute") throw new Error("京东云本期未实现能力: " + cap);
  var rows = listRegional(creds, filter);
  return { items: applyFilter(rows, filter) };
}

function getResource(args) {
  var creds = credsOf(args);
  var cap = str(args.capability).trim();
  var id = str(args.resourceId || args.id).trim();
  if (!id) throw new Error("缺少资源 id");
  if (cap !== "compute") throw new Error("京东云本期未实现能力: " + cap);
  var region = str(args.regionId || args.region).trim() || regionOfCreds(creds);
  var path = "/v1/regions/" + region + "/instances/" + id;
  var resp = vmGet(withRegion(creds, region), path, {});
  var result = resp.result && typeof resp.result === "object" ? resp.result : resp;
  var item = result.instance || result;
  var row = mapInstance(item, region);
  return fromRow(row, instanceConsoleUrl(region, id));
}

function invokeAction(args) {
  var action = args.action && typeof args.action === "object" ? args.action : args;
  var name = str(action.name).trim().toLowerCase();
  var cap = str(action.capability).trim();
  if (cap === "compute" && (name === "start" || name === "stop" || name === "reboot")) {
    throw new Error("京东云本期暂未实现生命周期操作: " + name);
  }
  throw new Error("不支持的动作: " + cap + "/" + name);
}

function getMetrics(args) {
  var cap = str(args.capability).trim();
  throw new Error("京东云该能力不支持监控: " + cap);
}

function queryLogs(args) {
  var query = args.query || {};
  return {
    kind: str(query.kind || "audit"),
    total: 0,
    page: Number(query.page) > 0 ? Number(query.page) : 1,
    entries: [],
  };
}

var HANDLERS = {
  testAccount: testAccount,
  listRegions: listRegions,
  getAccount: getAccount,
  listResources: listResources,
  getResource: getResource,
  invokeAction: invokeAction,
  getMetrics: getMetrics,
  queryLogs: queryLogs,
};

function call(method, argsJson) {
  var handler = HANDLERS[String(method || "")];
  if (!handler) throw new Error("UnknownMethod: " + method);
  var result = handler(asObj(argsJson));
  return typeof result === "string" ? result : JSON.stringify(result);
}

globalThis.call = call;
