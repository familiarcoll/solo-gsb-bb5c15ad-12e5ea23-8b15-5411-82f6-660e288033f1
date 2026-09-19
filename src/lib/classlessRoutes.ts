/**
 * DHCP 类无静态路由（RFC 3442，DHCP Option 121 / Classless Static Route）编码与解码。
 *
 * 编码：
 *  每条路由 = 1 字节前缀长度 + 目标网络的有效字节（ceil(前缀/8) 字节）+ 4 字节下一跳 IPv4。
 *  有效字节只保留掩码覆盖部分；/0 不携带任何目标字节。
 *  多条路由按（目标网络地址升序，前缀长度升序）排列后拼接。
 *
 * 解码：
 *  逐段消费，拒绝截断、冗余目标字节（前缀有效字节之后携带主机位）、
 *  非规范网络位（有效字节中被掩码清零的位必须为 0）。
 *
 * 纯本地只读计算，不修改规划、不产生历史记录。
 */
import { Cidr, cidrToString, ipv4ToLong, lastAddr, longToIpv4, networkOf } from './ip';
import { usableRangeOf } from './dhcp';

export interface ClasslessRoute {
  target: Cidr;
  nextHop: number;
}

/** 一条路由编码后的字节拆解（用于逐条展示） */
export interface EncodedRoute {
  route: ClasslessRoute;
  /** 完整字节序列：前缀长度 + 目标有效字节 + 4 字节下一跳 */
  bytes: number[];
  /** 各段拆解 */
  prefixByte: number;
  targetBytes: number[];
  nextHopBytes: number[];
}

export interface EncodeResult {
  routes: EncodedRoute[];
  /** 完整 Option 121 值（十六进制，每字节两位小写，无分隔） */
  hex: string;
  /** 总字节数 */
  length: number;
}

/** 路由行解析状态（供弹窗逐行展示） */
export type RouteLineStatus = 'ok' | 'invalid';

export interface RouteLine {
  /** 物理行号（从 1 开始，空行也计入） */
  row: number;
  /** 原始非空文本（trim 后） */
  input: string;
  status: RouteLineStatus;
  route: ClasslessRoute | null;
  reason: string | null;
}

export interface RouteParseResult {
  lines: RouteLine[];
  /** 至少一条非空行且全部合法（目标对齐、下一跳位于子网可用主机范围、目标不重复） */
  ok: boolean;
}

/** 前缀对应的目标网络有效字节数（RFC 3442：仅传输被掩码覆盖的整数字节） */
export function significantBytes(prefix: number): number {
  return Math.ceil(prefix / 8);
}

/** 单条路由编码：前缀长度 + 目标有效字节 + 4 字节下一跳。 */
export function encodeRoute(route: ClasslessRoute): EncodedRoute {
  const bytes: number[] = [route.target.prefix];
  const targetBytes: number[] = [];
  const octets = [
    (route.target.base >>> 24) & 255,
    (route.target.base >>> 16) & 255,
    (route.target.base >>> 8) & 255,
    route.target.base & 255,
  ];
  for (let i = 0; i < significantBytes(route.target.prefix); i++) {
    targetBytes.push(octets[i]);
    bytes.push(octets[i]);
  }
  const nextHopBytes = [
    (route.nextHop >>> 24) & 255,
    (route.nextHop >>> 16) & 255,
    (route.nextHop >>> 8) & 255,
    route.nextHop & 255,
  ];
  bytes.push(...nextHopBytes);
  return { route, bytes, prefixByte: route.target.prefix, targetBytes, nextHopBytes };
}

/** 按目标地址、前缀排序后编码为完整 Option 121 十六进制值。 */
export function encodeClasslessRoutes(routes: ClasslessRoute[]): EncodeResult {
  const sorted = [...routes].sort(
    (a, b) => a.target.base - b.target.base || a.target.prefix - b.target.prefix,
  );
  const encoded = sorted.map(encodeRoute);
  const all = encoded.flatMap((e) => e.bytes);
  return {
    routes: encoded,
    hex: all.map((b) => b.toString(16).padStart(2, '0')).join(''),
    length: all.length,
  };
}

/**
 * 逐行解析「目标 CIDR,下一跳 IPv4」：
 *  - 空行（含纯空白）忽略；
 *  - 必须为单个逗号分隔的两段；目标必须是带前缀的 CIDR 且已对齐网络地址；
 *  - 下一跳必须是合法 IPv4 且位于所选子网的可用主机范围（沿用 /31、/32 规则）；
 *  - 目标 CIDR 重复（按网络地址 + 前缀）按行报错；
 *  - 任一错误时调用方不应生成结果。
 */
export function parseRouteLines(subnet: Cidr, text: string): RouteParseResult {
  const lines: RouteLine[] = [];
  const seen = new Map<string, number>(); // 规范化 CIDR → 首次行号
  const usable = usableRangeOf(subnet);
  const subnetEnd = lastAddr(subnet);

  text.split('\n').forEach((raw, i) => {
    const row = i + 1;
    const input = raw.trim();
    if (!input) return;

    const fail = (reason: string): void => {
      lines.push({ row, input, status: 'invalid', route: null, reason });
    };

    const parts = input.split(',');
    if (parts.length !== 2 || parts.some((p) => p.trim() === '')) {
      fail('格式应为「目标 CIDR,下一跳 IPv4」（单个英文逗号分隔，两段均不可为空）');
      return;
    }
    const targetText = parts[0].trim();
    const hopText = parts[1].trim();

    const slash = targetText.indexOf('/');
    if (slash < 0) {
      fail(`目标必须为 CIDR（需显式前缀长度）：${targetText}`);
      return;
    }
    const prefixPart = targetText.slice(slash + 1).trim();
    if (!/^\d{1,2}$/.test(prefixPart)) {
      fail(`目标前缀长度非法：${targetText}`);
      return;
    }
    const prefix = Number(prefixPart);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      fail(`目标前缀长度须为 0-32 的整数：${targetText}`);
      return;
    }
    const addr = ipv4ToLong(targetText.slice(0, slash));
    if (addr === null) {
      fail(`目标地址非法：${targetText.slice(0, slash).trim()}`);
      return;
    }
    const base = networkOf(addr, prefix);
    if (base !== addr) {
      fail(
        `目标 CIDR 未对齐网络地址：${targetText}（应为 ${longToIpv4(base)}/${prefix}）`,
      );
      return;
    }

    const nextHop = ipv4ToLong(hopText);
    if (nextHop === null) {
      fail(`下一跳必须为合法 IPv4 地址：${hopText}`);
      return;
    }
    if (nextHop < subnet.base || nextHop > subnetEnd) {
      fail(
        `下一跳 ${longToIpv4(nextHop)} 不在子网内（${longToIpv4(subnet.base)} - ${longToIpv4(subnetEnd)}）`,
      );
      return;
    }
    if (nextHop < usable.start || nextHop > usable.end) {
      const which = nextHop === subnet.base ? '网络地址' : '广播地址';
      fail(
        `下一跳 ${longToIpv4(nextHop)} 是子网的${which}，不可作为网关（可用主机范围 ${longToIpv4(usable.start)} - ${longToIpv4(usable.end)}）`,
      );
      return;
    }

    const key = `${base}/${prefix}`;
    const firstRow = seen.get(key);
    if (firstRow !== undefined) {
      fail(`目标 ${cidrToString({ base, prefix })} 与第 ${firstRow} 行重复`);
      return;
    }
    seen.set(key, row);
    lines.push({
      row,
      input,
      status: 'ok',
      route: { target: { base, prefix }, nextHop },
      reason: null,
    });
  });

  return { lines, ok: lines.length > 0 && lines.every((l) => l.status === 'ok') };
}

export interface DecodeSuccess {
  ok: true;
  routes: ClasslessRoute[];
  encoded: EncodedRoute[];
  length: number;
}

export interface DecodeFailure {
  ok: false;
  error: string;
}

export type DecodeResult = DecodeSuccess | DecodeFailure;

/**
 * 解码 RFC 3442 Option 121 原始字节：
 *  逐段读取 [前缀长度][目标有效字节][4 字节下一跳]，直到消费完全部字节。
 *  - 截断（任一字段不完整）拒绝；
 *  - 非规范网络位（有效字节中掩码外的位非零）拒绝；
 *  - 目标重复拒绝（Option 121 同一目标不应出现多条）。
 * 不要求输入按地址排序（设备实现可能不排序），解码后由调用方展示原始顺序。
 */
export function decodeClasslessRoutesHex(hexInput: string): DecodeResult {
  const clean = hexInput.trim().replace(/\s+/g, '').replace(/^0x/i, '').toLowerCase();
  if (clean === '') {
    return { ok: false, error: '十六进制为空' };
  }
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    return { ok: false, error: '十六进制非法：须为偶数个十六进制字符（0-9a-f）' };
  }
  const data: number[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    data.push(parseInt(clean.slice(i, i + 2), 16));
  }

  const routes: ClasslessRoute[] = [];
  const seen = new Set<string>();
  let pos = 0;
  let seg = 0;
  while (pos < data.length) {
    seg += 1;
    const at = pos;
    const prefix = data[pos];
    pos += 1;
    if (prefix > 32) {
      return { ok: false, error: `第 ${seg} 条（偏移 ${at}）：前缀长度 ${prefix} 超过 32` };
    }
    const sig = significantBytes(prefix);
    if (pos + sig + 4 > data.length) {
      return {
        ok: false,
        error: `第 ${seg} 条（偏移 ${at}）：数据截断，需要 ${1 + sig + 4} 字节，仅剩 ${data.length - at} 字节`,
      };
    }
    const sigOctets = data.slice(pos, pos + sig);
    pos += sig;
    const hop =
      ((data[pos] << 24) >>> 0) +
      ((data[pos + 1] << 16) >>> 0) +
      ((data[pos + 2] << 8) >>> 0) +
      data[pos + 3];
    pos += 4;

    // 非规范网络位：最后一个有效字节中，前缀未覆盖的低位必须全部为 0
    // （更早的整字节被完整覆盖；sig === 0 即 /0 时无目标字节）。
    if (sig > 0) {
      const remainder = prefix % 8;
      if (remainder !== 0) {
        const hostBits = 8 - remainder;
        const last = sigOctets[sig - 1];
        if ((last & ((1 << hostBits) - 1)) !== 0) {
          return {
            ok: false,
            error: `第 ${seg} 条（偏移 ${at}）：目标携带冗余主机位（非规范网络地址），有效字节末尾为 0x${last
              .toString(16)
              .padStart(2, '0')}，/ ${prefix} 要求低 ${hostBits} 位为 0`,
          };
        }
      }
    }
    const octets = [0, 0, 0, 0];
    sigOctets.forEach((o, i) => {
      octets[i] = o;
    });
    const base =
      (((octets[0] << 24) >>> 0) +
        ((octets[1] << 16) >>> 0) +
        ((octets[2] << 8) >>> 0) +
        octets[3]) >>> 0;

    const key = `${base}/${prefix}`;
    if (seen.has(key)) {
      return { ok: false, error: `第 ${seg} 条（偏移 ${at}）：目标 ${longToIpv4(base)}/${prefix} 重复出现` };
    }
    seen.add(key);
    routes.push({ target: { base, prefix }, nextHop: hop >>> 0 });
  }

  const encoded = routes.map(encodeRoute);
  return { ok: true, routes, encoded, length: data.length };
}

/** 把解码出的路由回填为弹窗文本框行（保持解码顺序）：`目标 CIDR,下一跳`。 */
export function routesToText(routes: ClasslessRoute[]): string {
  return routes
    .map((r) => `${cidrToString(r.target)},${longToIpv4(r.nextHop)}`)
    .join('\n');
}

/** 单条路由的人类可读文本：`目标 CIDR via 下一跳`。 */
export function formatRoute(r: ClasslessRoute): string {
  return `${cidrToString(r.target)} via ${longToIpv4(r.nextHop)}`;
}
