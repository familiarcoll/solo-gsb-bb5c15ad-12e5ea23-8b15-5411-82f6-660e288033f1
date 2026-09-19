import { describe, expect, it } from 'vitest';
import { longToIpv4, parseCidr } from './ip';
import {
  DecodeResult,
  decodeClasslessRoutesHex,
  encodeClasslessRoutes,
  encodeRoute,
  formatRoute,
  parseRouteLines,
  routesToText,
  significantBytes,
} from './classlessRoutes';

const cidr = (s: string) => parseCidr(s)!;
const hex = (s: string) =>
  s
    .replace(/\s+/g, '')
    .match(/.{2}/g)!
    .map((b) => parseInt(b, 16));

describe('RFC 3442 有效字节数', () => {
  it('ceil(prefix/8)', () => {
    expect([0, 1, 8, 9, 16, 24, 25, 32].map(significantBytes)).toEqual([0, 1, 1, 2, 2, 3, 4, 4]);
  });
});

describe('单条路由编码', () => {
  const r = (target: string, hop: string) => ({
    target: cidr(target),
    nextHop: parseCidr(`${hop}/32`)!.base,
  });

  it('/0：只有前缀字节 00 + 4 字节下一跳（无目标字节）', () => {
    const e = encodeRoute(r('0.0.0.0/0', '10.0.0.1'));
    expect(e.bytes).toEqual(hex('00 0a000001'));
    expect(e.targetBytes).toEqual([]);
    expect(e.nextHopBytes).toEqual([10, 0, 0, 1]);
  });

  it('/8：1 个目标字节', () => {
    expect(encodeRoute(r('10.0.0.0/8', '10.0.0.1')).bytes).toEqual(hex('08 0a 0a000001'));
  });

  it('/9：2 个目标字节（非八位边界保留全部有效字节）', () => {
    // 10.128.0.0/9 = 0000 1010 . 1000 0000 ...
    const e = encodeRoute(r('10.128.0.0/9', '10.0.0.254'));
    expect(e.bytes).toEqual(hex('09 0a80 0a0000fe'));
    expect(e.targetBytes).toEqual([0x0a, 0x80]);
  });

  it('/24：3 个目标字节', () => {
    expect(encodeRoute(r('192.168.1.0/24', '192.168.1.1')).bytes).toEqual(
      hex('18 c0a801 c0a80101'),
    );
  });

  it('/32：4 个目标字节', () => {
    expect(encodeRoute(r('172.16.5.4/32', '172.16.5.1')).bytes).toEqual(
      hex('20 ac100504 ac100501'),
    );
  });
});

describe('多条路由编码与排序', () => {
  it('按目标地址、前缀排序后输出', () => {
    // 输入故意乱序：192.168.1.0/24、0.0.0.0/0、10.0.0.0/8
    const result = encodeClasslessRoutes([
      { target: cidr('192.168.1.0/24'), nextHop: cidr('192.168.1.1/32').base },
      { target: cidr('0.0.0.0/0'), nextHop: cidr('10.0.0.1/32').base },
      { target: cidr('10.0.0.0/8'), nextHop: cidr('10.0.0.2/32').base },
    ]);
    expect(result.hex).toBe(
      '00' + '0a000001' +
      '08' + '0a' + '0a000002' +
      '18' + 'c0a801' + 'c0a80101',
    );
    expect(result.length).toBe(5 + 6 + 8);
    expect(result.routes.map((e) => e.route.target.prefix)).toEqual([0, 8, 24]);
  });

  it('同地址时更具体前缀在后（前缀升序）', () => {
    const result = encodeClasslessRoutes([
      { target: cidr('10.0.0.0/16'), nextHop: cidr('10.0.0.2/32').base },
      { target: cidr('10.0.0.0/8'), nextHop: cidr('10.0.0.1/32').base },
    ]);
    expect(result.hex.startsWith('08')).toBe(true);
  });

  it('RFC 3442 文档示例：10.0.0.0/8 via 9.255.255.255 与 172.16.0.0/16 via 9.255.255.255', () => {
    const result = encodeClasslessRoutes([
      { target: cidr('10.0.0.0/8'), nextHop: cidr('9.255.255.255/32').base },
      { target: cidr('172.16.0.0/16'), nextHop: cidr('9.255.255.255/32').base },
    ]);
    expect(result.hex).toBe('080a09ffffff' + '10ac1009ffffff');
  });
});

describe('逐行解析与校验', () => {
  it('空行忽略，合法行通过', () => {
    const { lines, ok } = parseRouteLines(
      cidr('10.0.0.0/24'),
      '0.0.0.0/0,10.0.0.1\n\n  \n192.168.1.0/24,10.0.0.254\n',
    );
    expect(ok).toBe(true);
    expect(lines).toHaveLength(2);
    expect(lines.map((l) => l.row)).toEqual([1, 4]);
  });

  it('目标必须带前缀、合法且对齐网络地址', () => {
    const { lines, ok } = parseRouteLines(
      cidr('10.0.0.0/24'),
      ['10.0.0.0,10.0.0.1', '10.0.0.1/24,10.0.0.1', '10.0.0.0/33,10.0.0.1', '999.0.0.0/8,10.0.0.1'].join('\n'),
    );
    expect(ok).toBe(false);
    expect(lines.every((l) => l.status === 'invalid')).toBe(true);
    expect(lines[1].reason).toContain('未对齐');
    expect(lines[1].reason).toContain('10.0.0.0/24');
  });

  it('下一跳必须是合法 IPv4 且位于子网可用主机范围', () => {
    const { lines, ok } = parseRouteLines(
      cidr('10.0.0.0/24'),
      ['8.8.8.0/24,10.0.0.256', '8.8.8.0/24,10.0.0.0', '8.8.8.0/24,10.0.0.255', '8.8.8.0/24,abc'].join('\n'),
    );
    expect(ok).toBe(false);
    expect(lines.map((l) => l.status)).toEqual(['invalid', 'invalid', 'invalid', 'invalid']);
    expect(lines[1].reason).toContain('网络');
    expect(lines[2].reason).toContain('广播');
  });

  it('/31 与 /32 子网不排除网络/广播地址', () => {
    const r31 = parseRouteLines(cidr('10.0.0.0/31'), '0.0.0.0/0,10.0.0.0\n1.0.0.0/8,10.0.0.1');
    expect(r31.ok).toBe(true);
    const r32 = parseRouteLines(cidr('10.0.0.7/32'), '0.0.0.0/0,10.0.0.7');
    expect(r32.ok).toBe(true);
    const r32bad = parseRouteLines(cidr('10.0.0.7/32'), '0.0.0.0/0,10.0.0.8');
    expect(r32bad.ok).toBe(false);
  });

  it('下一跳超出子网边界报错', () => {
    const { ok, lines } = parseRouteLines(cidr('10.0.0.128/25'), '0.0.0.0/0,10.0.0.127');
    expect(ok).toBe(false);
    expect(lines[0].reason).toContain('不在子网内');
    expect(lines[0].reason).toContain('10.0.0.128');
    expect(lines[0].reason).toContain('10.0.0.255');
  });

  it('子网网络地址与广播地址分别给出明确原因', () => {
    const { lines } = parseRouteLines(
      cidr('10.0.0.128/25'),
      '0.0.0.0/0,10.0.0.128\n0.0.0.0/0,10.0.0.255',
    );
    expect(lines[0].reason).toContain('网络地址');
    expect(lines[1].reason).toContain('广播地址');
  });

  it('重复目标按行报错（首个保留，后续标错）', () => {
    const { ok, lines } = parseRouteLines(
      cidr('10.0.0.0/24'),
      ['10.1.0.0/16,10.0.0.1', '10.1.0.0/16,10.0.0.2', '10.1.0.0/16,10.0.0.3'].join('\n'),
    );
    expect(ok).toBe(false);
    expect(lines[0].status).toBe('ok');
    expect(lines[1].status).toBe('invalid');
    expect(lines[1].reason).toContain('第 1 行重复');
    expect(lines[2].reason).toContain('第 1 行重复');
  });

  it('同地址不同前缀不算重复', () => {
    const { ok } = parseRouteLines(
      cidr('10.0.0.0/24'),
      '10.0.0.0/8,10.0.0.1\n10.0.0.0/16,10.0.0.2',
    );
    expect(ok).toBe(true);
  });

  it('格式错误：缺逗号、空段、多个逗号', () => {
    const { lines } = parseRouteLines(
      cidr('10.0.0.0/24'),
      ['0.0.0.0/0 10.0.0.1', ',10.0.0.1', '0.0.0.0/0,', '0.0.0.0/0,10.0.0.1,10.0.0.2'].join('\n'),
    );
    expect(lines).toHaveLength(4);
    expect(lines.every((l) => l.status === 'invalid')).toBe(true);
  });

  it('纯空白输入不合法（无任何路由）', () => {
    expect(parseRouteLines(cidr('10.0.0.0/24'), '\n  \n').ok).toBe(false);
  });

  it('错误时仍可通过行号回填错误信息', () => {
    const { lines } = parseRouteLines(cidr('10.0.0.0/24'), '\n\nbad,bad');
    expect(lines[0].row).toBe(3);
  });
});

describe('十六进制解码', () => {
  it('往返：编码 → 解码 → 路由一致', () => {
    const routes = [
      { target: cidr('0.0.0.0/0'), nextHop: cidr('10.0.0.1/32').base },
      { target: cidr('10.20.0.0/16'), nextHop: cidr('10.0.0.2/32').base },
      { target: cidr('192.168.1.128/25'), nextHop: cidr('10.0.0.3/32').base },
      { target: cidr('172.16.5.4/32'), nextHop: cidr('10.0.0.4/32').base },
    ];
    const { hex: h } = encodeClasslessRoutes(routes);
    const d = decodeClasslessRoutesHex(h);
    expect(d.ok).toBe(true);
    if (!d.ok) throw new Error('should decode');
    expect(d.routes.map((r) => `${r.target.base}/${r.target.prefix}`)).toEqual([
      '0/0',
      `${cidr('10.20.0.0/16').base}/16`,
      `${cidr('172.16.5.4/32').base}/32`,
      `${cidr('192.168.1.128/25').base}/25`,
    ]);
    expect(d.routes.map((r) => longToIpv4(r.nextHop))).toEqual([
      '10.0.0.1',
      '10.0.0.2',
      '10.0.0.4',
      '10.0.0.3',
    ]);
    expect(d.length).toBe(5 + 7 + 9 + 9);
  });

  it('接受空格、0x 前缀与大写', () => {
    const d = decodeClasslessRoutesHex('0x00 0A 00 00 01');
    expect(d.ok).toBe(true);
  });

  it('拒绝奇数个十六进制字符与非十六进制字符', () => {
    expect((decodeClasslessRoutesHex('abc') as DecodeResult).ok).toBe(false);
    const bad = decodeClasslessRoutesHex('zz000a000001');
    expect(bad.ok).toBe(false);
    expect(bad.ok === false && bad.error).toContain('十六进制非法');
    expect(decodeClasslessRoutesHex('  ').ok).toBe(false);
  });

  it('拒绝截断：下一跳缺字节', () => {
    // /0 后只跟 3 字节
    const d = decodeClasslessRoutesHex('000a0000');
    expect(d.ok).toBe(false);
    if (d.ok) throw new Error('should fail');
    expect(d.error).toContain('截断');
  });

  it('拒绝截断：目标有效字节缺失', () => {
    // /16 需要 2 个目标字节，只给 1 个，再给 4 字节
    const d = decodeClasslessRoutesHex('100a0a000001');
    expect(d.ok).toBe(false);
    if (d.ok) throw new Error('should fail');
    expect(d.error).toContain('截断');
  });

  it('拒绝冗余目标字节：/0 多携带 4 个目标字节导致尾部残余', () => {
    // 00 + 4 个“目标”字节 + 4 字节下一跳：前段吃掉 5 字节，尾部被当作下一条并截断
    const d = decodeClasslessRoutesHex('0000000000' + '0a000001' + '20');
    expect(d.ok).toBe(false);
    if (d.ok) throw new Error('should fail');
    expect(d.error).toMatch(/截断|前缀长度/);
  });

  it('拒绝非规范网络位：/9 有效字节第二字节低位非零', () => {
    // 09 0a 81 0a 00 00 01：10.129.0.0/9 主机位非零
    const d = decodeClasslessRoutesHex('090a81' + '0a000001');
    expect(d.ok).toBe(false);
    if (d.ok) throw new Error('should fail');
    expect(d.error).toContain('冗余主机位');
  });

  it('拒绝非规范网络位：/25 第四字节低位非零', () => {
    // 19 c0 a8 01 0f = 192.168.1.15/25（低 7 位应为 0）
    const d = decodeClasslessRoutesHex('19c0a8010f' + '0a000001');
    expect(d.ok).toBe(false);
    if (d.ok) throw new Error('should fail');
    expect(d.error).toContain('冗余主机位');
  });

  it('八位边界前缀不检查尾字节（全部位均被覆盖）', () => {
    // /16 第二目标字节 0xff 合法
    const d = decodeClasslessRoutesHex('100aff' + '0a000001');
    expect(d.ok).toBe(true);
    if (!d.ok) throw new Error('should decode');
    expect(d.routes[0].target.base).toBe(cidr('10.255.0.0/16').base);
  });

  it('拒绝前缀长度 > 32', () => {
    const d = decodeClasslessRoutesHex('21' + '0a000001' + '00000000');
    expect(d.ok).toBe(false);
    if (d.ok) throw new Error('should fail');
    expect(d.error).toContain('超过 32');
  });

  it('拒绝重复目标', () => {
    const d = decodeClasslessRoutesHex(
      '080a' + '0a000001' +
      '080a' + '0a000002',
    );
    expect(d.ok).toBe(false);
    if (d.ok) throw new Error('should fail');
    expect(d.error).toContain('重复');
  });

  it('解码单字节前缀 0 的边界：空选项不允许（空输入报错）', () => {
    expect(decodeClasslessRoutesHex('').ok).toBe(false);
  });

  it('解码后可回填为文本行', () => {
    const d = decodeClasslessRoutesHex(
      '080a' + '09ffff0f' +
      '10ac10' + '09ffff0f',
    );
    if (!d.ok) throw new Error(d.error);
    expect(routesToText(d.routes)).toBe('10.0.0.0/8,9.255.255.15\n172.16.0.0/16,9.255.255.15');
  });

  it('下一跳 255.255.255.255 与 0.0.0.0 均可解码（四字节原样保留）', () => {
    const d = decodeClasslessRoutesHex('00' + 'ffffffff');
    expect(d.ok).toBe(true);
    if (!d.ok) throw new Error('should decode');
    expect(longToIpv4(d.routes[0].nextHop)).toBe('255.255.255.255');
    const d0 = decodeClasslessRoutesHex('00' + '00000000');
    expect(d0.ok).toBe(true);
  });

  it('每条拆解字节与整包一致', () => {
    const d = decodeClasslessRoutesHex(
      '080a' + '0a000001' +
      '20c0a8010a' + 'c0a80101',
    );
    if (!d.ok) throw new Error(d.error);
    expect(d.encoded.flatMap((e) => e.bytes)).toEqual(
      hex('080a0a000001' + '20c0a8010ac0a80101'),
    );
  });
});

describe('格式化', () => {
  it('formatRoute', () => {
    expect(
      formatRoute({ target: cidr('0.0.0.0/0'), nextHop: cidr('10.0.0.1/32').base }),
    ).toBe('0.0.0.0/0 via 10.0.0.1');
  });
});
