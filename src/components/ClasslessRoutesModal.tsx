import { useMemo, useState } from 'react';
import { Allocation } from '../lib/model';
import { cidrToString, longToIpv4, parseCidr } from '../lib/ip';
import { usableRangeOf } from '../lib/dhcp';
import {
  DecodeResult,
  decodeClasslessRoutesHex,
  encodeClasslessRoutes,
  parseRouteLines,
} from '../lib/classlessRoutes';

interface Props {
  alloc: Allocation;
  onClose: () => void;
}

const toHex = (n: number) => n.toString(16).padStart(2, '0');

async function copyText(value: string, onDone: () => void): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // 剪贴板 API 不可用（如非安全上下文）时回退
    const ta = document.createElement('textarea');
    ta.value = value;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
  onDone();
}

/**
 * DHCP 类无静态路由（RFC 3442，Option 121）弹窗：
 * 逐行输入「目标 CIDR,下一跳 IPv4」，编码为十六进制 Option 121；
 * 支持粘贴十六进制反向解码并回填表格。纯本地只读计算，不修改规划与历史，冲突锁定期间可用。
 */
export default function ClasslessRoutesModal({ alloc, onClose }: Props) {
  const subnet = useMemo(() => parseCidr(alloc.cidr)!, [alloc.cidr]);
  const usable = usableRangeOf(subnet);
  const [text, setText] = useState('');
  const [hexInput, setHexInput] = useState('');
  const [decodeResult, setDecodeResult] = useState<DecodeResult | null>(null);
  const [copiedHex, setCopiedHex] = useState(false);
  const [copiedLines, setCopiedLines] = useState(false);

  const parsed = useMemo(() => parseRouteLines(subnet, text), [subnet, text]);
  const encoded = useMemo(
    () => (parsed.ok ? encodeClasslessRoutes(parsed.lines.map((l) => l.route!)) : null),
    [parsed],
  );

  const doDecode = () => {
    const result = decodeClasslessRoutesHex(hexInput);
    setDecodeResult(result);
    if (result.ok) {
      setText(result.routes.map((r) => `${cidrToString(r.target)},${longToIpv4(r.nextHop)}`).join('\n'));
      setCopiedHex(false);
      setCopiedLines(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal wide" onClick={(e) => e.stopPropagation()}>
        <h3>DHCP 类无静态路由（Option 121）：{alloc.name}</h3>
        <p className="muted">
          子网 <code>{alloc.cidr}</code>，可用主机范围（下一跳必须在此范围内）{' '}
          <code>
            {longToIpv4(usable.start)} - {longToIpv4(usable.end)}
          </code>
          {subnet.prefix <= 30
            ? '（已自动排除网络地址与广播地址）'
            : '（/' + subnet.prefix + ' 按可用主机规则不排除任何地址）'}
          。每行一条 <code>目标 CIDR,下一跳 IPv4</code>，空行忽略；目标必须合法且对齐网络地址，
          目标重复按行报错。按 RFC 3442 编码为「前缀长度 + 目标有效字节 + 4 字节下一跳」，
          按目标地址、前缀排序输出。纯本地只读计算，不修改规划与历史，冲突锁定期间可用。
        </p>

        <label className="field">
          <span>路由清单（每行「目标 CIDR,下一跳 IPv4」，空行忽略）</span>
          <textarea
            autoFocus
            rows={6}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setCopiedHex(false);
              setCopiedLines(false);
            }}
            placeholder={'例如：\n0.0.0.0/0,10.0.0.1\n192.168.1.0/24,10.0.0.254\n10.10.0.0/16,10.0.0.2'}
            spellCheck={false}
          />
        </label>

        {parsed.lines.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>输入</th>
                  <th>校验结果</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {parsed.lines.map((l) => (
                  <tr key={l.row} className={l.status === 'ok' ? undefined : 'mig-moved'}>
                    <td className="muted">{l.row}</td>
                    <td>
                      <code>{l.input}</code>
                    </td>
                    <td>
                      {l.route ? (
                        <span>
                          <code>{cidrToString(l.route.target)}</code> →{' '}
                          <code>{longToIpv4(l.route.nextHop)}</code>
                        </span>
                      ) : (
                        <span className="muted">{l.reason}</span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${l.status === 'ok' ? 'mig-kept' : 'mig-moved'}`}>
                        {l.status === 'ok' ? '✓ 合法' : '非法'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {parsed.lines.some((l) => l.status !== 'ok') && (
          <ul className="errors batch-errors">
            {parsed.lines
              .filter((l) => l.status !== 'ok')
              .map((l) => (
                <li key={l.row}>
                  第 {l.row} 行：{l.reason}
                </li>
              ))}
          </ul>
        )}

        {encoded && (
          <div className="dhcp-result">
            <div className="dhcp-result-head">
              <span>
                Option 121 共 {encoded.routes.length} 条路由 · {encoded.length} 字节，按目标地址/前缀排序
              </span>
              <button
                className="btn small"
                onClick={() => copyText(encoded.hex, () => setCopiedHex(true))}
              >
                {copiedHex ? '已复制 ✓' : '复制十六进制'}
              </button>
            </div>
            <textarea
              readOnly
              rows={2}
              value={encoded.hex}
              style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
            />

            <div className="table-wrap" style={{ marginTop: 8 }}>
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>目标 CIDR</th>
                    <th>下一跳</th>
                    <th>前缀长度</th>
                    <th>目标有效字节</th>
                    <th>下一跳 4 字节</th>
                    <th>本条十六进制</th>
                  </tr>
                </thead>
                <tbody>
                  {encoded.routes.map((e, i) => (
                    <tr key={i}>
                      <td className="muted">{i + 1}</td>
                      <td>
                        <code>{cidrToString(e.route.target)}</code>
                      </td>
                      <td>
                        <code>{longToIpv4(e.route.nextHop)}</code>
                      </td>
                      <td>
                        {e.prefixByte}（/{e.prefixByte}，{e.targetBytes.length} 个目标字节）
                      </td>
                      <td>
                        {e.targetBytes.length > 0 ? (
                          <code className="hex-cell">
                            {e.targetBytes.map(toHex).join(' ')}
                          </code>
                        ) : (
                          <span className="muted">无（/0）</span>
                        )}
                      </td>
                      <td>
                        <code className="hex-cell">{e.nextHopBytes.map(toHex).join(' ')}</code>
                      </td>
                      <td>
                        <code className="hex-cell">{e.bytes.map(toHex).join(' ')}</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="batch-foot">
              <button
                className="btn small"
                onClick={() =>
                  copyText(
                    parsed.lines
                      .filter((l) => l.route)
                      .map((l) => `${cidrToString(l.route!.target)},${longToIpv4(l.route!.nextHop)}`)
                      .join('\n'),
                    () => setCopiedLines(true),
                  )
                }
              >
                {copiedLines ? '已复制 ✓' : '复制路由清单'}
              </button>
              <span className="batch-summary muted">
                字节拆解：每条 = 1 字节前缀长度 + ceil(前缀/8) 字节目标网络 + 4 字节下一跳
              </span>
            </div>
          </div>
        )}

        <hr style={{ margin: '14px 0', border: 'none', borderTop: '1px solid var(--border)' }} />

        <label className="field">
          <span>反向解码：粘贴 Option 121 十六进制（可含空格，成功后回填上方表格）</span>
          <textarea
            rows={2}
            value={hexInput}
            onChange={(e) => {
              setHexInput(e.target.value);
              setDecodeResult(null);
            }}
            placeholder="例如：00 0a 00 00 01 18 c0 a8 01 c0 a8 01 01"
            spellCheck={false}
            style={{ fontFamily: 'monospace' }}
          />
        </label>
        <div className="batch-foot">
          <button className="btn" disabled={hexInput.trim() === ''} onClick={doDecode}>
            解码并回填
          </button>
          {decodeResult && !decodeResult.ok && (
            <span className="form-error">{decodeResult.error}</span>
          )}
          {decodeResult && decodeResult.ok && (
            <span className="batch-summary" style={{ color: 'var(--green)' }}>
              ✓ 解码成功：{decodeResult.routes.length} 条路由，{decodeResult.length} 字节，已回填表格
            </span>
          )}
        </div>

        <div className="modal-actions">
          <button className="btn" onClick={onClose}>
            关闭
          </button>
        </div>
      </div>
    </div>
  );
}
