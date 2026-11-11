// 新签发来源显式选择窗口；旧原件缺少策略字段时仍按原来的两秒校验。
export const authoritySourceWindowPolicy = 'authority-source-window/2';
export const authoritySourceWindowNs = 5000000000n;
export function sourceWindowNs(value) {
 if (!Object.hasOwn(value, 'source_window_policy')) return 2000000000n;
 if (value.source_window_policy !== authoritySourceWindowPolicy) throw new Error('authority_source_window_policy');
 return authoritySourceWindowNs;
}
export function sourceWindowContains(value, start, end) {
 const first = BigInt(start), last = BigInt(end);
 return last > first && last - first <= sourceWindowNs(value);
}
