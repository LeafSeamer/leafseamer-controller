// 业务入口接受已发布布局，功能自己的最低版本仍由调用方声明。
export const currentStorageRevision = 109;

export function supportsStorageRevision(revision, minimum) {
  return Number.isInteger(revision) && revision >= minimum && revision <= currentStorageRevision;
}
