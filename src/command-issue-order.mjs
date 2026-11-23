export function commandIssueHead(db, before = null) {
  if(!db.inTransaction) throw new Error('command_issue_order_writer');
  const table=Number(db.pragma('user_version',{simple:true}))>=92?'command_issue_order':'command_transmission_issue';
  const head=before===null
    ? db.prepare(`SELECT max(issued_revision) FROM ${table}`).pluck().get()
    : db.prepare(`SELECT max(issued_revision) FROM ${table} WHERE issued_revision<?`).pluck().get(before);
  return String(BigInt(head??'0'));
}
