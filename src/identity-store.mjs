import crypto from 'node:crypto';
import {IdentityError, createOpaqueSecret, verifyOpaqueSecret, hashPassword, passwordProfile, validateLogin} from './identity-crypto.mjs';
import {initializeLocalPermissions} from './local-permission-store.mjs';

// 仅本地writer使用；HTTP处理器不得把调用本模块当作认证证明。
export function identityStore(db, serviceBootId, permissionService = null) {
  let current = null;
  const exists = () => db.prepare('SELECT count(*) FROM identity_initialization').pluck().get() !== 0;
  const reject = code => { throw new IdentityError(code); };
  const ensureCurrent = input => {
    if (!db.open) reject('identity_unavailable');
    if (exists()) reject('identity_already_initialized');
    const now = process.hrtime.bigint();
    if (!current || input.token_id !== current.tokenId || now < current.started || now >= current.deadline) reject('initialization_capability_invalid');
    const row = db.prepare("SELECT verifier FROM first_admin_challenge WHERE token_id = ? AND service_boot_id = ? AND state = 'pending'").pluck().get(current.tokenId, serviceBootId);
    if (!row || !verifyOpaqueSecret('first_admin', input.secret, row)) reject('initialization_capability_invalid');
  };
  return Object.freeze({
    summary() {
      const row = db.prepare('SELECT i.principal_id, i.issuer_id, i.mode, i.tx_id, r.issuer_epoch FROM identity_initialization i JOIN identity_issuer r ON r.issuer_id = i.issuer_id').raw().get();
      if (!row) return {initialized: false};
      return {initialized: true, principal_id: row[0], issuer_id: row[1], mode: row[2], transaction_id: row[3], issuer_epoch: row[4]};
    },
    begin() {
      if (exists()) reject('identity_already_initialized');
      const {secret, verifier} = createOpaqueSecret('first_admin'), tokenId = crypto.randomUUID();
      const started = process.hrtime.bigint(), deadline = started + 600_000_000_000n;
      db.transaction(() => {
        db.prepare("UPDATE first_admin_challenge SET state = 'invalidated' WHERE state = 'pending'").run();
        db.prepare("INSERT INTO first_admin_challenge VALUES (?, ?, ?, 'pending', NULL)").run(tokenId, serviceBootId, verifier);
      }).immediate();
      current = {tokenId, started, deadline};
      return Object.freeze({token_id: tokenId, secret, expires_in_seconds: 600});
    },
    async complete(input) {
      if (!input || typeof input !== 'object' || Object.keys(input).sort().join(',') !== 'login,mode,password,secret,token_id') reject('initialization_input');
      input = Object.freeze({...input});
      ensureCurrent(input); validateLogin(input.login);
      if (!['standalone', 'suite_issuer'].includes(input.mode)) reject('initialization_input');
      const phc = await hashPassword(input.password);
      const principalId = crypto.randomUUID(), issuerId = crypto.randomUUID(), epoch = crypto.randomUUID(), txId = crypto.randomUUID();
      const result = {initialized: true, principal_id: principalId, issuer_id: issuerId, issuer_epoch: epoch, mode: input.mode, transaction_id: txId};
      db.transaction(() => {
        // KDF期间不占SQLite事务；进入唯一writer后重核期限与消费状态。
        ensureCurrent(input);
        db.prepare('INSERT INTO identity_issuer VALUES (?, ?, ?)').run(issuerId, epoch, txId);
        db.prepare("INSERT INTO subject VALUES (?, ?, ?, ?, 'human')").run(crypto.randomUUID(), issuerId, epoch, principalId);
        db.prepare("INSERT INTO local_principal VALUES (?, ?, ?, ?, 'active', '1', ?)").run(principalId, input.login, phc, passwordProfile, txId);
        db.prepare("INSERT INTO local_authorization VALUES (?, 'administrator', '1', ?)").run(principalId, txId);
        db.prepare("UPDATE first_admin_challenge SET state = 'consumed', consumed_tx_id = ? WHERE token_id = ? AND state = 'pending'").run(txId, input.token_id);
        db.prepare('INSERT INTO identity_initialization VALUES (1, ?, ?, ?, ?, ?)').run(txId, input.token_id, principalId, issuerId, input.mode);
        db.prepare("INSERT INTO identity_receipt VALUES (?, 'first_admin', ?, ?)").run(txId, principalId, input.token_id);
        if (permissionService) initializeLocalPermissions(db, permissionService);
      }).immediate();
      current = null;
      return Object.freeze(result);
    }
  });
}
