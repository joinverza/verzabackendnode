import assert from "node:assert/strict";
import test from "node:test";

import { sanitizeAuditData } from "./auditLog.js";

void test("sanitizeAuditData drops common secret keys (case-insensitive, nested)", () => {
  const input = {
    password: "p",
    current_password: "cp",
    new_password: "np",
    refresh_token: "rt",
    access_token: "at",
    token: "t",
    secret: "s",
    api_key: "k",
    authorization: "Bearer abc",
    encrypted_data: "enc",
    backup_codes: ["b1", "b2"],
    twofa_secret: "2fa",
    nested: { Password: "P2", deep: { Authorization: "Bearer def", ok: 1 } },
    arr: [{ api_key: "k2", ok: true }]
  };
  const out = sanitizeAuditData(input) as any;
  assert.equal("password" in out, false);
  assert.equal("token" in out, false);
  assert.equal("authorization" in out, false);
  assert.equal("encrypted_data" in out, false);
  assert.equal("backup_codes" in out, false);
  assert.equal("twofa_secret" in out, false);
  assert.equal("current_password" in out, false);
  assert.equal("new_password" in out, false);
  assert.equal("refresh_token" in out, false);
  assert.equal("access_token" in out, false);
  assert.equal(out.nested?.Password, undefined);
  assert.equal(out.nested?.deep?.Authorization, undefined);
  assert.equal(out.nested?.deep?.ok, 1);
  assert.deepEqual(out.arr, [{ ok: true }]);
});

void test("sanitizeAuditData truncates long strings", () => {
  const long = "a".repeat(5000);
  const out = sanitizeAuditData({ ok: long }) as any;
  assert.equal(typeof out.ok, "string");
  assert.equal(out.ok.length <= 2050, true);
});

void test("sanitizeAuditData stays stable under repeated calls", () => {
  for (let i = 0; i < 2000; i += 1) {
    const out = sanitizeAuditData({ i, token: "t", nested: { password: "p", ok: true } }) as any;
    assert.equal(out.token, undefined);
    assert.equal(out.nested?.password, undefined);
    assert.equal(out.nested?.ok, true);
  }
});
