import assert from "node:assert/strict";
import test from "node:test";
import { sha256Hex } from "@verza/crypto";
import { HttpError } from "@verza/http";
import { generateTwoFactorSetup, verifyTwoFactorOrThrow } from "./index.js";
void test("verifyTwoFactorOrThrow returns used backup code hash when valid", () => {
    const setup = generateTwoFactorSetup();
    const backupCodesShaJson = JSON.stringify(setup.backupCodes.map((c) => sha256Hex(c)));
    const out = verifyTwoFactorOrThrow({
        totpSecretBase32: setup.secret,
        backupCodesShaJson,
        backupCode: setup.backupCodes[0]
    });
    assert.equal(out.usedBackupCodeSha, sha256Hex(setup.backupCodes[0]));
});
void test("verifyTwoFactorOrThrow throws invalid_twofa on bad codes", () => {
    const setup = generateTwoFactorSetup();
    const backupCodesShaJson = JSON.stringify(setup.backupCodes.map((c) => sha256Hex(c)));
    assert.throws(() => verifyTwoFactorOrThrow({
        totpSecretBase32: setup.secret,
        backupCodesShaJson,
        backupCode: "0000000000"
    }), (err) => err instanceof HttpError && err.code === "invalid_twofa");
});
//# sourceMappingURL=twofa.test.js.map