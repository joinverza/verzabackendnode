import type { Router } from "express";
import type { MainApiContext } from "../routes.js";
export declare function createProofsRouter(ctx: MainApiContext): Router;
export declare function getOrCreateProofForCredential(ctx: MainApiContext, opts: {
    userId: string;
    credentialId: string;
    type?: string;
}): Promise<{
    id: string;
    credential_id: string;
    type: string;
    status: string;
    created_at: string;
    proof: unknown;
}>;
//# sourceMappingURL=proofs.d.ts.map