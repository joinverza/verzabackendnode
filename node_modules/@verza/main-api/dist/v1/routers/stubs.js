import express from "express";
export function createStubRouter() {
    const router = express.Router();
    router.all(/.*/, (_req, res) => res.json({ status: "ok" }));
    return router;
}
//# sourceMappingURL=stubs.js.map