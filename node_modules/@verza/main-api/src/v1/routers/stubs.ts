import type { Router } from "express";

import express from "express";

export function createStubRouter(): Router {
  const router = express.Router();
  router.all(/.*/, (_req, res) => res.json({ status: "ok" }));
  return router;
}

