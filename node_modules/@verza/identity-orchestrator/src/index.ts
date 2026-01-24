import { createIdentityOrchestratorServer } from "./server.js";

const server = await createIdentityOrchestratorServer();
await server.start();

