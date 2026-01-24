import { createIdentityGatewayServer } from "./server.js";

const server = createIdentityGatewayServer();
await server.start();
