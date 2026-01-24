import { createMainApiServer } from "./server.js";

const server = await createMainApiServer();
await server.start();

