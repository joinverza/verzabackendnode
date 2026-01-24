import pino from "pino";
export type Logger = ReturnType<typeof createLogger>;
export declare function createLogger(opts: {
    service: string;
    level: string;
}): pino.Logger<never, boolean>;
//# sourceMappingURL=index.d.ts.map