import pino from "pino";
export type Logger = ReturnType<typeof createLogger>;
export declare function createLogger(opts: {
    service: string;
    level: string;
}): pino.Logger<never, boolean>;
export declare function initTelemetry(opts: {
    serviceName: string;
}): Promise<{
    enabled: boolean;
    shutdown: typeof shutdownTelemetry;
}>;
export declare function shutdownTelemetry(): Promise<void>;
//# sourceMappingURL=index.d.ts.map