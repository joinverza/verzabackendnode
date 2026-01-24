import pino from "pino";
export function createLogger(opts) {
    return pino({ level: opts.level, base: { service: opts.service } });
}
//# sourceMappingURL=index.js.map