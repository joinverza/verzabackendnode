import pino from "pino";

export type Logger = ReturnType<typeof createLogger>;

export function createLogger(opts: { service: string; level: string }) {
  return pino({ level: opts.level, base: { service: opts.service } });
}

