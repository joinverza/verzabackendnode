import pino from "pino";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { W3CTraceContextPropagator } from "@opentelemetry/core";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { NodeSDK } from "@opentelemetry/sdk-node";
import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";

export type Logger = ReturnType<typeof createLogger>;

let telemetrySdk: NodeSDK | null = null;
let telemetryEnabled = false;

export function createLogger(opts: { service: string; level: string }) {
  return pino({
    level: opts.level,
    base: { service: opts.service },
    redact: {
      paths: [
        "req.headers.authorization",
        "req.headers.cookie",
        "req.headers.set-cookie",
        "req.headers.x-api-key",
        'req.headers["x-api-key"]',
        'req.headers["x-institution-api-key"]',
        'req.headers["x-anchor-secret"]'
      ],
      remove: true
    }
  });
}

export async function initTelemetry(opts: { serviceName: string }) {
  if (telemetrySdk) return { enabled: telemetryEnabled, shutdown: shutdownTelemetry };

  const exporterEndpoint = String(process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "").trim();
  const tracesExporter = String(process.env.OTEL_TRACES_EXPORTER ?? "").trim();
  const enabledFlag = String(process.env.OTEL_ENABLED ?? "").trim();
  telemetryEnabled = enabledFlag === "1" || enabledFlag.toLowerCase() === "true" || Boolean(exporterEndpoint) || Boolean(tracesExporter);
  if (!telemetryEnabled || tracesExporter.toLowerCase() === "none") return { enabled: false, shutdown: shutdownTelemetry };

  const url = exporterEndpoint ? (exporterEndpoint.endsWith("/v1/traces") ? exporterEndpoint : `${exporterEndpoint.replace(/\/+$/, "")}/v1/traces`) : undefined;
  const traceExporter = url ? new OTLPTraceExporter({ url }) : undefined;

  telemetrySdk = new NodeSDK({
    resource: resourceFromAttributes({ "service.name": opts.serviceName }),
    ...(traceExporter ? { traceExporter } : {}),
    instrumentations: [getNodeAutoInstrumentations()],
    contextManager: new AsyncLocalStorageContextManager(),
    textMapPropagator: new W3CTraceContextPropagator()
  });

  telemetrySdk.start();
  return { enabled: true, shutdown: shutdownTelemetry };
}

export async function shutdownTelemetry() {
  if (!telemetrySdk) return;
  const sdk = telemetrySdk;
  telemetrySdk = null;
  telemetryEnabled = false;
  await sdk.shutdown();
}
