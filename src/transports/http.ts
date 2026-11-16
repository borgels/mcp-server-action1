import { action1EnvTimeoutMs } from '../action1/client.js';
import { ConfigError } from '../config-env.js';
import { configWarnings, getHttpConfig, type HttpConfig } from './http-helpers.js';
import { startHttpServer } from './http-server.js';

async function main(): Promise<void> {
  let config: HttpConfig;
  try {
    config = getHttpConfig();
    // Validate ACTION1_* numeric settings now instead of failing on every request.
    action1EnvTimeoutMs();
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error(`Action1 MCP HTTP server not started: ${error.message}`);
      process.exit(1);
    }
    throw error;
  }

  for (const warning of configWarnings(config)) {
    console.error(warning);
  }

  const running = await startHttpServer(config);
  console.error(`Action1 MCP HTTP server listening on http://${config.host}:${running.port}/mcp`);

  const shutdown = (signal: string) => {
    console.error(`Received ${signal}, shutting down`);
    void running.close().then(() => process.exit(0));
  };
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
