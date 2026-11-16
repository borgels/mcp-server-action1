import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Action1Client, type Action1ClientOptions } from './action1/client.js';
import { registerAction1Tools } from './tools/action1.js';
import { PACKAGE_VERSION } from './version.js';

export interface CreateServerOptions {
  client?: Action1Client;
  clientOptions?: Action1ClientOptions;
  /** Caller identity recorded in audit log entries (e.g. the X-MCP-User header). */
  caller?: string;
}

export function createServer(options: CreateServerOptions = {}): McpServer {
  const server = new McpServer({
    name: 'action1',
    version: PACKAGE_VERSION,
  });

  const client = options.client ?? new Action1Client(options.clientOptions);
  registerAction1Tools(server, client, { caller: options.caller });

  return server;
}
