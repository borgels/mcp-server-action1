import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Action1Client, type Action1ClientOptions } from './action1/client.js';
import { registerAction1Tools } from './tools/action1.js';

export interface CreateServerOptions {
  client?: Action1Client;
  clientOptions?: Action1ClientOptions;
  /** Caller identity recorded in audit log entries (e.g. the X-MCP-User header). */
  caller?: string;
}

export function createServer(options: CreateServerOptions = {}): McpServer {
  const server = new McpServer({
    name: 'action1',
    version: '0.1.0',
  });

  const client = options.client ?? new Action1Client(options.clientOptions);
  registerAction1Tools(server, client, { caller: options.caller });

  return server;
}
