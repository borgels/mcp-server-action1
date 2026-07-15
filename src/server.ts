import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Action1Client, type Action1ClientOptions } from './action1/client.js';
import { registerAction1Tools } from './tools/action1.js';

export interface CreateServerOptions {
  client?: Action1Client;
  clientOptions?: Action1ClientOptions;
}

export function createServer(options: CreateServerOptions = {}): McpServer {
  const server = new McpServer({
    name: 'action1',
    version: '0.1.0',
  });

  const client = options.client ?? new Action1Client(options.clientOptions);
  registerAction1Tools(server, client);

  return server;
}
