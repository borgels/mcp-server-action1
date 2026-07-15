import { createServer as createNodeServer } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer as createMcpServer } from '../server.js';
import {
  assertAllowedOrigin,
  assertAuthorized,
  corsHeaders,
  getHttpConfig,
  HttpRequestError,
  readJsonBody,
  sendJson,
} from './http-helpers.js';

const config = getHttpConfig();

const httpServer = createNodeServer(async (req, res) => {
  try {
    if (req.url !== '/mcp') {
      sendJson(res, 404, { error: 'Not found' }, req);
      return;
    }

    assertAllowedOrigin(req);

    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders(req));
      res.end();
      return;
    }

    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'Method not allowed' }, req, { Allow: 'POST' });
      return;
    }

    assertAuthorized(req, config);
    const body = await readJsonBody(req, config.maxBodyBytes);
    const mcpServer = createMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, body);

    res.on('close', () => {
      void transport.close();
      void mcpServer.close();
    });
  } catch (error) {
    console.error(error);
    if (!res.headersSent) {
      if (error instanceof HttpRequestError) {
        sendJson(res, error.status, { error: error.message }, req);
        return;
      }

      sendJson(res, 500, {
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Internal server error',
        },
        id: null,
      }, req);
    }
  }
});

httpServer.listen(config.port, config.host, () => {
  console.error(`Action1 MCP HTTP server listening on http://${config.host}:${config.port}/mcp`);
});
