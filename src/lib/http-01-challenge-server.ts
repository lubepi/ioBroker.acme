// Based on https://www.npmjs.com/package/acme-http-01-standalone

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';

interface ChallengeServerConfig {
    log: ioBroker.Log;
    port: number;
    address: string;
}

interface ChallengeData {
    challenge: {
        token: string;
        keyAuthorization: string;
    };
}

interface ChallengeServer {
    init: (opts: Record<string, unknown>) => Promise<null>;
    set: (data: ChallengeData) => Promise<null>;
    get: (data: ChallengeData) => Promise<{ keyAuthorization: string } | null>;
    remove: (data: ChallengeData) => Promise<null>;
    shutdown: () => void;
}

/**
 * Encapsulates the HTTP-01 ACME challenge server.
 * Each instance manages its own state, making it testable and reusable.
 */
class Http01ChallengeServer implements ChallengeServer {
    private readonly config: ChallengeServerConfig;
    private readonly memdb: Record<string, { keyAuthorization: string }> = {};
    private server: Server | null = null;
    private isListening = false;

    constructor(config: ChallengeServerConfig) {
        this.config = config;
    }

    private getChallengeKey(data: ChallengeData): string {
        return data.challenge.token;
    }

    private createServer(): void {
        this.server = createServer();

        this.server.on('error', (err: Error) => {
            // Startup errors are handled by init(); only log runtime errors here.
            if (this.isListening) {
                this.config.log.error(`Challenge server error: ${err.message}`);
            }
        });

        this.server.on('request', (req: IncomingMessage, res: ServerResponse) => {
            let response = '';
            this.config.log.debug(`challengeServer request: ${req.url}`);
            const regexp = /^\/.well-known\/acme-challenge\/(.*)/;
            const matches = req.url?.match(regexp);
            if (!matches || !Array.isArray(matches) || matches.length !== 2) {
                res.statusCode = 400;
                const requestLine = `${req.method || 'GET'} ${req.url || '/'}`;
                this.config.log.debug(`Ignoring non-ACME challenge request: ${requestLine}`);
            } else {
                const rawToken = matches[1] || '';
                const tokenWithoutQuery = rawToken.split('?')[0];
                const normalizedToken = decodeURIComponent(tokenWithoutQuery).replace(/\/+$/, '');
                this.config.log.debug(`Got challenge for ${normalizedToken}`);
                const knownTokens = Object.keys(this.memdb);
                const matchedToken = knownTokens.find(knownToken => knownToken === normalizedToken);
                if (!matchedToken) {
                    res.statusCode = 404;
                    this.config.log.warn(`Challenge server request token not in DB: ${normalizedToken}`);
                } else {
                    res.statusCode = 200;
                    response = this.memdb[matchedToken].keyAuthorization;
                }
            }
            this.config.log.debug(`Challenge server status & response: ${res.statusCode} ${response}`);
            res.end(response);
        });
    }

    init(opts: Record<string, unknown>): Promise<null> {
        this.config.log.debug(`init: ${JSON.stringify(opts)}`);
        return new Promise((resolve, reject) => {
            if (this.server) {
                this.config.log.warn('Server already running!');
                resolve(null);
            } else {
                this.createServer();
                const startupErrorHandler = (err: Error): void => {
                    this.server?.off('error', startupErrorHandler);
                    this.isListening = false;
                    reject(err);
                };

                this.server!.once('error', startupErrorHandler);
                this.server!.listen(this.config.port, this.config.address, () => {
                    this.server?.off('error', startupErrorHandler);
                    this.isListening = true;
                    this.config.log.info(
                        `challengeServer listening on ${this.config.address} port ${this.config.port}`,
                    );
                    resolve(null);
                });
            }
        });
    }

    set(data: ChallengeData): Promise<null> {
        this.config.log.debug(`set: ${JSON.stringify(data)}`);
        const key = this.getChallengeKey(data);
        this.memdb[key] = data.challenge;
        this.config.log.debug(`Added ${key} - DB now contains: ${Object.keys(this.memdb).length}`);
        return Promise.resolve(null);
    }

    get(data: ChallengeData): Promise<{ keyAuthorization: string } | null> {
        this.config.log.debug(`get: ${JSON.stringify(data)}`);
        const key = this.getChallengeKey(data);
        if (this.memdb[key]) {
            return Promise.resolve({ keyAuthorization: this.memdb[key].keyAuthorization });
        }
        return Promise.resolve(null);
    }

    remove(data: ChallengeData): Promise<null> {
        this.config.log.debug(`remove: ${JSON.stringify(data)}`);
        const key = this.getChallengeKey(data);
        delete this.memdb[key];
        this.config.log.debug(`DB now contains: ${Object.keys(this.memdb).length}`);
        return Promise.resolve(null);
    }

    shutdown(): void {
        if (!this.server) {
            this.config.log.warn('Shutdown called but nothing to do');
        } else {
            this.config.log.info('Shutting down challengeServer');
            this.isListening = false;
            this.server.close();
            this.server = null;
        }
        // Clear all stored challenges
        for (const key of Object.keys(this.memdb)) {
            delete this.memdb[key];
        }
    }
}

export function create(config: ChallengeServerConfig): ChallengeServer {
    return new Http01ChallengeServer(config);
}
