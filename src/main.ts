/*
 * Created with @iobroker/create-adapter v2.3.0
 */
import * as utils from '@iobroker/adapter-core';
import { CertificateManager, type CertificateCollection } from '@iobroker/webserver';
import * as acme from 'acme-client';
import crypto from 'node:crypto';
import dns, { promises as dnsPromises } from 'node:dns';
import net from 'node:net';
import { promisify } from 'node:util';
import x509 from 'x509.js';

import type { AdapterOptions } from '@iobroker/adapter-core';

import { create as createAcmeDnsChallenge, registerAcmeDnsAccount } from './lib/dns-01-acmedns';
import { create as createHttp01ChallengeServer } from './lib/http-01-challenge-server';
import { buildDnsChallengeData, normalizeDnsAlias } from './lib/dns-01-utils';
import type { AcmeAdapterConfig } from './types';

const accountObjectId = 'account';
// Renew 7 days before expiry
const renewWindow = 60 * 60 * 24 * 7 * 1000;
const adapterStopWaitTimeoutMs = 20000;
const adapterStopPollIntervalMs = 500;
const portReleaseWaitTimeoutMs = 10000;
const portReleasePollIntervalMs = 250;

interface AcmeAccount {
    full: Record<string, any> | null;
    key: Record<string, any> | null;
    keyEnc?: string | null;
}

interface ChallengeHandler {
    init: (opts: Record<string, unknown>) => Promise<null>;
    set: (data: any) => Promise<null>;
    get: (data: any) => Promise<any>;
    remove: (data: any) => Promise<null>;
    shutdown: () => void;
}

interface CollectionConfig {
    id: string;
    commonName: string;
    altNames: string;
}

interface AcmeDnsCollectionCredentials {
    collectionId: string;
    username: string;
    password: string;
    subdomain: string;
    baseUrl: string;
    fullDomain?: string;
}

class AcmeAdapter extends utils.Adapter {
    declare config: AcmeAdapterConfig;
    private account: AcmeAccount;
    private readonly challenges: Record<string, ChallengeHandler>;
    private readonly toShutdown: ChallengeHandler[];
    private donePortCheck: boolean;
    private certManager: CertificateManager | undefined;
    private acmeClient: acme.Client | null = null;
    private stoppedAdapters: string[] | null | undefined;
    private readonly dnsChallengeCache: Record<string, any>;
    private readonly acmeDnsCnameCheckedHosts: Set<string>;
    private readonly acmeDnsAutoRegisteredCollections: Set<string>;
    private readonly acmeDnsBlockedCollectionReasons: Map<string, string>;
    private acmeDnsAutoRegisterBlocked: boolean;
    private http01ServerReady: boolean;
    private http01ServerInitPromise: Promise<void> | null;

    /**
     * Safely extract an error message from an unknown error value.
     */
    private static getErrorMessage(err: unknown): string {
        if (err instanceof Error) {
            return err.message;
        }
        return String(err);
    }

    /**
     * Adds user-facing context for common opaque runtime errors.
     */
    private getActionableCertificateErrorMessage(err: unknown): string {
        const errorMessage = AcmeAdapter.getErrorMessage(err);

        const stack = err instanceof Error ? err.stack || '' : '';
        const acmeClientTransportBug =
            /Cannot read properties of undefined \(reading 'config'\)/.test(errorMessage) &&
            /acme-client\/src\/axios\.js/.test(stack);

        if (acmeClientTransportBug) {
            const transportHint =
                ' ACME transport error: no valid HTTP response was available from the ACME API (often timeout/connection reset/proxy or DNS/network interruption).';
            return errorMessage + transportHint;
        }

        if (/Cannot read properties of undefined \(reading 'config'\)/.test(errorMessage)) {
            const activeChallenges: string[] = [];
            if (this.config.http01Active) {
                activeChallenges.push('HTTP-01');
            }
            if (this.config.dns01Active) {
                activeChallenges.push(`DNS-01 (${this.config.dns01Module || 'module not set'})`);
            }

            const activeChallengeInfo = activeChallenges.length > 0 ? activeChallenges.join(', ') : 'none configured';

            return `${errorMessage}. Active challenge setup: ${activeChallengeInfo}. This can be caused by provider module/runtime issues, but also by transport/network timeouts. Verify DNS-01 module selection/credentials and connectivity to the ACME API.`;
        }

        return errorMessage;
    }

    constructor(options: Partial<utils.AdapterOptions> = {}) {
        super({
            ...options,
            name: 'acme',
        });

        this.account = {
            full: null,
            key: null,
        };
        this.challenges = {};
        this.toShutdown = [];
        this.donePortCheck = false;
        this.dnsChallengeCache = {};
        this.acmeDnsCnameCheckedHosts = new Set();
        this.acmeDnsAutoRegisteredCollections = new Set();
        this.acmeDnsBlockedCollectionReasons = new Map();
        this.acmeDnsAutoRegisterBlocked = false;
        this.http01ServerReady = false;
        this.http01ServerInitPromise = null;

        this.on('ready', this.onReady.bind(this));
        this.on('unload', this.onUnload.bind(this));
    }

    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     */
    private onUnload(callback: () => void): void {
        void (async () => {
            try {
                this.log.debug('Cleaning up resources...');
                for (const challenge of this.toShutdown) {
                    challenge.shutdown();
                }
                for (const key of Object.keys(this.dnsChallengeCache)) {
                    delete this.dnsChallengeCache[key];
                }
                this.acmeDnsCnameCheckedHosts.clear();
                this.acmeDnsAutoRegisteredCollections.clear();
                this.acmeDnsBlockedCollectionReasons.clear();
                this.http01ServerReady = false;
                this.http01ServerInitPromise = null;
                await this.restoreAdaptersOnSamePort();
            } catch (err) {
                this.log.warn(`Error during unload cleanup: ${AcmeAdapter.getErrorMessage(err)}`);
            } finally {
                callback();
            }
        })();
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady(): Promise<void> {
        // Redact sensitive fields before logging
        const safeConfig: Record<string, unknown> = { ...this.config };
        const sensitiveKeys = ['dns01OapiKey', 'dns01OapiPassword', 'dns01Okey', 'dns01Osecret', 'dns01Otoken'];
        for (const key of sensitiveKeys) {
            if (safeConfig[key]) {
                safeConfig[key] = '***REDACTED***';
            }
        }

        const collectionCredentials = safeConfig.dns01CollectionCredentials;
        if (Array.isArray(collectionCredentials)) {
            safeConfig.dns01CollectionCredentials = collectionCredentials.map((entry: any) => ({
                ...entry,
                password: entry?.password ? '***REDACTED***' : entry?.password,
                subdomain: entry?.subdomain ? '***REDACTED***' : entry?.subdomain,
            }));
        }

        this.log.debug(`config: ${JSON.stringify(safeConfig)}`);

        acme.setLogger((message: string) => this.log.debug(`acme-client: ${message}`));

        this.certManager = new CertificateManager({ adapter: this });

        if (!this.config?.collections?.length) {
            this.terminate('No collections configured - nothing to order');
        } else if (!this.config.maintainerEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.config.maintainerEmail)) {
            this.terminate('Invalid or missing maintainer email address');
        } else {
            const deterministicConfigErrors = this.getDeterministicConfigurationErrors();
            if (deterministicConfigErrors.length) {
                for (const err of deterministicConfigErrors) {
                    this.log.error(`Configuration preflight failed: ${err}`);
                }
                this.terminate(
                    `Configuration preflight failed with ${deterministicConfigErrors.length} error(s). Fix adapter settings and retry.`,
                );
                return;
            }

            // Setup challenges
            await this.initChallenges();

            if (!Object.keys(this.challenges).length) {
                this.log.error('Failed to initiate any challenges');
            } else {
                try {
                    // Init ACME/account, etc
                    await this.initAcme();

                    // Loop round collections and generate certs
                    for (const collection of this.config.collections) {
                        await this.generateCollection(collection);
                    }
                } catch (err) {
                    this.log.error(`Failed in ACME init/generation: ${AcmeAdapter.getErrorMessage(err)}`);
                }
            }
        }

        // Purge any collections we created in the past but are not configured now and have also expired.
        try {
            const collections = await this.certManager.getAllCollections();
            if (collections) {
                const configuredCollectionIds = new Set(this.config.collections.map(c => c.id));
                this.log.debug(`existingCollectionIds: ${JSON.stringify(Object.keys(collections))}`);
                for (const [collectionId, collection] of Object.entries(collections)) {
                    if (
                        collection.from === this.namespace &&
                        !configuredCollectionIds.has(collectionId) &&
                        collection.tsExpires < Date.now()
                    ) {
                        this.log.info(`Removing expired and de-configured collection ${collectionId}`);
                        await this.certManager.delCollection(collectionId);
                    }
                }
            } else {
                this.log.debug(`No collections found`);
            }
        } catch (err) {
            this.log.error(`Failed in existing collection check/purge: ${AcmeAdapter.getErrorMessage(err)}`);
        }

        this.log.debug('Shutdown...');

        for (const challenge of this.toShutdown) {
            challenge.shutdown();
        }

        try {
            await this.restoreAdaptersOnSamePort();
        } catch (err) {
            this.log.error(`Failed to restore adapters on same port: ${AcmeAdapter.getErrorMessage(err)}`);
        }

        this.terminate('Processing complete');
    }

    async initChallenges(): Promise<void> {
        if (this.config.http01Active) {
            this.log.debug('Init http-01 challenge server');
            // This does not actually cause the challenge server to start listening, so we don't need to do port check at this time.
            const thisChallenge = createHttp01ChallengeServer({
                port: this.config.port,
                address: this.config.bind,
                log: this.log,
            });
            this.challenges['http-01'] = thisChallenge;
            this.toShutdown.push(thisChallenge);
        }

        if (this.config.dns01Active) {
            this.log.debug('Init dns-01 challenge');

            // TODO: Is there a better way?
            // Just add all the DNS-01 options blindly for all the modules and see what sticks ;)
            const dns01Options: Record<string, any> = {};
            const dns01Props: Record<string, any> = {};
            for (const [key, value] of Object.entries(this.config)) {
                if (key.startsWith('dns01O')) {
                    // An option...
                    dns01Options[key.slice(6)] = value;
                } else if (key === 'dns01OverifyPropagation' || key === 'dns01PpropagationDelay') {
                    // Deprecated: handled internally/removed from the public config.
                    continue;
                } else if (key.startsWith('dns01P')) {
                    // A property to add after creation
                    dns01Props[key.slice(6)] = value;
                }
            }

            // Add the module-specific options
            switch (this.config.dns01Module) {
                case 'acme-dns-01-namecheap':
                    dns01Options.baseUrl = 'https://api.namecheap.com/xml.response';
                    break;
                case 'acme-dns-01-netcup':
                    // Adapter-side propagation polling is authoritative-first.
                    // Disable plugin-internal verification to avoid duplicated checks.
                    dns01Options.verifyPropagation = false;
                    break;
            }

            // Log dns-01 options with sensitive values redacted
            const safeOpts = { ...dns01Options };
            const sensitiveOptKeys = ['apiKey', 'apiPassword', 'key', 'secret', 'token', 'password', 'subdomain'];
            for (const k of sensitiveOptKeys) {
                if (safeOpts[k]) {
                    safeOpts[k] = '***REDACTED***';
                }
            }
            this.log.debug(`dns-01 options: ${JSON.stringify(safeOpts)}`);

            if (this.config.dns01Module === 'acme-dns-01-acmedns') {
                this.log.info(
                    'acme-dns uses per-collection credentials; missing credentials are created automatically during order processing',
                );
                // Keep a valid handler object for dns-01; real credentials are injected per collection during order processing.
                dns01Options.username = '__auto-register__';
                dns01Options.password = '__auto-register__';
                dns01Options.subdomain = '__auto-register__';
            }

            // Do this inside try... catch as the module is configurable
            let thisChallenge: ChallengeHandler | undefined;
            try {
                if (this.config.dns01Module === 'acme-dns-01-acmedns') {
                    thisChallenge = createAcmeDnsChallenge(dns01Options) as any;
                } else {
                    // Dynamic import - module name comes from config
                    const dns01Module = await import(this.config.dns01Module);
                    if (dns01Module.default) {
                        thisChallenge = dns01Module.default.create(dns01Options);
                    } else {
                        thisChallenge = dns01Module.create(dns01Options);
                    }
                }
            } catch (err) {
                this.log.error(
                    `Failed to load dns-01 challenge module '${this.config.dns01Module}': ${AcmeAdapter.getErrorMessage(err)}`,
                );
            }

            if (thisChallenge) {
                // Add extra properties
                // TODO: only add where needed?
                for (const [key, value] of Object.entries(dns01Props)) {
                    (thisChallenge as any)[key] = value;
                }
                // Adapter-side propagation verification runs before notifying the CA.
                // Keep propagationDelay at 0 to avoid extra ACME-client waiting.
                if (this.config.dns01Module === 'acme-dns-01-netcup') {
                    (thisChallenge as any).propagationDelay = 0;
                    this.log.debug('dns-01: Netcup verifyPropagation disabled; adapter handles propagation checks');
                    this.log.debug('dns-01: propagationDelay set to 0 for Netcup to avoid duplicate waiting');
                }

                // Some acme-dns-01-* modules expect init({ request }) to inject HTTP helper.
                if (typeof thisChallenge.init === 'function') {
                    try {
                        // eslint-disable-next-line @typescript-eslint/no-require-imports
                        const rootRequest = require('@root/request');
                        const request = promisify(rootRequest);
                        await thisChallenge.init({ request });
                    } catch (err) {
                        this.log.warn(
                            `dns-01 module '${this.config.dns01Module}' init() failed, trying without init: ${AcmeAdapter.getErrorMessage(err)}`,
                        );
                    }
                }

                this.challenges['dns-01'] = thisChallenge;
            }
        }
    }

    async initAcme(): Promise<void> {
        if (!this.acmeClient) {
            // Doesn't exist yet, actually do init
            const directoryUrl = this.config.useStaging
                ? acme.directory.letsencrypt.staging
                : acme.directory.letsencrypt.production;
            this.log.debug(`Using URL: ${directoryUrl}`);

            let accountNeedsSave = false;
            // Try and load a saved object
            const accountObject = await this.getObjectAsync(accountObjectId);
            if (accountObject) {
                this.log.debug('Loaded existing ACME account object');

                // Check if the saved account matches our current config
                const native = accountObject.native as any;
                const savedMaintainerEmail =
                    typeof native?.maintainerEmail === 'string' ? native.maintainerEmail.trim() : '';
                const configuredMaintainerEmail = `${this.config.maintainerEmail || ''}`.trim();

                if (savedMaintainerEmail && savedMaintainerEmail !== configuredMaintainerEmail) {
                    this.log.warn('Saved account does not match maintainer email, will recreate.');
                } else if (native?.useStaging !== this.config.useStaging) {
                    this.log.info(
                        `Saved account was created for ${native?.useStaging ? 'staging' : 'production'} LE, but current config uses ${this.config.useStaging ? 'staging' : 'production'} — will recreate.`,
                    );
                } else {
                    if (!savedMaintainerEmail && (native?.full || native?.keyEnc || native?.key)) {
                        this.log.debug(
                            'Saved account has no maintainerEmail metadata; reusing account and updating metadata.',
                        );
                    }
                    this.account = native as AcmeAccount;
                }
            }

            let accountKeyPem: string | Buffer | undefined;
            if (this.account.keyEnc) {
                this.log.debug('Decrypting persisted ACME account key...');
                try {
                    accountKeyPem = this.decrypt(this.account.keyEnc);
                } catch (err) {
                    this.log.error(`Failed to decrypt account key: ${AcmeAdapter.getErrorMessage(err)}`);
                    this.account = { full: null, key: null, keyEnc: null };
                }
            } else if (this.account.key) {
                this.log.debug('Converting legacy account key to PEM...');
                try {
                    accountKeyPem = crypto
                        .createPrivateKey({
                            key: this.account.key,
                            format: 'jwk',
                        })
                        .export({
                            type: 'pkcs8',
                            format: 'pem',
                        });
                    accountNeedsSave = true;
                } catch (err) {
                    this.log.error(`Failed to convert legacy account key: ${AcmeAdapter.getErrorMessage(err)}`);
                    this.account = { full: null, key: null };
                }
            }

            if (!accountKeyPem) {
                this.log.info('Generating new account key...');
                accountKeyPem = await acme.crypto.createPrivateKey();
                accountNeedsSave = true;
            }

            this.acmeClient = new acme.Client({
                directoryUrl,
                accountKey: accountKeyPem,
                accountUrl: this.account.full?.url,
            });

            // Always call createAccount. It's idempotent and ensures our client has the URL set.
            // If the account already exists (e.g. legacy acme.js), it will just return the existing data.
            this.log.info('Synchronizing ACME account...');
            const accountUrlBefore = this.account.full?.url;
            this.account.full = await this.acmeClient.createAccount({
                termsOfServiceAgreed: true,
                contact: [`mailto:${this.config.maintainerEmail}`],
            });
            this.log.debug(`Account synchronized: ${this.account.full.url}`);

            if (accountUrlBefore !== this.account.full.url) {
                accountNeedsSave = true;
            }

            if (accountNeedsSave) {
                this.log.info('Account state updated or first-time registration complete. Saving...');
                await this.extendObjectAsync(accountObjectId, {
                    native: {
                        full: this.account.full,
                        key: null,
                        keyEnc: this.encrypt(accountKeyPem.toString()),
                        maintainerEmail: this.config.maintainerEmail,
                        useStaging: this.config.useStaging,
                    },
                });
            }
        }
    }

    private async ensureHttp01ChallengeServerStarted(): Promise<void> {
        if (!this.config.http01Active) {
            return;
        }

        if (this.http01ServerReady) {
            return;
        }

        if (this.http01ServerInitPromise) {
            await this.http01ServerInitPromise;
            return;
        }

        const handler = this.challenges['http-01'];
        if (!handler) {
            throw new Error('HTTP-01 challenge handler is not initialized');
        }

        this.http01ServerInitPromise = (async () => {
            try {
                await handler.init({});
                this.http01ServerReady = true;
                this.log.info(`HTTP-01 challenge server started on ${this.config.bind}:${this.config.port}`);
            } catch (err) {
                this.http01ServerReady = false;
                const reason = AcmeAdapter.getErrorMessage(err);
                const hint =
                    this.config.http01StopConflictingAdapters === true
                        ? 'Choose a free HTTP-01 port or verify bind/address settings.'
                        : 'Choose a free HTTP-01 port or enable automatic stopping of conflicting adapters.';
                throw new Error(
                    `HTTP-01 challenge server could not start on ${this.config.bind}:${this.config.port}: ${reason}. ${hint}`,
                );
            }
        })();

        try {
            await this.http01ServerInitPromise;
        } finally {
            this.http01ServerInitPromise = null;
        }
    }

    private applyHttp01SelfCheckNetworkPreference(enable: boolean): () => void {
        if (!enable) {
            return () => {};
        }

        const restoreActions: Array<() => void> = [];

        try {
            const previousAutoSelectFamily = net.getDefaultAutoSelectFamily();
            net.setDefaultAutoSelectFamily(true);
            restoreActions.push(() => {
                net.setDefaultAutoSelectFamily(previousAutoSelectFamily);
            });
            this.log.debug('HTTP-01 self-check: enabled dual-stack auto family selection');
        } catch (err) {
            this.log.debug(
                `HTTP-01 self-check: unable to enable dual-stack auto family selection (${AcmeAdapter.getErrorMessage(err)})`,
            );
        }

        try {
            const previousOrder = dns.getDefaultResultOrder();
            dns.setDefaultResultOrder('ipv6first');
            restoreActions.push(() => {
                dns.setDefaultResultOrder(previousOrder);
            });
            this.log.debug('HTTP-01 self-check: using IPv6-first DNS resolution for local ACME verification');
        } catch (err) {
            this.log.debug(
                `HTTP-01 self-check: unable to apply IPv6-first DNS preference (${AcmeAdapter.getErrorMessage(err)})`,
            );
        }

        return () => {
            for (let i = restoreActions.length - 1; i >= 0; i--) {
                try {
                    restoreActions[i]();
                } catch {
                    // Ignore restore errors; these are best-effort runtime preferences.
                }
            }
        };
    }

    private applyHttp01SelfCheckFastFail(enable: boolean): () => void {
        if (!enable || !this.acmeClient) {
            return () => {};
        }

        const client: any = this.acmeClient;
        const originalVerifyChallenge = client.verifyChallenge;
        if (typeof originalVerifyChallenge !== 'function') {
            return () => {};
        }

        let verifyHttp01: ((authz: any, challenge: any, keyAuthorization: string) => Promise<any>) | undefined;
        let acmeAxios: any;
        try {
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            const verifyModule = require('acme-client/src/verify');
            verifyHttp01 = verifyModule?.['http-01'];
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            acmeAxios = require('acme-client/src/axios');
        } catch (err) {
            this.log.debug(`HTTP-01 self-check: fast-fail patch unavailable (${AcmeAdapter.getErrorMessage(err)})`);
            return () => {};
        }

        if (typeof verifyHttp01 !== 'function' || !acmeAxios?.defaults?.acmeSettings) {
            return () => {};
        }

        client.verifyChallenge = async (authz: any, challenge: any): Promise<any> => {
            if (!challenge || challenge.type !== 'http-01') {
                return originalVerifyChallenge.call(client, authz, challenge);
            }

            const domain =
                typeof authz?.identifier?.value === 'string' && authz.identifier.value
                    ? authz.identifier.value
                    : 'configured domain';
            const previousRetryMaxAttempts = acmeAxios.defaults.acmeSettings.retryMaxAttempts;
            try {
                // Fast-fail on HTTP-01 self-check to avoid long retry loops on deterministic proxy misrouting.
                this.log.debug(
                    `HTTP-01 self-check: verifying ${domain} against ${this.config.bind}:${this.config.port} with IPv6-first DNS and dual-stack auto family selection enabled`,
                );
                acmeAxios.defaults.acmeSettings.retryMaxAttempts = 0;
                const keyAuthorization = await this.acmeClient!.getChallengeKeyAuthorization(challenge);
                return await verifyHttp01(authz, challenge, keyAuthorization);
            } catch (err) {
                const message = AcmeAdapter.getErrorMessage(err);
                if (/Request failed with status code 502/.test(message)) {
                    this.log.debug(`HTTP-01 self-check debug: ${domain} returned 502 from the proxy/gateway.`);
                    throw new Error(
                        `Request failed with status code 502 (HTTP-01 self-check). Reverse proxy/router returned Bad Gateway for /.well-known/acme-challenge/. Verify forwarding from external port 80 to ${this.config.bind}:${this.config.port} for published DNS paths.`,
                    );
                }
                if (/Request failed with status code 404/.test(message)) {
                    this.log.debug(
                        `HTTP-01 self-check debug: ${domain} returned 404. The request reached an HTTP endpoint, but that path did not expose this adapter's challenge token.`,
                    );
                    throw new Error(
                        `Request failed with status code 404 (HTTP-01 self-check). The challenge URL for ${domain} is reachable but does not expose this adapter's challenge token. This usually means the domain's A/AAAA DNS records and/or reverse proxy routing point to a different host/backend than the HTTP-01 challenge endpoint.`,
                    );
                }
                if (/\(resp\.data \|\| ""\)\.replace is not a function/.test(message)) {
                    this.log.debug(`HTTP-01 self-check debug: ${domain} returned a non-text HTTP response.`);
                    throw new Error(
                        `HTTP-01 self-check received an unexpected non-text HTTP response for ${domain}. The challenge endpoint must return plain key-authorization text. This usually means /.well-known/acme-challenge/ is served by a different app/router/proxy target than ${this.config.bind}:${this.config.port}.`,
                    );
                }
                throw err;
            } finally {
                acmeAxios.defaults.acmeSettings.retryMaxAttempts = previousRetryMaxAttempts;
            }
        };

        this.log.debug('HTTP-01 self-check: fast-fail enabled for local verification');

        return () => {
            client.verifyChallenge = originalVerifyChallenge;
        };
    }

    private async isHttp01PortAvailable(): Promise<boolean> {
        return await new Promise(resolve => {
            const server = net.createServer();
            const onResolved = (available: boolean): void => {
                server.removeAllListeners('error');
                server.removeAllListeners('listening');
                resolve(available);
            };

            server.once('error', () => {
                try {
                    server.close();
                } catch {
                    // ignore close errors on failed bind attempts
                }
                onResolved(false);
            });

            server.once('listening', () => {
                server.close(() => onResolved(true));
            });

            try {
                server.listen(this.config.port, this.config.bind);
            } catch {
                onResolved(false);
            }
        });
    }

    private async waitForHttp01PortRelease(timeoutMs = portReleaseWaitTimeoutMs): Promise<boolean> {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            if (await this.isHttp01PortAvailable()) {
                return true;
            }
            await new Promise(resolve => setTimeout(resolve, portReleasePollIntervalMs));
        }
        return await this.isHttp01PortAvailable();
    }

    private async waitForAdapterStop(instanceId: string, timeoutMs = adapterStopWaitTimeoutMs): Promise<boolean> {
        const stateId = `${instanceId}.alive`;
        const deadline = Date.now() + timeoutMs;

        while (Date.now() < deadline) {
            const state = await this.getForeignStateAsync(stateId);
            if (state?.val !== true) {
                return true;
            }
            await new Promise(resolve => setTimeout(resolve, adapterStopPollIntervalMs));
        }

        const finalState = await this.getForeignStateAsync(stateId);
        return finalState?.val !== true;
    }

    async stopAdaptersOnSamePort(): Promise<void> {
        // TODO: Maybe this should be in some sort of utility so other adapters can 'grab' a port in use?
        // Stop conflicting adapters using our challenge server port only if we are going to need it and haven't already checked.
        if (this.config.http01Active && !this.donePortCheck) {
            if (this.config.http01StopConflictingAdapters !== true) {
                this.log.info(
                    'Automatic stopping of conflicting adapters on HTTP-01 port is disabled unless explicitly enabled. Existing services will remain running.',
                );
                this.donePortCheck = true;
                return;
            }

            // TODO: is there a better way than hardcoding this 'system.adapter.' part?
            const us = `system.adapter.${this.namespace}`;
            const host = this.host;
            const bind = this.config.bind;
            const port = this.config.port;
            this.log.debug(
                `Checking for adapter other than us (${us}) on our host/bind/port ${host}/${bind}/${port}...`,
            );
            const result = await this.getObjectViewAsync('system', 'instance', {
                startkey: 'system.adapter.',
                endkey: 'system.adapter.\u9999',
            });
            const instances = result.rows.map(row => row.value);
            const adapters = instances.filter(
                instance =>
                    // (this.log.debug(`id: ${instance._id}, enabled: ${instance.common.enabled}, host: ${instance.common.host}, port: ${instance.native.port}, bind: ${instance.native.bind}, `)) &&
                    instance &&
                    // Instance isn't ours
                    instance._id !== us &&
                    // Instance is enabled
                    instance.common.enabled &&
                    // Instance is on the same host as us
                    instance.common.host === host &&
                    instance.native &&
                    // Instance has a bind address
                    typeof instance.native.bind === 'string' &&
                    // Instance is on our bind address, or...
                    (instance.native.bind === bind ||
                        // We are using v4 address, and the instance is on all v4 interfaces, or...
                        (bind.includes('.') && instance.native.bind === '0.0.0.0') ||
                        // Instance is on v4 address, and we will listen on all, or...
                        (instance.native.bind.includes('.') && bind === '0.0.0.0') ||
                        // We are using v6 address, and the instance is on all v4 interfaces, or...
                        (bind.includes(':') && instance.native.bind === '::') ||
                        // Instance is on v6 address, and we will listen on all, or...
                        (instance.native.bind.includes(':') && bind === '::') ||
                        // TODO: These last two seem odd and maybe needs further investigation, but...
                        // Instance is on all v6 and we want all v4, or...
                        (instance.native.bind === '::' && bind === '0.0.0.0') ||
                        // Instance is on all v4, and we want all v6, or...
                        (instance.native.bind === '0.0.0.0' && bind === '::')) &&
                    // Port numbers are sometimes string and sometimes integer, so don't use '==='!
                    // Instance wants the same port as us, or...
                    (instance.native.port == port ||
                        // Instance is using LE still and it wants same port as us
                        (instance.native.secure &&
                            instance.native.leEnabled &&
                            instance.native.leUpdate &&
                            instance.native.leCheckPort == port)),
            );

            if (!adapters.length) {
                this.log.debug('No adapters found on same port, nothing to stop');
            } else {
                this.log.info(`Stopping adapter(s) on our host/bind/port ${host}/${bind}/${port}...`);
                this.stoppedAdapters = adapters.map(adapter => adapter._id);
                for (let i = 0; i < this.stoppedAdapters.length; i++) {
                    const config = await this.getForeignObjectAsync(this.stoppedAdapters[i]);
                    if (config) {
                        this.log.info(`Stopping ${config._id}`);
                        config.common.enabled = false;
                        await this.setForeignObjectAsync(config._id, config);
                    }
                }

                for (const adapterId of this.stoppedAdapters) {
                    const stopped = await this.waitForAdapterStop(adapterId);
                    if (!stopped) {
                        this.log.warn(
                            `Adapter ${adapterId} did not stop within ${adapterStopWaitTimeoutMs}ms. HTTP-01 port might still be in use.`,
                        );
                    }
                }

                const portReleased = await this.waitForHttp01PortRelease();
                if (!portReleased) {
                    this.log.warn(
                        `HTTP-01 port ${bind}:${port} still appears busy after waiting ${portReleaseWaitTimeoutMs}ms for conflicting adapters to stop.`,
                    );
                }
            }
            this.donePortCheck = true;
        }
    }

    async restoreAdaptersOnSamePort(): Promise<void> {
        if (!this.stoppedAdapters) {
            this.log.debug('No previously shutdown adapters to restart');
        } else {
            this.log.info('Starting adapter(s) previously shutdown...');
            for (let i = 0; i < this.stoppedAdapters.length; i++) {
                const config = await this.getForeignObjectAsync(this.stoppedAdapters[i]);
                if (config) {
                    this.log.info(`Starting ${config._id}`);
                    config.common.enabled = true;
                    await this.setForeignObjectAsync(config._id, config);
                }
            }
            this.stoppedAdapters = null;
            this.donePortCheck = false;
        }
    }

    /**
     * Compare two arrays for matching content regardless of order.
     * Correctly handles duplicates by sorting both arrays before comparison.
     */
    private arraysMatch(arr1: unknown, arr2: unknown): boolean {
        if (!Array.isArray(arr1) || !Array.isArray(arr2)) {
            // How can they be matching arrays if not even arrays?
            return false;
        }

        if (arr1 === arr2) {
            // Some dummy passed in the same objects so of course they are the same!
            return true;
        }

        if (arr1.length !== arr2.length) {
            // Cannot be the same if the length doesn't match.
            return false;
        }

        const sorted1 = [...arr1].sort();
        const sorted2 = [...arr2].sort();
        return sorted1.every((val, idx) => val === sorted2[idx]);
    }

    private getDnsChallengeCacheKey(authz: any, challenge: any): string {
        return `${authz?.identifier?.value || ''}|${challenge?.token || ''}`;
    }

    private async getDnsZones(handler: any, dnsHost: string): Promise<string[]> {
        if (!handler || typeof handler.zones !== 'function') {
            return [];
        }

        try {
            const zones = await handler.zones({ dnsHosts: [dnsHost] });
            if (!Array.isArray(zones)) {
                return [];
            }
            return zones.filter(zone => typeof zone === 'string');
        } catch (err) {
            this.log.debug(`dns-01 zones() lookup failed: ${AcmeAdapter.getErrorMessage(err)}`);
            return [];
        }
    }

    private async buildDnsChallengePayload(
        handler: any,
        authz: any,
        challenge: any,
        keyAuthorization: string,
    ): Promise<any> {
        const normalizedDnsAlias = normalizeDnsAlias(this.config.dns01Alias);
        const identifierValue = normalizedDnsAlias || authz.identifier.value;
        const dnsHost = `_acme-challenge.${identifierValue}`;

        if (normalizedDnsAlias) {
            this.log.info(`Using DNS Alias: ${dnsHost} instead of _acme-challenge.${authz.identifier.value}`);
        }

        const zones = await this.getDnsZones(handler, dnsHost);
        return buildDnsChallengeData({
            identifierValue,
            identifierType: authz.identifier.type,
            wildcard: authz.wildcard,
            token: challenge.token,
            keyAuthorization,
            zones,
        });
    }

    private async saveCollectionAcmeDnsCredentials(credentials: AcmeDnsCollectionCredentials): Promise<void> {
        const instanceObjectId = `system.adapter.${this.namespace}`;
        const instanceObj = await this.getForeignObjectAsync(instanceObjectId);
        if (!instanceObj?.native) {
            throw new Error(`Unable to update adapter config object: ${instanceObjectId}`);
        }

        const existing = Array.isArray(instanceObj.native.dns01CollectionCredentials)
            ? [...instanceObj.native.dns01CollectionCredentials]
            : [];
        const idx = existing.findIndex((entry: any) => entry?.collectionId === credentials.collectionId);
        if (idx >= 0) {
            existing[idx] = credentials;
        } else {
            existing.push(credentials);
        }

        instanceObj.native.dns01CollectionCredentials = existing;
        await this.setForeignObjectAsync(instanceObjectId, instanceObj);

        this.config.dns01CollectionCredentials = existing as AcmeDnsCollectionCredentials[];
    }

    private async autoCreateCollectionAcmeDnsCredentials(
        collectionId: string,
        preferredBaseUrl?: string,
    ): Promise<AcmeDnsCollectionCredentials | null> {
        if (this.acmeDnsAutoRegisterBlocked) {
            this.log.warn(
                `Collection ${collectionId}: automatic acme-dns registration is temporarily disabled for this run due to previous registration failure`,
            );
            return null;
        }

        const baseUrl = `${preferredBaseUrl || this.config.dns01ObaseUrl || ''}`.trim();

        try {
            const registration = await registerAcmeDnsAccount(baseUrl || undefined);
            const credentials: AcmeDnsCollectionCredentials = {
                collectionId,
                username: registration.username,
                password: registration.password,
                subdomain: registration.subdomain,
                baseUrl,
                fullDomain: registration.fullDomain,
            };

            await this.saveCollectionAcmeDnsCredentials(credentials);
            this.log.info(`Collection ${collectionId}: acme-dns account created automatically`);
            if (registration.fullDomain) {
                this.log.info(
                    `Collection ${collectionId}: configure CNAME target to ${registration.fullDomain} for DNS-01 delegation`,
                );
            }
            return credentials;
        } catch (err) {
            this.acmeDnsAutoRegisterBlocked = true;
            this.log.error(
                `Collection ${collectionId}: failed to auto-create acme-dns account (${AcmeAdapter.getErrorMessage(err)})`,
            );
            return null;
        }
    }

    private getCollectionAcmeDnsCredentials(collectionId: string): AcmeDnsCollectionCredentials | null {
        const credentials = this.config.dns01CollectionCredentials;
        if (!Array.isArray(credentials) || !credentials.length) {
            return null;
        }

        const credential = credentials.find(entry => entry?.collectionId === collectionId);
        if (!credential) {
            return null;
        }

        return {
            collectionId,
            username: `${credential.username || ''}`.trim(),
            password: `${credential.password || ''}`.trim(),
            subdomain: `${credential.subdomain || ''}`.trim(),
            baseUrl: `${credential.baseUrl || ''}`.trim(),
            fullDomain:
                typeof credential.fullDomain === 'string' && credential.fullDomain.trim()
                    ? credential.fullDomain.trim()
                    : undefined,
        };
    }

    private getDeterministicConfigurationErrors(): string[] {
        const errors: string[] = [];
        if (!this.config.dns01Active || this.config.dns01Module !== 'acme-dns-01-acmedns') {
            return errors;
        }

        const collections = Array.isArray(this.config.collections) ? this.config.collections : [];
        const knownCollectionIds = new Set(
            collections
                .map(collection => `${collection?.id || ''}`.trim().toLowerCase())
                .filter(collectionId => !!collectionId),
        );

        const credentialRows = Array.isArray(this.config.dns01CollectionCredentials)
            ? this.config.dns01CollectionCredentials
            : [];

        for (let index = 0; index < credentialRows.length; index += 1) {
            const row = credentialRows[index];
            const rowLabel = `acme-dns credentials row ${index + 1}`;

            const collectionId = `${row?.collectionId || ''}`.trim();
            const baseUrl = `${row?.baseUrl || ''}`.trim();

            if (collectionId && !knownCollectionIds.has(collectionId.toLowerCase())) {
                errors.push(`${rowLabel}: collection ID "${collectionId}" does not exist in collections table`);
            }

            if (baseUrl) {
                try {
                    // Validate deterministic URL format upfront to fail fast.
                    const parsedUrl = new URL(baseUrl);
                    if (!parsedUrl.hostname) {
                        errors.push(`${rowLabel}: base URL "${baseUrl}" has no hostname`);
                    }
                } catch {
                    errors.push(`${rowLabel}: base URL "${baseUrl}" is invalid`);
                }
            }
        }

        return errors;
    }

    private normalizeDnsName(name: string): string {
        return name.trim().replace(/\.+$/, '').toLowerCase();
    }

    private isResolverUnreachableError(err: unknown): boolean {
        const code = (err as any)?.code;
        return (
            typeof code === 'string' &&
            ['ETIMEOUT', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNREFUSED', 'ECONNRESET', 'EREFUSED'].includes(
                code,
            )
        );
    }

    private isDnsNoRecordError(err: unknown): boolean {
        const code = (err as any)?.code;
        return typeof code === 'string' && ['ENODATA', 'ENOTFOUND', 'NXDOMAIN', 'NOTFOUND'].includes(code);
    }

    private async precheckHttp01DnsRecords(domains: string[]): Promise<void> {
        if (!this.config.http01Active) {
            return;
        }

        const http01Domains = Array.from(
            new Set(
                domains
                    .filter(domain => !domain.startsWith('*.'))
                    .map(domain => this.normalizeDnsName(domain))
                    .filter(domain => !!domain),
            ),
        );
        if (!http01Domains.length) {
            return;
        }

        const missingPublicRecords: string[] = [];

        for (const domain of http01Domains) {
            const [ipv4Result, ipv6Result] = await Promise.allSettled([
                dnsPromises.resolve4(domain),
                dnsPromises.resolve6(domain),
            ]);

            const hasA = ipv4Result.status === 'fulfilled' && ipv4Result.value.length > 0;
            const hasAAAA = ipv6Result.status === 'fulfilled' && ipv6Result.value.length > 0;

            if (hasA || hasAAAA) {
                continue;
            }

            const aNoRecord = ipv4Result.status === 'rejected' && this.isDnsNoRecordError(ipv4Result.reason);
            const aaaaNoRecord = ipv6Result.status === 'rejected' && this.isDnsNoRecordError(ipv6Result.reason);

            if (aNoRecord && aaaaNoRecord) {
                missingPublicRecords.push(domain);
                continue;
            }

            const aReason = ipv4Result.status === 'rejected' ? AcmeAdapter.getErrorMessage(ipv4Result.reason) : 'none';
            const aaaaReason =
                ipv6Result.status === 'rejected' ? AcmeAdapter.getErrorMessage(ipv6Result.reason) : 'none';
            this.log.debug(
                `HTTP-01 DNS preflight: ${domain} has no resolvable A/AAAA records via local resolver (A error: ${aReason}, AAAA error: ${aaaaReason}). Continuing because this may be a temporary resolver/network issue.`,
            );
        }

        if (missingPublicRecords.length > 0) {
            throw new Error(
                `HTTP-01 DNS preflight failed: no public A/AAAA record found for ${missingPublicRecords.join(', ')}. Configure at least one A or AAAA record (or disable HTTP-01 for this collection). The A/AAAA entry is either missing or not yet visible on tested resolvers.`,
            );
        }
    }

    private async resolveNsServerAddresses(nsHost: string): Promise<string[]> {
        const addresses = new Set<string>();

        try {
            const ipv4 = await dnsPromises.resolve4(nsHost);
            for (const ip of ipv4) {
                addresses.add(ip);
            }
        } catch (err) {
            this.log.debug(`DNS A lookup failed for nameserver ${nsHost}: ${AcmeAdapter.getErrorMessage(err)}`);
        }

        try {
            const ipv6 = await dnsPromises.resolve6(nsHost);
            for (const ip of ipv6) {
                addresses.add(ip);
            }
        } catch (err) {
            this.log.debug(`DNS AAAA lookup failed for nameserver ${nsHost}: ${AcmeAdapter.getErrorMessage(err)}`);
        }

        return Array.from(addresses);
    }

    private async getAuthoritativeResolvers(
        recordName: string,
    ): Promise<Array<{ name: string; resolver: dnsPromises.Resolver }>> {
        const normalizedName = this.normalizeDnsName(recordName);
        const labels = normalizedName.split('.');
        const nsHosts = new Set<string>();

        for (let i = 0; i < labels.length - 1; i += 1) {
            const zoneCandidate = labels.slice(i).join('.');
            try {
                const nsRecords = await dnsPromises.resolveNs(zoneCandidate);
                if (nsRecords.length > 0) {
                    for (const ns of nsRecords) {
                        nsHosts.add(this.normalizeDnsName(ns));
                    }
                    break;
                }
            } catch (err) {
                this.log.debug(`DNS NS lookup failed for ${zoneCandidate}: ${AcmeAdapter.getErrorMessage(err)}`);
            }
        }

        const authoritativeResolvers: Array<{ name: string; resolver: dnsPromises.Resolver }> = [];
        for (const nsHost of nsHosts) {
            const addresses = await this.resolveNsServerAddresses(nsHost);
            if (!addresses.length) {
                this.log.debug(`No IP addresses resolved for nameserver ${nsHost}.`);
                continue;
            }

            for (const address of addresses) {
                const resolver = new dnsPromises.Resolver();
                resolver.setServers([address]);
                authoritativeResolvers.push({
                    name: `${nsHost} (${address})`,
                    resolver,
                });
            }
        }

        return authoritativeResolvers;
    }

    private async resolveTxtViaResolver(
        resolver: dnsPromises.Resolver,
        recordName: string,
    ): Promise<{ values: string[]; reachable: boolean }> {
        try {
            const cnameRecords = await resolver.resolveCname(recordName);
            if (cnameRecords.length > 0) {
                return this.resolveTxtViaResolver(resolver, cnameRecords[0]);
            }
        } catch (err) {
            this.log.debug(`DNS CNAME lookup failed for ${recordName}: ${AcmeAdapter.getErrorMessage(err)}`);
        }

        try {
            const txtRecords = await resolver.resolveTxt(recordName);
            return {
                values: txtRecords.flat().filter(entry => typeof entry === 'string'),
                reachable: true,
            };
        } catch (err) {
            this.log.debug(`DNS TXT lookup failed for ${recordName}: ${AcmeAdapter.getErrorMessage(err)}`);
            return {
                values: [],
                reachable: !this.isResolverUnreachableError(err),
            };
        }
    }

    private async resolveCnameViaResolver(
        resolver: dnsPromises.Resolver,
        recordName: string,
    ): Promise<{ values: string[]; reachable: boolean }> {
        try {
            const cnameRecords = await resolver.resolveCname(recordName);
            return {
                values: cnameRecords,
                reachable: true,
            };
        } catch (err) {
            this.log.debug(`DNS CNAME lookup failed for ${recordName}: ${AcmeAdapter.getErrorMessage(err)}`);
            return {
                values: [],
                reachable: !this.isResolverUnreachableError(err),
            };
        }
    }

    private async waitForDnsPropagation(recordName: string, expectedValue: string): Promise<void> {
        const waitForMs = 5000;
        const maxAttempts = 240;
        const systemResolver = new dnsPromises.Resolver();
        const authoritativeResolvers = await this.getAuthoritativeResolvers(recordName);

        if (authoritativeResolvers.length > 0) {
            this.log.debug(
                `Using authoritative DNS resolvers for propagation check of ${recordName}: ${authoritativeResolvers
                    .map(entry => entry.name)
                    .join(', ')}`,
            );
        } else {
            this.log.warn(
                `No authoritative DNS resolver could be determined for ${recordName}. Falling back to system resolver checks.`,
            );
        }

        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            if (authoritativeResolvers.length > 0) {
                const checks = await Promise.all(
                    authoritativeResolvers.map(async ({ name, resolver }) => {
                        const result = await this.resolveTxtViaResolver(resolver, recordName);
                        return {
                            name,
                            reachable: result.reachable,
                            ok: result.values.includes(expectedValue),
                        };
                    }),
                );

                const reachableChecks = checks.filter(check => check.reachable);
                const okResolvers = reachableChecks.filter(check => check.ok).map(check => check.name);

                if (reachableChecks.length > 0 && okResolvers.length === reachableChecks.length) {
                    this.log.info(
                        `DNS propagation verified for ${recordName} on all reachable authoritative resolvers (${okResolvers.join(', ')}).`,
                    );
                    return;
                }

                if (reachableChecks.length > 0) {
                    this.log.debug(
                        `DNS propagation not yet complete for ${recordName} on authoritative resolvers. Visible on ${okResolvers.length}/${reachableChecks.length} reachable authoritative resolvers. Retrying in ${waitForMs}ms. (Attempt ${attempt} / ${maxAttempts})`,
                    );
                } else {
                    const fallback = await this.resolveTxtViaResolver(systemResolver, recordName);
                    if (fallback.values.includes(expectedValue)) {
                        this.log.info(
                            `DNS propagation verified for ${recordName} via system resolver fallback (authoritative resolvers not reachable).`,
                        );
                        return;
                    }

                    this.log.debug(
                        `Authoritative resolvers for ${recordName} were not reachable and system resolver fallback does not see TXT yet. Retrying in ${waitForMs}ms. (Attempt ${attempt} / ${maxAttempts})`,
                    );
                }
            } else {
                const fallback = await this.resolveTxtViaResolver(systemResolver, recordName);
                if (fallback.values.includes(expectedValue)) {
                    this.log.info(`DNS propagation verified for ${recordName} via system resolver.`);
                    return;
                }

                this.log.debug(
                    `DNS propagation not yet complete for ${recordName} via system resolver. Retrying in ${waitForMs}ms. (Attempt ${attempt} / ${maxAttempts})`,
                );
            }

            if (attempt < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, waitForMs));
            }
        }

        throw new Error(`Timed out waiting for DNS propagation of ${recordName}`);
    }

    private async waitForDnsAliasDelegation(sourceRecordName: string, targetRecordName: string): Promise<void> {
        const waitForMs = 5000;
        const maxAttempts = 3;
        const normalizedTarget = this.normalizeDnsName(targetRecordName);
        const systemResolver = new dnsPromises.Resolver();
        const authoritativeResolvers = await this.getAuthoritativeResolvers(sourceRecordName);

        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            if (authoritativeResolvers.length > 0) {
                const checks = await Promise.all(
                    authoritativeResolvers.map(async ({ name, resolver }) => {
                        const result = await this.resolveCnameViaResolver(resolver, sourceRecordName);
                        const ok = result.values.some(record => this.normalizeDnsName(record) === normalizedTarget);
                        return {
                            name,
                            reachable: result.reachable,
                            ok,
                        };
                    }),
                );

                const reachableChecks = checks.filter(check => check.reachable);
                const ready = reachableChecks.find(check => check.ok);
                if (ready && reachableChecks.every(check => check.ok)) {
                    this.log.info(
                        `DNS alias delegation verified for ${sourceRecordName} -> ${targetRecordName} on all reachable authoritative resolvers.`,
                    );
                    return;
                }

                if (reachableChecks.length === 0) {
                    const fallback = await this.resolveCnameViaResolver(systemResolver, sourceRecordName);
                    if (fallback.values.some(record => this.normalizeDnsName(record) === normalizedTarget)) {
                        this.log.info(
                            `DNS alias delegation verified for ${sourceRecordName} -> ${targetRecordName} via system resolver fallback (authoritative resolvers not reachable).`,
                        );
                        return;
                    }
                }
            } else {
                const fallback = await this.resolveCnameViaResolver(systemResolver, sourceRecordName);
                if (fallback.values.some(record => this.normalizeDnsName(record) === normalizedTarget)) {
                    this.log.info(
                        `DNS alias delegation verified for ${sourceRecordName} -> ${targetRecordName} via system resolver.`,
                    );
                    return;
                }
            }

            this.log.debug(
                `DNS alias delegation not yet visible for ${sourceRecordName} -> ${targetRecordName}. Retrying in ${waitForMs}ms. (Attempt ${attempt} / ${maxAttempts})`,
            );

            if (attempt < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, waitForMs));
            }
        }

        const message =
            `Alias delegation not visible: ${sourceRecordName} -> ${targetRecordName}. ` +
            'The CNAME entry is either missing or not yet visible on tested resolvers. ' +
            'If you have just created or updated this DNS record, wait a moment for propagation and retry the adapter run.';
        throw new Error(message);
    }

    private getAcmeDnsDelegationTargetForCollection(collectionId: string): string | null {
        const credential = this.getCollectionAcmeDnsCredentials(collectionId);
        if (credential?.fullDomain) {
            return this.normalizeDnsName(credential.fullDomain);
        }

        const token = `${credential?.subdomain || ''}`.trim();
        if (!token) {
            return null;
        }

        const configuredBaseUrl = (credential?.baseUrl || `${this.config.dns01ObaseUrl || ''}`).trim();
        const baseUrl = configuredBaseUrl || 'https://auth.acme-dns.io';

        try {
            const host = new URL(baseUrl).hostname;
            if (!host) {
                return null;
            }
            return this.normalizeDnsName(`${token}.${host}`);
        } catch {
            return null;
        }
    }

    private async ensureAcmeDnsDelegationVisible(collectionId: string, authz: any): Promise<string | null> {
        const identifierValue = authz?.identifier?.value;
        if (!identifierValue || typeof identifierValue !== 'string') {
            return null;
        }

        const expectedTarget = this.getAcmeDnsDelegationTargetForCollection(collectionId);
        if (!expectedTarget) {
            this.log.debug(
                `Collection ${collectionId}: acme-dns delegation target could not be determined from credentials/config. Skipping explicit CNAME precheck.`,
            );
            return null;
        }

        const sourceDnsHost = `_acme-challenge.${identifierValue}`;
        const cacheKey = `${sourceDnsHost}->${expectedTarget}`;
        if (this.acmeDnsCnameCheckedHosts.has(cacheKey)) {
            return expectedTarget;
        }
        this.acmeDnsCnameCheckedHosts.add(cacheKey);

        this.log.info(
            `Checking DNS alias delegation of ${sourceDnsHost} to ${expectedTarget} before TXT propagation checks.`,
        );
        await this.waitForDnsAliasDelegation(sourceDnsHost, expectedTarget);
        return expectedTarget;
    }

    private async activateCollectionDnsCredentials(collectionId: string): Promise<() => void> {
        this.acmeDnsBlockedCollectionReasons.delete(collectionId);

        if (!this.config.dns01Active || this.config.dns01Module !== 'acme-dns-01-acmedns') {
            return () => undefined;
        }

        let credentials = this.getCollectionAcmeDnsCredentials(collectionId);
        let autoRegistered = false;
        if (!credentials) {
            this.log.info(
                `Collection ${collectionId}: no acme-dns credentials configured, trying automatic account registration`,
            );
            credentials = await this.autoCreateCollectionAcmeDnsCredentials(collectionId);
            autoRegistered = !!credentials;
        }

        if (credentials && !credentials.username && !credentials.password && !credentials.subdomain) {
            this.log.info(
                `Collection ${collectionId}: acme-dns credentials row has no credentials, trying automatic account registration`,
            );
            credentials = await this.autoCreateCollectionAcmeDnsCredentials(collectionId, credentials.baseUrl);
            autoRegistered = !!credentials;
        }

        if (!credentials) {
            this.acmeDnsBlockedCollectionReasons.set(
                collectionId,
                'acme-dns credentials could not be determined (automatic registration failed or was blocked)',
            );
            return () => undefined;
        }

        const dns01Options: Record<string, any> = {};
        for (const [key, value] of Object.entries(this.config)) {
            if (key.startsWith('dns01O')) {
                dns01Options[key.slice(6)] = value;
            }
        }

        dns01Options.username = credentials.username;
        dns01Options.password = credentials.password;
        dns01Options.subdomain = credentials.subdomain;
        if (credentials.baseUrl) {
            dns01Options.baseUrl = credentials.baseUrl;
        }

        const previousHandler = this.challenges['dns-01'];
        if (!previousHandler) {
            return () => undefined;
        }

        const overrideHandler = createAcmeDnsChallenge(dns01Options) as unknown as ChallengeHandler;
        if (typeof overrideHandler.init === 'function') {
            try {
                // eslint-disable-next-line @typescript-eslint/no-require-imports
                const rootRequest = require('@root/request');
                const request = promisify(rootRequest);
                await overrideHandler.init({ request });
            } catch (err) {
                this.log.warn(
                    `Collection ${collectionId}: acme-dns credentials init() failed, continuing anyway: ${AcmeAdapter.getErrorMessage(err)}`,
                );
            }
        }

        this.challenges['dns-01'] = overrideHandler;
        if (autoRegistered) {
            this.acmeDnsAutoRegisteredCollections.add(collectionId);
        }
        this.log.info(`Collection ${collectionId}: using dedicated acme-dns collection credentials`);

        return () => {
            this.challenges['dns-01'] = previousHandler;
            try {
                overrideHandler.shutdown();
            } catch (err) {
                this.log.debug(
                    `Collection ${collectionId}: acme-dns credentials shutdown failed: ${AcmeAdapter.getErrorMessage(err)}`,
                );
            }
        };
    }

    async generateCollection(collection: CollectionConfig): Promise<void> {
        this.log.debug(`Collection: ${JSON.stringify(collection)}`);

        // Create domains now as will be used to test any existing collection.
        const domains = collection.commonName
            .split(',')
            .map(d => d.trim())
            .filter(n => n);
        if (collection.altNames) {
            domains.push(
                ...collection.altNames
                    .replace(/\s/g, '')
                    .split(',')
                    .filter(n => n),
            );
        }
        this.log.debug(`domains: ${JSON.stringify(domains)}`);
        const wildcardDomains = domains.filter(domain => domain.startsWith('*.'));

        // Get an existing collection & see if it needs renewing
        let create = false;
        const existingCollection = (await this.certManager?.getCollection(collection.id)) as
            | CertificateCollection
            | null
            | undefined;
        if (!existingCollection) {
            this.log.info(`Collection ${collection.id} does not exist - will create`);
            create = true;
        } else {
            this.log.debug(`Existing: ${collection.id}: ${JSON.stringify(existingCollection)}`);

            try {
                // Decode certificate to check not due for renewal and parts match what is configured.
                const crt = x509.parseCert(existingCollection.cert.toString());
                this.log.debug(`Existing cert: ${JSON.stringify(crt)}`);

                if (Date.now() > Date.parse(crt.notAfter) - renewWindow) {
                    this.log.info(`Collection ${collection.id} expiring soon - will renew`);
                    create = true;
                } else if (collection.commonName !== crt.subject.commonName) {
                    this.log.info(`Collection ${collection.id} common name does not match - will renew`);
                    create = true;
                } else if (!this.arraysMatch(domains, crt.altNames)) {
                    this.log.info(`Collection ${collection.id} alt names do not match - will renew`);
                    create = true;
                } else if (this.config.useStaging !== existingCollection.staging) {
                    this.log.info(`Collection ${collection.id} staging flags do not match - will renew`);
                    create = true;
                } else {
                    this.log.debug(`Collection ${collection.id} certificate already looks good`);
                }
            } catch (err) {
                this.log.error(
                    `Collection ${collection.id} exists but looks invalid (${AcmeAdapter.getErrorMessage(err)}) - will renew`,
                );
                create = true;
            }
        }

        if (create) {
            if (wildcardDomains.length > 0 && this.config.http01Active && !this.config.dns01Active) {
                this.log.warn(
                    `Collection ${collection.id} contains wildcard domain(s) (${wildcardDomains.join(', ')}), but DNS-01 is disabled. Wildcard certificates require DNS-01. Enable DNS-01 and retry.`,
                );
                return;
            }

            if (
                this.config.dns01Active &&
                ['acme-dns-01-acmedns', 'acme-dns-01-duckdns'].includes(this.config.dns01Module)
            ) {
                const dns01Domains = this.config.http01Active ? wildcardDomains : domains;
                const uniqueDns01Domains = Array.from(new Set(dns01Domains.map(domain => domain.toLowerCase())));

                if (uniqueDns01Domains.length > 1) {
                    this.log.warn(
                        `Collection ${collection.id} contains multiple DNS-01 domains (${uniqueDns01Domains.join(', ')}) while provider ${this.config.dns01Module} supports only one TXT record per account. Split this into one domain per collection and retry.`,
                    );
                    return;
                }
            }

            // stopAdaptersOnSamePort can be called many times as has its own checks to prevent unnecessary action.
            await this.stopAdaptersOnSamePort();

            if (!this.acmeClient || !this.account.full) {
                this.log.error('ACME client not initialized');
                return;
            }

            const restoreDnsOverride = await this.activateCollectionDnsCredentials(collection.id);
            const blockedReason = this.acmeDnsBlockedCollectionReasons.get(collection.id);
            if (blockedReason) {
                this.log.warn(`Collection ${collection.id}: skipping certificate order because ${blockedReason}.`);
                restoreDnsOverride();
                return;
            }

            if (this.acmeDnsAutoRegisteredCollections.has(collection.id)) {
                const delegationTarget = this.getAcmeDnsDelegationTargetForCollection(collection.id);
                if (delegationTarget) {
                    this.log.info(
                        `Collection ${collection.id}: automatic acme-dns registration completed. Configure _acme-challenge CNAME to ${delegationTarget} and start the adapter again.`,
                    );
                } else {
                    this.log.info(
                        `Collection ${collection.id}: automatic acme-dns registration completed. Configure _acme-challenge CNAME using the generated acme-dns target and start the adapter again.`,
                    );
                }
                this.log.info(
                    `Collection ${collection.id}: skipping certificate order in this run so DNS delegation can be configured first.`,
                );
                restoreDnsOverride();
                return;
            }

            let cert: string | undefined;
            try {
                const hasNonWildcardDomains = domains.some(domain => !domain.startsWith('*.'));
                if (this.config.http01Active && hasNonWildcardDomains) {
                    this.log.info(
                        `HTTP-01 preflight: validating listener availability on ${this.config.bind}:${this.config.port} before placing order.`,
                    );
                    await this.ensureHttp01ChallengeServerStarted();
                    this.log.info('HTTP-01 preflight: validating public DNS A/AAAA records for challenge domains.');
                    await this.precheckHttp01DnsRecords(domains);
                }

                // Generate CSR
                const [serverKey, csr] = await acme.crypto.createCsr({
                    commonName: collection.commonName.split(',')[0].trim(),
                    altNames: domains,
                });

                // Create the order first to check its status.
                // This prevents 403 errors if the order is already 'valid' on the ACME server.
                this.log.debug(`Placing order for ${domains.join(', ')}...`);
                let order = await this.acmeClient.createOrder({
                    identifiers: domains.map(d => ({ type: 'dns', value: d })),
                });

                if (order.status === 'processing') {
                    this.log.info(`Order for ${domains.join(', ')} is currently processing. Waiting...`);
                    order = await this.acmeClient.waitForValidStatus(order);
                }

                if (order.status === 'valid') {
                    this.log.info(
                        `Order for ${domains.join(', ')} is already valid. Skipping challenges and redeeming certificate...`,
                    );
                    cert = (await this.acmeClient.getCertificate(order)).toString();
                } else {
                    // Use auto() to handle the pending challenge/finalization flow.
                    const challengePriority: string[] = [];
                    if (this.config.http01Active) {
                        challengePriority.push('http-01');
                    }
                    if (this.config.dns01Active) {
                        challengePriority.push('dns-01');
                    }

                    const aliasDnsOnlyFlow =
                        !!this.config.dns01Alias && this.config.dns01Active && !this.config.http01Active;
                    if (aliasDnsOnlyFlow) {
                        this.log.info(
                            'DNS-01 alias configured in DNS-only mode: waiting for CNAME delegation and DNS propagation before continuing the ACME flow.',
                        );
                    }

                    const hasHttp01Targets = this.config.http01Active && hasNonWildcardDomains;
                    const restoreHttp01FastFail = this.applyHttp01SelfCheckFastFail(hasHttp01Targets);
                    const restoreHttp01NetworkPreference = this.applyHttp01SelfCheckNetworkPreference(hasHttp01Targets);

                    try {
                        cert = (
                            await this.acmeClient.auto({
                                csr,
                                email: this.config.maintainerEmail,
                                termsOfServiceAgreed: true,
                                skipChallengeVerification: aliasDnsOnlyFlow,
                                challengePriority,
                                challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                                    this.log.debug(
                                        `Satisfying challenge ${challenge.type} for ${authz.identifier.value}`,
                                    );
                                    const handler = this.challenges[challenge.type];
                                    if (!handler) {
                                        throw new Error(`No handler for challenge type ${challenge.type}`);
                                    }

                                    if (challenge.type === 'dns-01') {
                                        const challengeData = await this.buildDnsChallengePayload(
                                            handler,
                                            authz,
                                            challenge,
                                            keyAuthorization,
                                        );
                                        this.dnsChallengeCache[this.getDnsChallengeCacheKey(authz, challenge)] =
                                            challengeData;
                                        await handler.set(challengeData);

                                        const sourceDnsHost = `_acme-challenge.${authz.identifier.value}`;
                                        const challengeDnsHost =
                                            challengeData?.challenge?.dnsHost ||
                                            challengeData?.dnsHost ||
                                            sourceDnsHost;
                                        let propagationDnsHost = challengeDnsHost;
                                        let delegationAlreadyVerified = false;

                                        if (
                                            this.config.dns01Module === 'acme-dns-01-acmedns' &&
                                            challengeDnsHost === sourceDnsHost
                                        ) {
                                            const delegatedDnsHost = await this.ensureAcmeDnsDelegationVisible(
                                                collection.id,
                                                authz,
                                            );
                                            if (delegatedDnsHost) {
                                                propagationDnsHost = delegatedDnsHost;
                                                delegationAlreadyVerified = true;
                                            }
                                        }

                                        const expectedDnsAuthorization = challengeData?.challenge?.dnsAuthorization;
                                        if (!expectedDnsAuthorization) {
                                            throw new Error(
                                                `Missing dnsAuthorization in challenge payload for ${challengeDnsHost}`,
                                            );
                                        }

                                        if (propagationDnsHost !== sourceDnsHost) {
                                            if (!delegationAlreadyVerified) {
                                                this.log.info(
                                                    `Waiting for DNS alias delegation of ${sourceDnsHost} to ${propagationDnsHost} before notifying the CA.`,
                                                );
                                                await this.waitForDnsAliasDelegation(sourceDnsHost, propagationDnsHost);
                                            }
                                            this.log.info(
                                                `Waiting for DNS propagation of ${propagationDnsHost} on authoritative resolvers (with system fallback) before notifying the CA.`,
                                            );
                                        } else {
                                            this.log.info(
                                                `DNS-01 without alias: waiting for DNS propagation of ${propagationDnsHost} on authoritative resolvers (with system fallback) before notifying the CA.`,
                                            );
                                        }

                                        await this.waitForDnsPropagation(propagationDnsHost, expectedDnsAuthorization);
                                    } else {
                                        await this.ensureHttp01ChallengeServerStarted();

                                        const challengeData: any = {
                                            identifier: { ...authz.identifier },
                                            token: challenge.token,
                                            keyAuthorization,
                                            challenge: {
                                                token: challenge.token,
                                                keyAuthorization,
                                            },
                                        };
                                        await handler.set(challengeData);
                                    }
                                },
                                challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                                    this.log.debug(
                                        `Removing challenge ${challenge.type} for ${authz.identifier.value}`,
                                    );
                                    const handler = this.challenges[challenge.type];
                                    if (handler) {
                                        if (challenge.type === 'dns-01') {
                                            const cacheKey = this.getDnsChallengeCacheKey(authz, challenge);
                                            const cached = this.dnsChallengeCache[cacheKey];
                                            const removeData =
                                                cached ||
                                                (await this.buildDnsChallengePayload(
                                                    handler,
                                                    authz,
                                                    challenge,
                                                    keyAuthorization,
                                                ));
                                            await handler.remove(removeData);
                                            delete this.dnsChallengeCache[cacheKey];
                                        } else {
                                            const removeData: any = {
                                                identifier: { ...authz.identifier },
                                                token: challenge.token,
                                                challenge: {
                                                    token: challenge.token,
                                                    keyAuthorization,
                                                },
                                            };
                                            await handler.remove(removeData);
                                        }
                                    }
                                },
                            })
                        ).toString();
                    } finally {
                        restoreHttp01FastFail();
                        restoreHttp01NetworkPreference();
                    }
                }

                const serverKeyPem = serverKey.toString();

                // Split bundle: first is leaf, everything is chain
                const certs = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [cert];
                const leafCert = certs[0];

                const collectionToSet: CertificateCollection | null = {
                    from: this.namespace,
                    key: serverKeyPem,
                    cert: leafCert,
                    chain: certs,
                    domains,
                    staging: this.config.useStaging,
                    tsExpires: 0,
                };

                // Decode certificate to get expiry.
                try {
                    const crt = x509.parseCert(leafCert);
                    this.log.debug(`New certs notBefore ${crt.notBefore} notAfter ${crt.notAfter}`);
                    collectionToSet.tsExpires = Date.parse(crt.notAfter);
                } catch {
                    this.log.error(`Certificate returned for ${collection.id} looks invalid - not saving`);
                    return;
                }

                this.log.debug(
                    `Prepared certificate collection ${collection.id} (domains: ${domains.length}, chainParts: ${certs.length})`,
                );
                // Save it
                await this.certManager?.setCollection(collection.id, collectionToSet);
                this.log.info(`Collection ${collection.id} order success`);
            } catch (err) {
                const errorMessage = AcmeAdapter.getErrorMessage(err);
                const userFacingErrorMessage = this.getActionableCertificateErrorMessage(err);
                if (err instanceof Error && err.stack) {
                    this.log.debug(`Certificate request stack (${collection.id}): ${err.stack}`);
                }
                if (errorMessage.startsWith('Alias delegation not visible:')) {
                    this.log.warn(
                        `Certificate request for ${collection.id} (${domains?.join(', ')}) aborted: ${userFacingErrorMessage}`,
                    );
                } else {
                    this.log.error(
                        `Certificate request for ${collection.id} (${domains?.join(', ')}) failed: ${userFacingErrorMessage}`,
                    );
                }
            } finally {
                restoreDnsOverride();
            }

            this.log.debug('Done');
        }
    }
}
if (require.main !== module) {
    // Export the constructor in compact mode
    module.exports = (options: Partial<AdapterOptions> | undefined) => new AcmeAdapter(options);
} else {
    // otherwise start the instance directly
    (() => new AcmeAdapter())();
}
