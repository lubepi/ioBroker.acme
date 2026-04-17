"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
/*
 * Created with @iobroker/create-adapter v2.3.0
 */
const utils = __importStar(require("@iobroker/adapter-core"));
const webserver_1 = require("@iobroker/webserver");
const acme = __importStar(require("acme-client"));
const node_dns_1 = __importStar(require("node:dns"));
const node_net_1 = __importDefault(require("node:net"));
const node_util_1 = require("node:util");
const x509_js_1 = __importDefault(require("x509.js"));
const dns_01_acmedns_1 = require("./lib/dns-01-acmedns");
const http_01_challenge_server_1 = require("./lib/http-01-challenge-server");
const dns_01_utils_1 = require("./lib/dns-01-utils");
const accountObjectId = 'account';
// Renew 7 days before expiry
const renewWindow = 60 * 60 * 24 * 7 * 1000;
const adapterStopWaitTimeoutMs = 20000;
const adapterStopPollIntervalMs = 500;
const portReleaseWaitTimeoutMs = 10000;
const portReleasePollIntervalMs = 250;
class AcmeAdapter extends utils.Adapter {
    account;
    challenges;
    toShutdown;
    donePortCheck;
    certManager;
    acmeClient = null;
    stoppedAdapters;
    dnsChallengeCache;
    acmeDnsCnameCheckedHosts;
    acmeDnsAutoRegisteredCollections;
    acmeDnsBlockedCollectionReasons;
    acmeDnsAutoRegisterBlocked;
    http01ServerReady;
    http01ServerInitPromise;
    /**
     * Safely extract an error message from an unknown error value.
     */
    static getErrorMessage(err) {
        if (err instanceof Error) {
            return err.message;
        }
        return String(err);
    }
    /**
     * Adds user-facing context for common opaque runtime errors.
     */
    getActionableCertificateErrorMessage(err) {
        const errorMessage = AcmeAdapter.getErrorMessage(err);
        const stack = err instanceof Error ? err.stack || '' : '';
        const acmeClientTransportBug = /Cannot read properties of undefined \(reading 'config'\)/.test(errorMessage) &&
            /acme-client\/src\/axios\.js/.test(stack);
        if (acmeClientTransportBug) {
            const transportHint = ' ACME transport error: no valid HTTP response was available from the ACME API (often timeout/connection reset/proxy or DNS/network interruption).';
            return errorMessage + transportHint;
        }
        if (/Cannot read properties of undefined \(reading 'config'\)/.test(errorMessage)) {
            const activeChallenges = [];
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
    constructor(options = {}) {
        super({
            ...options,
            name: 'acme',
        });
        this.account = {
            full: null,
            keyEnc: null,
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
    onUnload(callback) {
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
            }
            catch (err) {
                this.log.warn(`Error during unload cleanup: ${AcmeAdapter.getErrorMessage(err)}`);
            }
            finally {
                callback();
            }
        })();
    }
    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Redact sensitive fields before logging
        const safeConfig = { ...this.config };
        const sensitiveKeys = ['dns01OapiKey', 'dns01OapiPassword', 'dns01Okey', 'dns01Osecret', 'dns01Otoken'];
        for (const key of sensitiveKeys) {
            if (safeConfig[key]) {
                safeConfig[key] = '***REDACTED***';
            }
        }
        const collectionCredentials = safeConfig.dns01CollectionCredentials;
        if (Array.isArray(collectionCredentials)) {
            safeConfig.dns01CollectionCredentials = collectionCredentials.map((entry) => ({
                ...entry,
                password: entry?.password ? '***REDACTED***' : entry?.password,
                subdomain: entry?.subdomain ? '***REDACTED***' : entry?.subdomain,
            }));
        }
        delete safeConfig.dns01CollectionOverrides;
        this.log.debug(`config: ${JSON.stringify(safeConfig)}`);
        acme.setLogger((message) => this.log.debug(`acme-client: ${message}`));
        this.certManager = new webserver_1.CertificateManager({ adapter: this });
        if (!this.config?.collections?.length) {
            this.terminate('No collections configured - nothing to order');
        }
        else if (!this.config.maintainerEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.config.maintainerEmail)) {
            this.terminate('Invalid or missing maintainer email address');
        }
        else {
            const deterministicConfigErrors = this.getDeterministicConfigurationErrors();
            if (deterministicConfigErrors.length) {
                for (const err of deterministicConfigErrors) {
                    this.log.error(`Configuration preflight failed: ${err}`);
                }
                this.terminate(`Configuration preflight failed with ${deterministicConfigErrors.length} error(s). Fix adapter settings and retry.`);
                return;
            }
            // Setup challenges
            await this.initChallenges();
            if (!Object.keys(this.challenges).length) {
                this.log.error('Failed to initiate any challenges');
            }
            else {
                try {
                    // Init ACME/account, etc
                    await this.initAcme();
                    // Loop round collections and generate certs
                    for (const collection of this.config.collections) {
                        await this.generateCollection(collection);
                    }
                }
                catch (err) {
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
                    if (collection.from === this.namespace &&
                        !configuredCollectionIds.has(collectionId) &&
                        collection.tsExpires < Date.now()) {
                        this.log.info(`Removing expired and de-configured collection ${collectionId}`);
                        await this.certManager.delCollection(collectionId);
                    }
                }
            }
            else {
                this.log.debug(`No collections found`);
            }
        }
        catch (err) {
            this.log.error(`Failed in existing collection check/purge: ${AcmeAdapter.getErrorMessage(err)}`);
        }
        this.log.debug('Shutdown...');
        for (const challenge of this.toShutdown) {
            challenge.shutdown();
        }
        try {
            await this.restoreAdaptersOnSamePort();
        }
        catch (err) {
            this.log.error(`Failed to restore adapters on same port: ${AcmeAdapter.getErrorMessage(err)}`);
        }
        this.terminate('Processing complete');
    }
    async initChallenges() {
        if (this.config.http01Active) {
            this.log.debug('Init http-01 challenge server');
            // This does not actually cause the challenge server to start listening, so we don't need to do port check at this time.
            const thisChallenge = (0, http_01_challenge_server_1.create)({
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
            const dns01Options = {};
            const dns01Props = {};
            for (const [key, value] of Object.entries(this.config)) {
                if (key.startsWith('dns01O')) {
                    // An option...
                    dns01Options[key.slice(6)] = value;
                }
                else if (key.startsWith('dns01P')) {
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
                this.log.info('acme-dns uses per-collection credentials; missing credentials are created automatically during order processing');
                // Keep a valid handler object for dns-01; real credentials are injected per collection during order processing.
                delete dns01Options.baseUrl;
                dns01Options.username = '__auto-register__';
                dns01Options.password = '__auto-register__';
                dns01Options.subdomain = '__auto-register__';
            }
            // Do this inside try... catch as the module is configurable
            let thisChallenge;
            try {
                if (this.config.dns01Module === 'acme-dns-01-acmedns') {
                    thisChallenge = (0, dns_01_acmedns_1.create)(dns01Options);
                }
                else {
                    // Dynamic import - module name comes from config
                    const dns01Module = await import(this.config.dns01Module);
                    if (dns01Module.default) {
                        thisChallenge = dns01Module.default.create(dns01Options);
                    }
                    else {
                        thisChallenge = dns01Module.create(dns01Options);
                    }
                }
            }
            catch (err) {
                this.log.error(`Failed to load dns-01 challenge module '${this.config.dns01Module}': ${AcmeAdapter.getErrorMessage(err)}`);
            }
            if (thisChallenge) {
                // Add extra properties
                // TODO: only add where needed?
                for (const [key, value] of Object.entries(dns01Props)) {
                    thisChallenge[key] = value;
                }
                // Adapter-side propagation verification runs before notifying the CA.
                // Keep propagationDelay at 0 to avoid extra ACME-client waiting.
                if (this.config.dns01Module === 'acme-dns-01-netcup') {
                    thisChallenge.propagationDelay = 0;
                    this.log.debug('dns-01: Netcup verifyPropagation disabled; adapter handles propagation checks');
                    this.log.debug('dns-01: propagationDelay set to 0 for Netcup to avoid duplicate waiting');
                }
                // Some acme-dns-01-* modules expect init({ request }) to inject HTTP helper.
                if (typeof thisChallenge.init === 'function') {
                    try {
                        // eslint-disable-next-line @typescript-eslint/no-require-imports
                        const rootRequest = require('@root/request');
                        const request = (0, node_util_1.promisify)(rootRequest);
                        await thisChallenge.init({ request });
                    }
                    catch (err) {
                        this.log.warn(`dns-01 module '${this.config.dns01Module}' init() failed, trying without init: ${AcmeAdapter.getErrorMessage(err)}`);
                    }
                }
                this.challenges['dns-01'] = thisChallenge;
            }
        }
    }
    async initAcme() {
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
                const native = accountObject.native;
                const savedMaintainerEmail = typeof native?.maintainerEmail === 'string' ? native.maintainerEmail.trim() : '';
                const configuredMaintainerEmail = `${this.config.maintainerEmail || ''}`.trim();
                if (savedMaintainerEmail && savedMaintainerEmail !== configuredMaintainerEmail) {
                    this.log.warn('Saved account does not match maintainer email, will recreate.');
                }
                else if (native?.useStaging !== this.config.useStaging) {
                    this.log.info(`Saved account was created for ${native?.useStaging ? 'staging' : 'production'} LE, but current config uses ${this.config.useStaging ? 'staging' : 'production'} — will recreate.`);
                }
                else {
                    if (!savedMaintainerEmail && (native?.full || native?.keyEnc)) {
                        this.log.debug('Saved account has no maintainerEmail metadata; reusing account and updating metadata.');
                    }
                    this.account = native;
                }
            }
            let accountKeyPem;
            if (this.account.keyEnc) {
                this.log.debug('Decrypting persisted ACME account key...');
                try {
                    accountKeyPem = this.decrypt(this.account.keyEnc);
                }
                catch (err) {
                    this.log.error(`Failed to decrypt account key: ${AcmeAdapter.getErrorMessage(err)}`);
                    this.account = { full: null, keyEnc: null };
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
                        keyEnc: this.encrypt(accountKeyPem.toString()),
                        maintainerEmail: this.config.maintainerEmail,
                        useStaging: this.config.useStaging,
                    },
                });
            }
        }
    }
    async ensureHttp01ChallengeServerStarted() {
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
            }
            catch (err) {
                this.http01ServerReady = false;
                const reason = AcmeAdapter.getErrorMessage(err);
                const hint = this.config.http01StopConflictingAdapters === true
                    ? 'Choose a free HTTP-01 port or verify bind/address settings.'
                    : 'Choose a free HTTP-01 port or enable automatic stopping of conflicting adapters.';
                throw new Error(`HTTP-01 challenge server could not start on ${this.config.bind}:${this.config.port}: ${reason}. ${hint}`);
            }
        })();
        try {
            await this.http01ServerInitPromise;
        }
        finally {
            this.http01ServerInitPromise = null;
        }
    }
    applyHttp01SelfCheckNetworkPreference(enable) {
        if (!enable) {
            return () => { };
        }
        const restoreActions = [];
        try {
            const previousAutoSelectFamily = node_net_1.default.getDefaultAutoSelectFamily();
            node_net_1.default.setDefaultAutoSelectFamily(true);
            restoreActions.push(() => {
                node_net_1.default.setDefaultAutoSelectFamily(previousAutoSelectFamily);
            });
            this.log.debug('HTTP-01 self-check: enabled dual-stack auto family selection');
        }
        catch (err) {
            this.log.debug(`HTTP-01 self-check: unable to enable dual-stack auto family selection (${AcmeAdapter.getErrorMessage(err)})`);
        }
        try {
            const previousOrder = node_dns_1.default.getDefaultResultOrder();
            node_dns_1.default.setDefaultResultOrder('ipv6first');
            restoreActions.push(() => {
                node_dns_1.default.setDefaultResultOrder(previousOrder);
            });
            this.log.debug('HTTP-01 self-check: using IPv6-first DNS resolution for local ACME verification');
        }
        catch (err) {
            this.log.debug(`HTTP-01 self-check: unable to apply IPv6-first DNS preference (${AcmeAdapter.getErrorMessage(err)})`);
        }
        return () => {
            for (let i = restoreActions.length - 1; i >= 0; i--) {
                try {
                    restoreActions[i]();
                }
                catch {
                    // Ignore restore errors; these are best-effort runtime preferences.
                }
            }
        };
    }
    applyHttp01SelfCheckFastFail(enable) {
        if (!enable || !this.acmeClient) {
            return () => { };
        }
        const client = this.acmeClient;
        const originalVerifyChallenge = client.verifyChallenge;
        if (typeof originalVerifyChallenge !== 'function') {
            return () => { };
        }
        let verifyHttp01;
        let acmeAxios;
        try {
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            const verifyModule = require('acme-client/src/verify');
            verifyHttp01 = verifyModule?.['http-01'];
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            acmeAxios = require('acme-client/src/axios');
        }
        catch (err) {
            this.log.debug(`HTTP-01 self-check: fast-fail patch unavailable (${AcmeAdapter.getErrorMessage(err)})`);
            return () => { };
        }
        if (typeof verifyHttp01 !== 'function' || !acmeAxios?.defaults?.acmeSettings) {
            return () => { };
        }
        client.verifyChallenge = async (authz, challenge) => {
            if (!challenge || challenge.type !== 'http-01') {
                return originalVerifyChallenge.call(client, authz, challenge);
            }
            const domain = typeof authz?.identifier?.value === 'string' && authz.identifier.value
                ? authz.identifier.value
                : 'configured domain';
            const previousRetryMaxAttempts = acmeAxios.defaults.acmeSettings.retryMaxAttempts;
            try {
                // Fast-fail on HTTP-01 self-check to avoid long retry loops on deterministic proxy misrouting.
                this.log.debug(`HTTP-01 self-check: verifying ${domain} against ${this.config.bind}:${this.config.port} with IPv6-first DNS and dual-stack auto family selection enabled`);
                acmeAxios.defaults.acmeSettings.retryMaxAttempts = 0;
                const keyAuthorization = await this.acmeClient.getChallengeKeyAuthorization(challenge);
                return await verifyHttp01(authz, challenge, keyAuthorization);
            }
            catch (err) {
                const message = AcmeAdapter.getErrorMessage(err);
                if (/Request failed with status code 502/.test(message)) {
                    this.log.debug(`HTTP-01 self-check debug: ${domain} returned 502 from the proxy/gateway.`);
                    throw new Error(`Request failed with status code 502 (HTTP-01 self-check). Reverse proxy/router returned Bad Gateway for /.well-known/acme-challenge/. Verify forwarding from external port 80 to ${this.config.bind}:${this.config.port} for published DNS paths.`);
                }
                if (/Request failed with status code 404/.test(message)) {
                    this.log.debug(`HTTP-01 self-check debug: ${domain} returned 404. The request reached an HTTP endpoint, but that path did not expose this adapter's challenge token.`);
                    throw new Error(`Request failed with status code 404 (HTTP-01 self-check). The challenge URL for ${domain} is reachable but does not expose this adapter's challenge token. This usually means the domain's A/AAAA DNS records and/or reverse proxy routing point to a different host/backend than the HTTP-01 challenge endpoint.`);
                }
                if (/\(resp\.data \|\| ""\)\.replace is not a function/.test(message)) {
                    this.log.debug(`HTTP-01 self-check debug: ${domain} returned a non-text HTTP response.`);
                    throw new Error(`HTTP-01 self-check received an unexpected non-text HTTP response for ${domain}. The challenge endpoint must return plain key-authorization text. This usually means /.well-known/acme-challenge/ is served by a different app/router/proxy target than ${this.config.bind}:${this.config.port}.`);
                }
                throw err;
            }
            finally {
                acmeAxios.defaults.acmeSettings.retryMaxAttempts = previousRetryMaxAttempts;
            }
        };
        this.log.debug('HTTP-01 self-check: fast-fail enabled for local verification');
        return () => {
            client.verifyChallenge = originalVerifyChallenge;
        };
    }
    async isHttp01PortAvailable() {
        return await new Promise(resolve => {
            const server = node_net_1.default.createServer();
            const onResolved = (available) => {
                server.removeAllListeners('error');
                server.removeAllListeners('listening');
                resolve(available);
            };
            server.once('error', () => {
                try {
                    server.close();
                }
                catch {
                    // ignore close errors on failed bind attempts
                }
                onResolved(false);
            });
            server.once('listening', () => {
                server.close(() => onResolved(true));
            });
            try {
                server.listen(this.config.port, this.config.bind);
            }
            catch {
                onResolved(false);
            }
        });
    }
    async waitForHttp01PortRelease(timeoutMs = portReleaseWaitTimeoutMs) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            if (await this.isHttp01PortAvailable()) {
                return true;
            }
            await new Promise(resolve => setTimeout(resolve, portReleasePollIntervalMs));
        }
        return await this.isHttp01PortAvailable();
    }
    async waitForAdapterStop(instanceId, timeoutMs = adapterStopWaitTimeoutMs) {
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
    async stopAdaptersOnSamePort() {
        // TODO: Maybe this should be in some sort of utility so other adapters can 'grab' a port in use?
        // Stop conflicting adapters using our challenge server port only if we are going to need it and haven't already checked.
        if (this.config.http01Active && !this.donePortCheck) {
            if (this.config.http01StopConflictingAdapters !== true) {
                this.log.info('Automatic stopping of conflicting adapters on HTTP-01 port is disabled unless explicitly enabled. Existing services will remain running.');
                this.donePortCheck = true;
                return;
            }
            // TODO: is there a better way than hardcoding this 'system.adapter.' part?
            const us = `system.adapter.${this.namespace}`;
            const host = this.host;
            const bind = this.config.bind;
            const port = this.config.port;
            this.log.debug(`Checking for adapter other than us (${us}) on our host/bind/port ${host}/${bind}/${port}...`);
            const result = await this.getObjectViewAsync('system', 'instance', {
                startkey: 'system.adapter.',
                endkey: 'system.adapter.\u9999',
            });
            const instances = result.rows.map(row => row.value);
            const adapters = instances.filter(instance => 
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
                        instance.native.leCheckPort == port)));
            if (!adapters.length) {
                this.log.debug('No adapters found on same port, nothing to stop');
            }
            else {
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
                        this.log.warn(`Adapter ${adapterId} did not stop within ${adapterStopWaitTimeoutMs}ms. HTTP-01 port might still be in use.`);
                    }
                }
                const portReleased = await this.waitForHttp01PortRelease();
                if (!portReleased) {
                    this.log.warn(`HTTP-01 port ${bind}:${port} still appears busy after waiting ${portReleaseWaitTimeoutMs}ms for conflicting adapters to stop.`);
                }
            }
            this.donePortCheck = true;
        }
    }
    async restoreAdaptersOnSamePort() {
        if (!this.stoppedAdapters) {
            this.log.debug('No previously shutdown adapters to restart');
        }
        else {
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
    arraysMatch(arr1, arr2) {
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
    getDnsChallengeCacheKey(authz, challenge) {
        return `${authz?.identifier?.value || ''}|${challenge?.token || ''}`;
    }
    async getDnsZones(handler, dnsHost) {
        if (!handler || typeof handler.zones !== 'function') {
            return [];
        }
        try {
            const zones = await handler.zones({ dnsHosts: [dnsHost] });
            if (!Array.isArray(zones)) {
                return [];
            }
            return zones.filter(zone => typeof zone === 'string');
        }
        catch (err) {
            this.log.debug(`dns-01 zones() lookup failed: ${AcmeAdapter.getErrorMessage(err)}`);
            return [];
        }
    }
    async buildDnsChallengePayload(handler, authz, challenge, keyAuthorization) {
        const normalizedDnsAlias = (0, dns_01_utils_1.normalizeDnsAlias)(this.config.dns01Alias);
        const identifierValue = normalizedDnsAlias || authz.identifier.value;
        const dnsHost = `_acme-challenge.${identifierValue}`;
        if (normalizedDnsAlias) {
            this.log.info(`Using DNS Alias: ${dnsHost} instead of _acme-challenge.${authz.identifier.value}`);
        }
        const zones = await this.getDnsZones(handler, dnsHost);
        return (0, dns_01_utils_1.buildDnsChallengeData)({
            identifierValue,
            identifierType: authz.identifier.type,
            wildcard: authz.wildcard,
            token: challenge.token,
            keyAuthorization,
            zones,
        });
    }
    async saveCollectionAcmeDnsCredentials(credentials) {
        const instanceObjectId = `system.adapter.${this.namespace}`;
        const instanceObj = await this.getForeignObjectAsync(instanceObjectId);
        if (!instanceObj?.native) {
            throw new Error(`Unable to update adapter config object: ${instanceObjectId}`);
        }
        const existing = Array.isArray(instanceObj.native.dns01CollectionCredentials)
            ? [...instanceObj.native.dns01CollectionCredentials]
            : [];
        const idx = existing.findIndex((entry) => entry?.collectionId === credentials.collectionId);
        if (idx >= 0) {
            existing[idx] = credentials;
        }
        else {
            existing.push(credentials);
        }
        instanceObj.native.dns01CollectionCredentials = existing;
        await this.setForeignObjectAsync(instanceObjectId, instanceObj);
        this.config.dns01CollectionCredentials = existing;
    }
    async autoCreateCollectionAcmeDnsCredentials(collectionId, preferredBaseUrl) {
        if (this.acmeDnsAutoRegisterBlocked) {
            this.log.warn(`Collection ${collectionId}: automatic acme-dns registration is temporarily disabled for this run due to previous registration failure`);
            return null;
        }
        const baseUrl = `${preferredBaseUrl || ''}`.trim();
        try {
            const registration = await (0, dns_01_acmedns_1.registerAcmeDnsAccount)(baseUrl || undefined);
            const credentials = {
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
                this.log.info(`Collection ${collectionId}: configure CNAME target to ${registration.fullDomain} for DNS-01 delegation`);
            }
            return credentials;
        }
        catch (err) {
            this.acmeDnsAutoRegisterBlocked = true;
            this.log.error(`Collection ${collectionId}: failed to auto-create acme-dns account (${AcmeAdapter.getErrorMessage(err)})`);
            return null;
        }
    }
    getCollectionAcmeDnsCredentials(collectionId) {
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
            fullDomain: typeof credential.fullDomain === 'string' && credential.fullDomain.trim()
                ? credential.fullDomain.trim()
                : undefined,
        };
    }
    getDeterministicConfigurationErrors() {
        const errors = [];
        if (!this.config.dns01Active || this.config.dns01Module !== 'acme-dns-01-acmedns') {
            return errors;
        }
        const collections = Array.isArray(this.config.collections) ? this.config.collections : [];
        const knownCollectionIds = new Set(collections
            .map(collection => `${collection?.id || ''}`.trim().toLowerCase())
            .filter(collectionId => !!collectionId));
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
                }
                catch {
                    errors.push(`${rowLabel}: base URL "${baseUrl}" is invalid`);
                }
            }
        }
        return errors;
    }
    normalizeDnsName(name) {
        return name.trim().replace(/\.+$/, '').toLowerCase();
    }
    isResolverUnreachableError(err) {
        const code = err?.code;
        return (typeof code === 'string' &&
            ['ETIMEOUT', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNREFUSED', 'ECONNRESET', 'EREFUSED'].includes(code));
    }
    isDnsNoRecordError(err) {
        const code = err?.code;
        return typeof code === 'string' && ['ENODATA', 'ENOTFOUND', 'NXDOMAIN', 'NOTFOUND'].includes(code);
    }
    async precheckHttp01DnsRecords(domains) {
        if (!this.config.http01Active) {
            return;
        }
        const http01Domains = Array.from(new Set(domains
            .filter(domain => !domain.startsWith('*.'))
            .map(domain => this.normalizeDnsName(domain))
            .filter(domain => !!domain)));
        if (!http01Domains.length) {
            return;
        }
        const missingPublicRecords = [];
        for (const domain of http01Domains) {
            const [ipv4Result, ipv6Result] = await Promise.allSettled([
                node_dns_1.promises.resolve4(domain),
                node_dns_1.promises.resolve6(domain),
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
            const aaaaReason = ipv6Result.status === 'rejected' ? AcmeAdapter.getErrorMessage(ipv6Result.reason) : 'none';
            this.log.debug(`HTTP-01 DNS preflight: ${domain} has no resolvable A/AAAA records via local resolver (A error: ${aReason}, AAAA error: ${aaaaReason}). Continuing because this may be a temporary resolver/network issue.`);
        }
        if (missingPublicRecords.length > 0) {
            throw new Error(`HTTP-01 DNS preflight failed: no public A/AAAA record found for ${missingPublicRecords.join(', ')}. Configure at least one A or AAAA record (or disable HTTP-01 for this collection). The A/AAAA entry is either missing or not yet visible on tested resolvers.`);
        }
    }
    async resolveNsServerAddresses(nsHost) {
        const addresses = new Set();
        try {
            const ipv4 = await node_dns_1.promises.resolve4(nsHost);
            for (const ip of ipv4) {
                addresses.add(ip);
            }
        }
        catch (err) {
            this.log.debug(`DNS A lookup failed for nameserver ${nsHost}: ${AcmeAdapter.getErrorMessage(err)}`);
        }
        try {
            const ipv6 = await node_dns_1.promises.resolve6(nsHost);
            for (const ip of ipv6) {
                addresses.add(ip);
            }
        }
        catch (err) {
            this.log.debug(`DNS AAAA lookup failed for nameserver ${nsHost}: ${AcmeAdapter.getErrorMessage(err)}`);
        }
        return Array.from(addresses);
    }
    async getAuthoritativeResolvers(recordName) {
        const normalizedName = this.normalizeDnsName(recordName);
        const labels = normalizedName.split('.');
        const nsHosts = new Set();
        for (let i = 0; i < labels.length - 1; i += 1) {
            const zoneCandidate = labels.slice(i).join('.');
            try {
                const nsRecords = await node_dns_1.promises.resolveNs(zoneCandidate);
                if (nsRecords.length > 0) {
                    for (const ns of nsRecords) {
                        nsHosts.add(this.normalizeDnsName(ns));
                    }
                    break;
                }
            }
            catch (err) {
                this.log.debug(`DNS NS lookup failed for ${zoneCandidate}: ${AcmeAdapter.getErrorMessage(err)}`);
            }
        }
        const authoritativeResolvers = [];
        for (const nsHost of nsHosts) {
            const addresses = await this.resolveNsServerAddresses(nsHost);
            if (!addresses.length) {
                this.log.debug(`No IP addresses resolved for nameserver ${nsHost}.`);
                continue;
            }
            for (const address of addresses) {
                const resolver = new node_dns_1.promises.Resolver();
                resolver.setServers([address]);
                authoritativeResolvers.push({
                    name: `${nsHost} (${address})`,
                    resolver,
                });
            }
        }
        return authoritativeResolvers;
    }
    async resolveTxtViaResolver(resolver, recordName) {
        try {
            const cnameRecords = await resolver.resolveCname(recordName);
            if (cnameRecords.length > 0) {
                return this.resolveTxtViaResolver(resolver, cnameRecords[0]);
            }
        }
        catch (err) {
            this.log.debug(`DNS CNAME lookup failed for ${recordName}: ${AcmeAdapter.getErrorMessage(err)}`);
        }
        try {
            const txtRecords = await resolver.resolveTxt(recordName);
            return {
                values: txtRecords.flat().filter(entry => typeof entry === 'string'),
                reachable: true,
            };
        }
        catch (err) {
            this.log.debug(`DNS TXT lookup failed for ${recordName}: ${AcmeAdapter.getErrorMessage(err)}`);
            return {
                values: [],
                reachable: !this.isResolverUnreachableError(err),
            };
        }
    }
    async resolveCnameViaResolver(resolver, recordName) {
        try {
            const cnameRecords = await resolver.resolveCname(recordName);
            return {
                values: cnameRecords,
                reachable: true,
            };
        }
        catch (err) {
            this.log.debug(`DNS CNAME lookup failed for ${recordName}: ${AcmeAdapter.getErrorMessage(err)}`);
            return {
                values: [],
                reachable: !this.isResolverUnreachableError(err),
            };
        }
    }
    async waitForDnsPropagation(recordName, expectedValue) {
        const waitForMs = 5000;
        const maxAttempts = 240;
        const authoritativeResolvers = await this.getAuthoritativeResolvers(recordName);
        if (authoritativeResolvers.length === 0) {
            throw new Error(`No authoritative DNS resolver could be determined for ${recordName}`);
        }
        this.log.debug(`Using authoritative DNS resolvers for propagation check of ${recordName}: ${authoritativeResolvers
            .map(entry => entry.name)
            .join(', ')}`);
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            const checks = await Promise.all(authoritativeResolvers.map(async ({ name, resolver }) => {
                const result = await this.resolveTxtViaResolver(resolver, recordName);
                return {
                    name,
                    reachable: result.reachable,
                    ok: result.values.includes(expectedValue),
                };
            }));
            const reachableChecks = checks.filter(check => check.reachable);
            const okResolvers = reachableChecks.filter(check => check.ok).map(check => check.name);
            if (reachableChecks.length > 0 && okResolvers.length === reachableChecks.length) {
                this.log.info(`DNS propagation verified for ${recordName} on all reachable authoritative resolvers (${okResolvers.join(', ')}).`);
                return;
            }
            if (reachableChecks.length > 0) {
                this.log.debug(`DNS propagation not yet complete for ${recordName} on authoritative resolvers. Visible on ${okResolvers.length}/${reachableChecks.length} reachable authoritative resolvers. Retrying in ${waitForMs}ms. (Attempt ${attempt} / ${maxAttempts})`);
            }
            else {
                this.log.debug(`Authoritative resolvers for ${recordName} are currently not reachable. Retrying in ${waitForMs}ms. (Attempt ${attempt} / ${maxAttempts})`);
            }
            if (attempt < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, waitForMs));
            }
        }
        throw new Error(`Timed out waiting for DNS propagation of ${recordName}`);
    }
    async waitForDnsAliasDelegation(sourceRecordName, targetRecordName) {
        const waitForMs = 5000;
        const maxAttempts = 3;
        const normalizedTarget = this.normalizeDnsName(targetRecordName);
        const authoritativeResolvers = await this.getAuthoritativeResolvers(sourceRecordName);
        if (authoritativeResolvers.length === 0) {
            throw new Error(`No authoritative DNS resolver could be determined for ${sourceRecordName}`);
        }
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            const checks = await Promise.all(authoritativeResolvers.map(async ({ name, resolver }) => {
                const result = await this.resolveCnameViaResolver(resolver, sourceRecordName);
                const ok = result.values.some(record => this.normalizeDnsName(record) === normalizedTarget);
                return {
                    name,
                    reachable: result.reachable,
                    ok,
                };
            }));
            const reachableChecks = checks.filter(check => check.reachable);
            const okCount = reachableChecks.filter(check => check.ok).length;
            if (reachableChecks.length > 0 && okCount === reachableChecks.length) {
                this.log.info(`DNS alias delegation verified for ${sourceRecordName} -> ${targetRecordName} on all reachable authoritative resolvers.`);
                return;
            }
            if (reachableChecks.length > 0) {
                this.log.debug(`DNS alias delegation not yet visible for ${sourceRecordName} -> ${targetRecordName}. Visible on ${okCount}/${reachableChecks.length} reachable authoritative resolvers. Retrying in ${waitForMs}ms. (Attempt ${attempt} / ${maxAttempts})`);
            }
            else {
                this.log.debug(`Authoritative resolvers for ${sourceRecordName} are currently not reachable. Retrying in ${waitForMs}ms. (Attempt ${attempt} / ${maxAttempts})`);
            }
            if (attempt < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, waitForMs));
            }
        }
        const message = `Alias delegation not visible: ${sourceRecordName} -> ${targetRecordName}. ` +
            'The CNAME entry is either missing or not yet visible on tested resolvers. ' +
            'If you have just created or updated this DNS record, wait a moment for propagation and retry the adapter run.';
        throw new Error(message);
    }
    getAcmeDnsDelegationTargetForCollection(collectionId) {
        const credential = this.getCollectionAcmeDnsCredentials(collectionId);
        if (credential?.fullDomain) {
            return this.normalizeDnsName(credential.fullDomain);
        }
        const token = `${credential?.subdomain || ''}`.trim();
        if (!token) {
            return null;
        }
        const baseUrl = `${credential?.baseUrl || ''}`.trim() || 'https://auth.acme-dns.io';
        try {
            const host = new URL(baseUrl).hostname;
            if (!host) {
                return null;
            }
            return this.normalizeDnsName(`${token}.${host}`);
        }
        catch {
            return null;
        }
    }
    async ensureAcmeDnsDelegationVisible(collectionId, authz) {
        const identifierValue = authz?.identifier?.value;
        if (!identifierValue || typeof identifierValue !== 'string') {
            return null;
        }
        const expectedTarget = this.getAcmeDnsDelegationTargetForCollection(collectionId);
        if (!expectedTarget) {
            this.log.debug(`Collection ${collectionId}: acme-dns delegation target could not be determined from credentials/config. Skipping explicit CNAME precheck.`);
            return null;
        }
        const sourceDnsHost = `_acme-challenge.${identifierValue}`;
        const cacheKey = `${sourceDnsHost}->${expectedTarget}`;
        if (this.acmeDnsCnameCheckedHosts.has(cacheKey)) {
            return expectedTarget;
        }
        this.acmeDnsCnameCheckedHosts.add(cacheKey);
        this.log.info(`Checking DNS alias delegation of ${sourceDnsHost} to ${expectedTarget} before TXT propagation checks.`);
        await this.waitForDnsAliasDelegation(sourceDnsHost, expectedTarget);
        return expectedTarget;
    }
    async activateCollectionDnsCredentials(collectionId) {
        this.acmeDnsBlockedCollectionReasons.delete(collectionId);
        if (!this.config.dns01Active || this.config.dns01Module !== 'acme-dns-01-acmedns') {
            return () => undefined;
        }
        let credentials = this.getCollectionAcmeDnsCredentials(collectionId);
        let autoRegistered = false;
        if (!credentials) {
            this.log.info(`Collection ${collectionId}: no acme-dns credentials configured, trying automatic account registration`);
            credentials = await this.autoCreateCollectionAcmeDnsCredentials(collectionId);
            autoRegistered = !!credentials;
        }
        if (credentials && !credentials.username && !credentials.password && !credentials.subdomain) {
            this.log.info(`Collection ${collectionId}: acme-dns credentials row has no credentials, trying automatic account registration`);
            credentials = await this.autoCreateCollectionAcmeDnsCredentials(collectionId, credentials.baseUrl);
            autoRegistered = !!credentials;
        }
        if (!credentials) {
            this.acmeDnsBlockedCollectionReasons.set(collectionId, 'acme-dns credentials could not be determined (automatic registration failed or was blocked)');
            return () => undefined;
        }
        const dns01Options = {};
        for (const [key, value] of Object.entries(this.config)) {
            if (key.startsWith('dns01O')) {
                dns01Options[key.slice(6)] = value;
            }
        }
        delete dns01Options.baseUrl;
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
        const overrideHandler = (0, dns_01_acmedns_1.create)(dns01Options);
        if (typeof overrideHandler.init === 'function') {
            try {
                // eslint-disable-next-line @typescript-eslint/no-require-imports
                const rootRequest = require('@root/request');
                const request = (0, node_util_1.promisify)(rootRequest);
                await overrideHandler.init({ request });
            }
            catch (err) {
                this.log.warn(`Collection ${collectionId}: acme-dns credentials init() failed, continuing anyway: ${AcmeAdapter.getErrorMessage(err)}`);
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
            }
            catch (err) {
                this.log.debug(`Collection ${collectionId}: acme-dns credentials shutdown failed: ${AcmeAdapter.getErrorMessage(err)}`);
            }
        };
    }
    async generateCollection(collection) {
        this.log.debug(`Collection: ${JSON.stringify(collection)}`);
        // Create domains now as will be used to test any existing collection.
        const domains = collection.commonName
            .split(',')
            .map(d => d.trim())
            .filter(n => n);
        if (collection.altNames) {
            domains.push(...collection.altNames
                .replace(/\s/g, '')
                .split(',')
                .filter(n => n));
        }
        this.log.debug(`domains: ${JSON.stringify(domains)}`);
        const wildcardDomains = domains.filter(domain => domain.startsWith('*.'));
        // Get an existing collection & see if it needs renewing
        let create = false;
        const existingCollection = (await this.certManager?.getCollection(collection.id));
        if (!existingCollection) {
            this.log.info(`Collection ${collection.id} does not exist - will create`);
            create = true;
        }
        else {
            this.log.debug(`Existing: ${collection.id}: ${JSON.stringify(existingCollection)}`);
            try {
                // Decode certificate to check not due for renewal and parts match what is configured.
                const crt = x509_js_1.default.parseCert(existingCollection.cert.toString());
                this.log.debug(`Existing cert: ${JSON.stringify(crt)}`);
                if (Date.now() > Date.parse(crt.notAfter) - renewWindow) {
                    this.log.info(`Collection ${collection.id} expiring soon - will renew`);
                    create = true;
                }
                else if (collection.commonName !== crt.subject.commonName) {
                    this.log.info(`Collection ${collection.id} common name does not match - will renew`);
                    create = true;
                }
                else if (!this.arraysMatch(domains, crt.altNames)) {
                    this.log.info(`Collection ${collection.id} alt names do not match - will renew`);
                    create = true;
                }
                else if (this.config.useStaging !== existingCollection.staging) {
                    this.log.info(`Collection ${collection.id} staging flags do not match - will renew`);
                    create = true;
                }
                else {
                    this.log.debug(`Collection ${collection.id} certificate already looks good`);
                }
            }
            catch (err) {
                this.log.error(`Collection ${collection.id} exists but looks invalid (${AcmeAdapter.getErrorMessage(err)}) - will renew`);
                create = true;
            }
        }
        if (create) {
            if (wildcardDomains.length > 0 && this.config.http01Active && !this.config.dns01Active) {
                this.log.warn(`Collection ${collection.id} contains wildcard domain(s) (${wildcardDomains.join(', ')}), but DNS-01 is disabled. Wildcard certificates require DNS-01. Enable DNS-01 and retry.`);
                return;
            }
            if (this.config.dns01Active &&
                ['acme-dns-01-acmedns', 'acme-dns-01-duckdns'].includes(this.config.dns01Module)) {
                const dns01Domains = this.config.http01Active ? wildcardDomains : domains;
                const uniqueDns01Domains = Array.from(new Set(dns01Domains.map(domain => domain.toLowerCase())));
                if (uniqueDns01Domains.length > 1) {
                    this.log.warn(`Collection ${collection.id} contains multiple DNS-01 domains (${uniqueDns01Domains.join(', ')}) while provider ${this.config.dns01Module} supports only one TXT record per account. Split this into one domain per collection and retry.`);
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
                    this.log.info(`Collection ${collection.id}: automatic acme-dns registration completed. Configure _acme-challenge CNAME to ${delegationTarget} and start the adapter again.`);
                }
                else {
                    this.log.info(`Collection ${collection.id}: automatic acme-dns registration completed. Configure _acme-challenge CNAME using the generated acme-dns target and start the adapter again.`);
                }
                this.log.info(`Collection ${collection.id}: skipping certificate order in this run so DNS delegation can be configured first.`);
                restoreDnsOverride();
                return;
            }
            let cert;
            try {
                const hasNonWildcardDomains = domains.some(domain => !domain.startsWith('*.'));
                if (this.config.http01Active && hasNonWildcardDomains) {
                    this.log.info(`HTTP-01 preflight: validating listener availability on ${this.config.bind}:${this.config.port} before placing order.`);
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
                    this.log.info(`Order for ${domains.join(', ')} is already valid. Skipping challenges and redeeming certificate...`);
                    cert = (await this.acmeClient.getCertificate(order)).toString();
                }
                else {
                    // Use auto() to handle the pending challenge/finalization flow.
                    const challengePriority = [];
                    if (this.config.http01Active) {
                        challengePriority.push('http-01');
                    }
                    if (this.config.dns01Active) {
                        challengePriority.push('dns-01');
                    }
                    const aliasDnsOnlyFlow = !!this.config.dns01Alias && this.config.dns01Active && !this.config.http01Active;
                    if (aliasDnsOnlyFlow) {
                        this.log.info('DNS-01 alias configured in DNS-only mode: waiting for CNAME delegation and DNS propagation before continuing the ACME flow.');
                    }
                    const hasHttp01Targets = this.config.http01Active && hasNonWildcardDomains;
                    const restoreHttp01FastFail = this.applyHttp01SelfCheckFastFail(hasHttp01Targets);
                    const restoreHttp01NetworkPreference = this.applyHttp01SelfCheckNetworkPreference(hasHttp01Targets);
                    try {
                        cert = (await this.acmeClient.auto({
                            csr,
                            email: this.config.maintainerEmail,
                            termsOfServiceAgreed: true,
                            skipChallengeVerification: aliasDnsOnlyFlow,
                            challengePriority,
                            challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                                this.log.debug(`Satisfying challenge ${challenge.type} for ${authz.identifier.value}`);
                                const handler = this.challenges[challenge.type];
                                if (!handler) {
                                    throw new Error(`No handler for challenge type ${challenge.type}`);
                                }
                                if (challenge.type === 'dns-01') {
                                    const challengeData = await this.buildDnsChallengePayload(handler, authz, challenge, keyAuthorization);
                                    this.dnsChallengeCache[this.getDnsChallengeCacheKey(authz, challenge)] =
                                        challengeData;
                                    await handler.set(challengeData);
                                    const sourceDnsHost = `_acme-challenge.${authz.identifier.value}`;
                                    const challengeDnsHost = challengeData?.challenge?.dnsHost ||
                                        challengeData?.dnsHost ||
                                        sourceDnsHost;
                                    let propagationDnsHost = challengeDnsHost;
                                    let delegationAlreadyVerified = false;
                                    if (this.config.dns01Module === 'acme-dns-01-acmedns' &&
                                        challengeDnsHost === sourceDnsHost) {
                                        const delegatedDnsHost = await this.ensureAcmeDnsDelegationVisible(collection.id, authz);
                                        if (delegatedDnsHost) {
                                            propagationDnsHost = delegatedDnsHost;
                                            delegationAlreadyVerified = true;
                                        }
                                    }
                                    const expectedDnsAuthorization = challengeData?.challenge?.dnsAuthorization;
                                    if (!expectedDnsAuthorization) {
                                        throw new Error(`Missing dnsAuthorization in challenge payload for ${challengeDnsHost}`);
                                    }
                                    if (propagationDnsHost !== sourceDnsHost) {
                                        if (!delegationAlreadyVerified) {
                                            this.log.info(`Waiting for DNS alias delegation of ${sourceDnsHost} to ${propagationDnsHost} before notifying the CA.`);
                                            await this.waitForDnsAliasDelegation(sourceDnsHost, propagationDnsHost);
                                        }
                                        this.log.info(`Waiting for DNS propagation of ${propagationDnsHost} on authoritative resolvers before notifying the CA.`);
                                    }
                                    else {
                                        this.log.info(`DNS-01 without alias: waiting for DNS propagation of ${propagationDnsHost} on authoritative resolvers before notifying the CA.`);
                                    }
                                    await this.waitForDnsPropagation(propagationDnsHost, expectedDnsAuthorization);
                                }
                                else {
                                    await this.ensureHttp01ChallengeServerStarted();
                                    const challengeData = {
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
                                this.log.debug(`Removing challenge ${challenge.type} for ${authz.identifier.value}`);
                                const handler = this.challenges[challenge.type];
                                if (handler) {
                                    if (challenge.type === 'dns-01') {
                                        const cacheKey = this.getDnsChallengeCacheKey(authz, challenge);
                                        const cached = this.dnsChallengeCache[cacheKey];
                                        const removeData = cached ||
                                            (await this.buildDnsChallengePayload(handler, authz, challenge, keyAuthorization));
                                        await handler.remove(removeData);
                                        delete this.dnsChallengeCache[cacheKey];
                                    }
                                    else {
                                        const removeData = {
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
                        })).toString();
                    }
                    finally {
                        restoreHttp01FastFail();
                        restoreHttp01NetworkPreference();
                    }
                }
                const serverKeyPem = serverKey.toString();
                // Split bundle: first is leaf, everything is chain
                const certs = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [cert];
                const leafCert = certs[0];
                const collectionToSet = {
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
                    const crt = x509_js_1.default.parseCert(leafCert);
                    this.log.debug(`New certs notBefore ${crt.notBefore} notAfter ${crt.notAfter}`);
                    collectionToSet.tsExpires = Date.parse(crt.notAfter);
                }
                catch {
                    this.log.error(`Certificate returned for ${collection.id} looks invalid - not saving`);
                    return;
                }
                this.log.debug(`Prepared certificate collection ${collection.id} (domains: ${domains.length}, chainParts: ${certs.length})`);
                // Save it
                await this.certManager?.setCollection(collection.id, collectionToSet);
                this.log.info(`Collection ${collection.id} order success`);
            }
            catch (err) {
                const errorMessage = AcmeAdapter.getErrorMessage(err);
                const userFacingErrorMessage = this.getActionableCertificateErrorMessage(err);
                if (err instanceof Error && err.stack) {
                    this.log.debug(`Certificate request stack (${collection.id}): ${err.stack}`);
                }
                if (errorMessage.startsWith('Alias delegation not visible:')) {
                    this.log.warn(`Certificate request for ${collection.id} (${domains?.join(', ')}) aborted: ${userFacingErrorMessage}`);
                }
                else {
                    this.log.error(`Certificate request for ${collection.id} (${domains?.join(', ')}) failed: ${userFacingErrorMessage}`);
                }
            }
            finally {
                restoreDnsOverride();
            }
            this.log.debug('Done');
        }
    }
}
if (require.main !== module) {
    // Export the constructor in compact mode
    module.exports = (options) => new AcmeAdapter(options);
}
else {
    // otherwise start the instance directly
    (() => new AcmeAdapter())();
}
