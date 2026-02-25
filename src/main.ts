/*
 * Created with @iobroker/create-adapter v2.3.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
import * as utils from '@iobroker/adapter-core';
import { CertificateManager, type CertificateCollection } from '@iobroker/webserver';
import ACME from 'acme';
import Keypairs from '@root/keypairs';
import CSR from '@root/csr';
import PEM from '@root/pem';
import x509 from 'x509.js';
import { Resolver } from 'node:dns/promises';

import type { AdapterOptions } from '@iobroker/adapter-core';

import pkg from '../package.json';
import { create as createHttp01ChallengeServer } from './lib/http-01-challenge-server';
import type { AcmeAdapterConfig } from './types';

// Public DNS resolvers used as fallback when authoritative NS lookup fails.
const publicResolver = new Resolver();
publicResolver.setServers(['1.1.1.1', '8.8.8.8']);

const accountObjectId = 'account';
// Renew 7 days before expiry
const renewWindow = 60 * 60 * 24 * 7 * 1000;

interface AcmeAccount {
    full: Record<string, any> | null;
    key: Record<string, any> | null;
}

interface ChallengeHandler {
    init: (opts: Record<string, unknown>) => Promise<null>;
    set: (data: any) => Promise<null>;
    get: (data: any) => Promise<any>;
    remove: (data: any) => Promise<null>;
    shutdown: () => void;
}

class AcmeAdapter extends utils.Adapter {
    declare config: AcmeAdapterConfig;
    private account: AcmeAccount;
    private readonly challenges: Record<string, ChallengeHandler>;
    private readonly toShutdown: ChallengeHandler[];
    private donePortCheck: boolean;
    private certManager: CertificateManager | undefined;
    private acme: {
        init: (directoryUrl: string) => Promise<void>;
        accounts: {
            create: (options: {
                subscriberEmail: string;
                agreeToTerms: boolean;
                accountKey: Record<string, any>;
            }) => Promise<Record<string, any>>;
        };
        certificates: {
            create: (options: {
                account: Record<string, any>;
                accountKey: Record<string, string | Buffer>;
                csr: string;
                domains: string[];
                challenges: Record<string, ChallengeHandler>;
            }) => Promise<{ cert: string; chain: string }>;
        };
    } | null = null;
    private stoppedAdapters: string[] | null | undefined;

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

        this.on('ready', this.onReady.bind(this));
        this.on('unload', this.onUnload.bind(this));
    }

    /**
     * Called when the adapter is unloaded (e.g. ioBroker restart, adapter stop).
     * Cleans up challenge servers and restores previously stopped adapters.
     */
    private onUnload(callback: () => void): void {
        try {
            for (const challenge of this.toShutdown) {
                try {
                    challenge.shutdown();
                } catch {
                    // ignore individual shutdown errors
                }
            }
            // Best-effort restore of stopped adapters — fire and forget since we're shutting down
            if (this.stoppedAdapters) {
                this.restoreAdaptersOnSamePort().catch(() => {});
            }
        } catch {
            // ignore
        } finally {
            callback();
        }
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady(): Promise<void> {
        // Log config without sensitive fields
        const safeConfig = { ...this.config } as Record<string, unknown>;
        for (const key of Object.keys(safeConfig)) {
            if (
                /api|key|secret|password|token/i.test(key) &&
                typeof safeConfig[key] === 'string' &&
                safeConfig[key].length > 0
            ) {
                safeConfig[key] = '***';
            }
        }
        this.log.debug(`config: ${JSON.stringify(safeConfig)}`);

        this.certManager = new CertificateManager({ adapter: this });

        if (!this.config?.collections?.length) {
            this.terminate('No collections configured - nothing to order');
        } else {
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
                    this.log.error(`Failed in ACME init/generation: ${err}`);
                }
            }
        }

        // Purge any collections we created in the past but are not configured now and have also expired.
        try {
            const collections = await this.certManager.getAllCollections();
            if (collections) {
                this.log.debug(`existingCollectionIds: ${JSON.stringify(Object.keys(collections))}`);
                for (const [collectionId, collection] of Object.entries(collections)) {
                    if (collection.from === this.namespace && collection.tsExpires < Date.now()) {
                        this.log.info(`Removing expired and de-configured collection ${collectionId}`);
                        await this.certManager.delCollection(collectionId);
                    }
                }
            } else {
                this.log.debug(`No collections found`);
            }
        } catch (err) {
            this.log.error(`Failed in existing collection check/purge: ${err}`);
        }

        this.log.debug('Shutdown...');

        for (const challenge of this.toShutdown) {
            challenge.shutdown();
        }

        try {
            await this.restoreAdaptersOnSamePort();
        } catch (err) {
            this.log.error(`Failed to restore adapters on same port: ${err}`);
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
            }

            // Log options without exposing credentials
            const safeOpts = { ...dns01Options } as Record<string, unknown>;
            for (const key of Object.keys(safeOpts)) {
                if (
                    /api|key|secret|password|token/i.test(key) &&
                    typeof safeOpts[key] === 'string' &&
                    safeOpts[key].length > 0
                ) {
                    safeOpts[key] = '***';
                }
            }
            this.log.debug(`dns-01 options: ${JSON.stringify(safeOpts)}`);

            // Do this inside try... catch as the module is configurable
            let thisChallenge: ChallengeHandler | undefined;
            try {
                // Netcup is bundled locally; all other modules are npm packages
                if (this.config.dns01Module === 'acme-dns-01-netcup') {
                    const netcupModule = await import('./lib/acme-dns-01-netcup.js');
                    thisChallenge = netcupModule.create({ ...(dns01Options as any), log: this.log });
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
                this.log.error(`Failed to load dns-01 challenge module: ${err}`);
            }

            if (thisChallenge) {
                // Add extra properties
                // TODO: only add where needed?
                for (const [key, value] of Object.entries(dns01Props)) {
                    (thisChallenge as any)[key] = value;
                }
                // The Netcup set() method polls until the TXT record is confirmed
                // on public DNS (1.1.1.1/8.8.8.8), so no additional propagation
                // delay is needed. Forcing 0 prevents acme.js from waiting an
                // extra propagationDelay ms before its Pre-Flight DNS check,
                // which could race against DNS cache expiry on 1.1.1.1.
                if (this.config.dns01Module === 'acme-dns-01-netcup') {
                    (thisChallenge as any).propagationDelay = 0;
                    this.log.debug(
                        'dns-01: propagationDelay set to 0 for Netcup (set() handles propagation internally)',
                    );
                }
                this.challenges['dns-01'] = thisChallenge;
            }
        }
    }

    acmeNotify(ev: string, msg: unknown): void {
        let text: string;
        try {
            text = JSON.stringify(msg);
        } catch {
            text = String(msg);
        }
        if (ev === 'error') {
            this.log.error(`ACMENotify - ${ev}: ${text}`);
        } else if (ev === 'warning') {
            this.log.warn(`ACMENotify - ${ev}: ${text}`);
        } else {
            this.log.debug(`ACMENotify - ${ev}: ${text}`);
        }
    }

    /**
     * Polls authoritative nameservers and then public resolvers until the expected
     * TXT record is visible, ensuring the ACME challenge succeeds on first attempt.
     */
    private async pollDns01Challenge(ch: {
        dnsHost: string;
        dnsAuthorization: string;
    }): Promise<{ answer: { data: string[] }[] }> {
        const labels = ch.dnsHost.split('.');
        const zone = labels.slice(-2).join('.');

        // Build a resolver pointing at the zone's authoritative NS
        let resolver: Resolver;
        try {
            const nsNames = await publicResolver.resolveNs(zone);
            const nsIps: string[] = [];
            for (const ns of nsNames.slice(0, 3)) {
                try {
                    const addrs = await publicResolver.resolve4(ns);
                    nsIps.push(...addrs.map((ip: string) => `${ip}:53`));
                } catch {
                    /* skip */
                }
            }
            if (nsIps.length > 0) {
                resolver = new Resolver();
                resolver.setServers(nsIps);
                this.log.debug(`acme.dns01: using authoritative NS for ${zone}: ${nsIps.join(', ')}`);
            } else {
                resolver = publicResolver;
                this.log.debug(`acme.dns01: NS lookup empty, falling back to public resolvers`);
            }
        } catch {
            resolver = publicResolver;
            this.log.debug(`acme.dns01: NS lookup failed, falling back to public resolvers`);
        }

        // Poll until the TXT record is visible on the authoritative NS.
        // Netcup zone updates take ~5-10 min due to a serialised update queue.
        // Two consecutive updates (dry-run remove + real set) can take ~10-20 min.
        const maxAttempts = 120; // 120 × 10 s = 20 min
        const retryDelayMs = 10_000;
        this.log.info(
            `acme.dns01: polling authoritative NS for ${ch.dnsHost} ` +
                `(every ${retryDelayMs / 1000}s, max ${maxAttempts} attempts = ${(maxAttempts * retryDelayMs) / 60_000} min)...`,
        );

        const expectedValue = ch.dnsAuthorization;
        this.log.debug(`acme.dns01: waiting for TXT value: ${expectedValue}`);

        let foundRecords: string[][] = [];
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                const records = await resolver.resolveTxt(ch.dnsHost);
                if (records.flat().includes(expectedValue)) {
                    this.log.debug(
                        `acme.dns01: correct TXT value found on authoritative NS after attempt ${attempt}/${maxAttempts}`,
                    );
                    foundRecords = records;
                    break;
                }
                this.log.debug(
                    `acme.dns01: attempt ${attempt}/${maxAttempts}: ${
                        records.length > 0
                            ? `found ${records.length} stale TXT record(s) but not the expected value`
                            : 'no TXT records yet'
                    }, retrying in ${retryDelayMs / 1000}s...`,
                );
            } catch {
                this.log.debug(
                    `acme.dns01: attempt ${attempt}/${maxAttempts}: NXDOMAIN — not yet visible, retrying in ${retryDelayMs / 1000}s...`,
                );
            }
            await new Promise<void>(r => setTimeout(r, retryDelayMs));
        }

        if (foundRecords.length === 0) {
            throw new Error(`acme.dns01: TXT record not visible on authoritative NS after ${maxAttempts} attempts`);
        }

        // Additionally wait until the correct value is also visible on public resolvers
        // (1.1.1.1 / 8.8.8.8), because LE's validators use recursive resolvers that
        // may have cached a negative (NXDOMAIN) response from earlier attempts.
        const maxPublicAttempts = 60; // 60 × 10 s = 10 min extra
        this.log.info(`acme.dns01: ${ch.dnsHost} visible on authoritative NS — waiting for public resolvers...`);
        for (let attempt = 1; attempt <= maxPublicAttempts; attempt++) {
            try {
                const records = await publicResolver.resolveTxt(ch.dnsHost);
                if (records.flat().includes(expectedValue)) {
                    this.log.info(
                        `acme.dns01: correct TXT value confirmed on public resolver after ${attempt}/${maxPublicAttempts} — submitting challenge to LE`,
                    );
                    return { answer: records.map((rr: string[]) => ({ data: rr })) };
                }
                this.log.debug(
                    `acme.dns01: public resolver attempt ${attempt}/${maxPublicAttempts}: ${
                        records.length > 0 ? 'found stale records but not the expected value' : 'no records yet'
                    }, retrying in ${retryDelayMs / 1000}s...`,
                );
            } catch {
                this.log.debug(
                    `acme.dns01: public resolver attempt ${attempt}/${maxPublicAttempts}: NXDOMAIN, retrying in ${retryDelayMs / 1000}s...`,
                );
            }
            await new Promise<void>(r => setTimeout(r, retryDelayMs));
        }

        // Public resolver didn't pick it up — submit anyway with authoritative NS result
        this.log.warn(
            `acme.dns01: public resolver timeout — submitting with authoritative NS result (may still succeed)`,
        );
        return { answer: foundRecords.map((rr: string[]) => ({ data: rr })) };
    }

    async initAcme(): Promise<void> {
        if (!this.acme) {
            // Doesn't exist yet, actually do init
            const directoryUrl = this.config.useStaging
                ? 'https://acme-staging-v02.api.letsencrypt.org/directory'
                : 'https://acme-v02.api.letsencrypt.org/directory';
            this.log.debug(`Using URL: ${directoryUrl}`);

            this.acme = ACME.create({
                maintainerEmail: this.config.maintainerEmail,
                packageAgent: `${pkg.name}/${pkg.version}`,
                notify: this.acmeNotify.bind(this),
                debug: true,
            });
            await this.acme!.init(directoryUrl);

            // Override acme.js's internal DNS-01 Pre-Flight check.
            // set() creates the record and returns immediately (propagationDelay=0).
            // This function then polls the authoritative NS directly until the record
            // is visible — and only then returns, so that acme.js immediately POSTs
            // the challenge to LE while the authorization is still fresh/pending.
            (this.acme as any).dns01 = (ch: { dnsHost: string; dnsAuthorization: string }) =>
                this.pollDns01Challenge(ch);
            this.log.debug(
                'acme.dns01 overridden: polls authoritative NS until record is visible, then immediately submits to LE',
            );

            // Try and load a saved object
            const accountObject = await this.getObjectAsync(accountObjectId);
            if (accountObject) {
                this.log.debug(`Loaded existing ACME account: ${JSON.stringify(accountObject)}`);

                if (accountObject.native?.maintainerEmail !== this.config.maintainerEmail) {
                    this.log.info('Saved account does not match maintainer email, will recreate.');
                } else if (accountObject.native?.useStaging === undefined) {
                    this.log.info('Saved account is missing staging/production flag (old format), will recreate.');
                } else if (accountObject.native?.useStaging !== this.config.useStaging) {
                    this.log.info(
                        `Saved account was created for ${accountObject.native.useStaging ? 'staging' : 'production'} LE, but current config uses ${this.config.useStaging ? 'staging' : 'production'} — will recreate.`,
                    );
                } else {
                    this.account = accountObject.native as AcmeAccount;
                }
            }

            if (!this.account.full) {
                this.log.info('Registering new ACME account...');

                // Register a new account
                const accountKeypair: { [name: string]: any } = await Keypairs.generate({
                    kty: 'EC',
                    format: 'jwk',
                });
                this.log.debug('New account keypair generated');
                this.account.key = accountKeypair.private;

                this.account.full = await this.acme!.accounts.create({
                    subscriberEmail: this.config.maintainerEmail,
                    agreeToTerms: true,
                    accountKey: this.account.key!,
                });
                this.log.debug(`Created ACME account (kid: ${this.account.full?.key?.kid ?? 'unknown'})`);

                await this.extendObjectAsync(accountObjectId, {
                    native: {
                        ...this.account,
                        maintainerEmail: this.config.maintainerEmail,
                        useStaging: this.config.useStaging,
                    },
                });
            }
        }
    }

    async stopAdaptersOnSamePort(): Promise<void> {
        // TODO: Maybe this should be in some sort of utility so other adapters can 'grab' a port in use?
        // Stop conflicting adapters using our challenge server port only if we are going to need it and haven't already checked.
        if (this.config.http01Active && !this.donePortCheck) {
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
     * Checks whether two string arrays contain the same elements (order-independent).
     */
    _arraysMatch(arr1: unknown, arr2: unknown): boolean {
        if (!Array.isArray(arr1) || !Array.isArray(arr2)) {
            return false;
        }
        if (arr1 === arr2) {
            return true;
        }
        if (arr1.length !== arr2.length) {
            return false;
        }
        const sorted1 = [...arr1].sort();
        const sorted2 = [...arr2].sort();
        return sorted1.every((val, idx) => val === sorted2[idx]);
    }

    async generateCollection(collection: { id: string; commonName: string; altNames: string }): Promise<void> {
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
            this.log.debug(
                `Existing collection "${collection.id}": domains=${JSON.stringify(existingCollection.domains)}, staging=${existingCollection.staging}, expires=${existingCollection.tsExpires ? new Date(existingCollection.tsExpires).toISOString() : 'unknown'}`,
            );

            try {
                // Decode certificate to check not due for renewal and parts match what is configured.
                const crt = x509.parseCert(existingCollection.cert.toString());
                this.log.debug(`Existing cert: ${JSON.stringify(crt)}`);

                if (Date.now() > Date.parse(crt.notAfter) - renewWindow) {
                    this.log.info(`Collection ${collection.id} expiring soon (notAfter: ${crt.notAfter}) - will renew`);
                    create = true;
                } else if (collection.commonName !== crt.subject.commonName) {
                    this.log.info(
                        `Collection ${collection.id} common name changed ("${crt.subject.commonName}" → "${collection.commonName}") - will renew`,
                    );
                    create = true;
                } else if (!this._arraysMatch(domains, crt.altNames)) {
                    this.log.info(
                        `Collection ${collection.id} alt names changed (${JSON.stringify(crt.altNames)} → ${JSON.stringify(domains)}) - will renew`,
                    );
                    create = true;
                } else if (this.config.useStaging !== existingCollection.staging) {
                    this.log.info(`Collection ${collection.id} staging flags do not match - will renew`);
                    create = true;
                } else {
                    this.log.debug(`Collection ${collection.id} certificate already looks good`);
                }
            } catch (err) {
                this.log.error(`Collection ${collection.id} exists but looks invalid (${err}) - will renew`);
                create = true;
            }
        }

        if (create) {
            // stopAdaptersOnSamePort can be called many times as has its own checks to prevent unnecessary action.
            await this.stopAdaptersOnSamePort();

            const serverKeypair = await Keypairs.generate({ kty: 'RSA', format: 'jwk' });
            const serverPem = await Keypairs.export({ jwk: serverKeypair.private });
            const serverKey = await Keypairs.import({ pem: serverPem });

            const csrDer = await CSR.csr({
                jwk: serverKey,
                domains,
                encoding: 'der',
            });
            const csr = PEM.packBlock({
                type: 'CERTIFICATE REQUEST',
                bytes: csrDer,
            });

            if (!this.acme || !this.account.full || !this.account.key) {
                this.log.error('ACME client not initialized');
                return;
            }
            let pems: { cert: string; chain: string } | undefined;
            try {
                pems = await this.acme.certificates.create({
                    account: this.account.full,
                    accountKey: this.account.key,
                    csr,
                    domains,
                    challenges: this.challenges,
                });
            } catch (err) {
                this.log.error(`Certificate request for ${collection.id} (${domains?.join(', ')}) failed: ${err}`);
            }

            this.log.debug('Done');

            if (pems) {
                let collectionToSet: CertificateCollection | null = {
                    from: this.namespace,
                    key: serverPem,
                    cert: pems.cert,
                    chain: [pems.cert, pems.chain],
                    domains,
                    staging: this.config.useStaging,
                    tsExpires: 0,
                };

                // Decode certificate to get expiry.
                // Kind of handy that this happens to verify certificate looks good too.
                try {
                    const crt = x509.parseCert(collectionToSet.cert.toString());
                    this.log.debug(`New certs notBefore ${crt.notBefore} notAfter ${crt.notAfter}`);
                    collectionToSet.tsExpires = Date.parse(crt.notAfter);
                } catch {
                    this.log.error(`Certificate returned for ${collection.id} looks invalid - not saving`);
                    collectionToSet = null;
                }

                if (collectionToSet) {
                    this.log.debug(
                        `${collection.id}: domains=${JSON.stringify(collectionToSet.domains)}, expires=${new Date(collectionToSet.tsExpires).toISOString()}`,
                    );
                    // Save it
                    await this.certManager?.setCollection(collection.id, collectionToSet);
                    this.log.info(
                        `Collection ${collection.id} order success for ${domains.join(', ')} (expires ${new Date(collectionToSet.tsExpires).toISOString()})`,
                    );
                }
            }
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
