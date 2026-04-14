const path = require('path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const net = require('node:net');
const { tests } = require('@iobroker/testing');
const { buildDnsChallengeData, computeDnsAuthorization, normalizeDnsAlias } = require('../build/lib/dns-01-utils');

const mockAcmeClientPath = path.join(__dirname, 'mock-acme-client.js');

function createAcmeMockEnv() {
    const previous = process.env.NODE_OPTIONS ? `${process.env.NODE_OPTIONS} ` : '';
    return {
        NODE_OPTIONS: `${previous}--require ${mockAcmeClientPath}`,
    };
}

async function waitForAdapterStop(harness, timeoutMs = 45_000) {
    const start = Date.now();
    while (!harness.didAdapterStop()) {
        if (Date.now() - start > timeoutMs) {
            throw new Error(`Adapter did not stop within ${timeoutMs}ms`);
        }
        await new Promise(resolve => setTimeout(resolve, 250));
    }
}

async function getAcmeHost(harness) {
    const acmeObj = await harness.objects.getObjectAsync('system.adapter.acme.0');
    if (!acmeObj?.common?.host) {
        throw new Error('system.adapter.acme.0 common.host not found');
    }
    return acmeObj.common.host;
}

async function createConflictingAdapter(harness, { id, host, bind, port, enabled }) {
    const now = Date.now();
    await harness.objects.setObjectAsync(id, {
        _id: id,
        type: 'instance',
        common: {
            name: 'simple-api',
            enabled,
            host,
            mode: 'daemon',
            titleLang: { en: 'simple-api' },
        },
        native: {
            bind,
            port,
            secure: false,
            leEnabled: false,
            leUpdate: false,
            leCheckPort: 80,
        },
    });

    await harness.states.setStateAsync(`${id}.alive`, {
        val: false,
        ack: true,
        from: 'system.host.testing',
        ts: now,
        lc: now,
    });
}

async function configureHttpOnlyCollection(harness, { id, commonName, port, stopConflicting }) {
    await harness.changeAdapterConfig('acme', {
        native: {
            maintainerEmail: 'test@example.com',
            useStaging: true,
            bind: '0.0.0.0',
            port,
            http01Active: true,
            http01StopConflictingAdapters: stopConflicting,
            dns01Active: false,
            collections: [
                {
                    id,
                    commonName,
                    altNames: '',
                },
            ],
        },
    });
}

// Run integration tests - See https://github.com/ioBroker/testing for a detailed explanation and further options
tests.integration(path.join(__dirname, '..'), {
    allowedExitCodes: [11],
    defineAdditionalTests({ suite }) {
        suite('DNS alias utils', () => {
            it('normalizes dns01Alias values', () => {
                if (normalizeDnsAlias('') !== '') {
                    throw new Error('Expected empty alias to stay empty');
                }
                if (normalizeDnsAlias('  acme.example.net  ') !== 'acme.example.net') {
                    throw new Error('Expected trimmed alias domain');
                }
                if (normalizeDnsAlias('_acme-challenge.acme.example.net') !== 'acme.example.net') {
                    throw new Error('Expected alias prefix to be removed');
                }
                if (normalizeDnsAlias('acme.example.net.') !== 'acme.example.net') {
                    throw new Error('Expected trailing dot to be removed');
                }
            });

            it('computes dnsAuthorization according to RFC dns-01 hash format', () => {
                const keyAuthorization = 'token.thumbprint';
                const expected = crypto.createHash('sha256').update(keyAuthorization).digest('base64url');
                const actual = computeDnsAuthorization(keyAuthorization);
                if (actual !== expected) {
                    throw new Error('DNS authorization hash does not match expected value');
                }
            });

            it('builds provider-compatible dns challenge payload', () => {
                const payload = buildDnsChallengeData({
                    identifierValue: 'sub.example.com',
                    identifierType: 'dns',
                    wildcard: false,
                    token: 'tok',
                    keyAuthorization: 'token.thumbprint',
                    zones: ['example.com'],
                });

                if (payload.dnsHost !== '_acme-challenge.sub.example.com') {
                    throw new Error('dnsHost mismatch');
                }
                if (payload.dnsZone !== 'example.com') {
                    throw new Error('dnsZone mismatch');
                }
                if (payload.dnsPrefix !== '_acme-challenge.sub') {
                    throw new Error('dnsPrefix mismatch');
                }
                if (!payload.challenge || payload.challenge.dnsAuthorization !== payload.dnsAuthorization) {
                    throw new Error('challenge dnsAuthorization missing or inconsistent');
                }
            });
        });

        suite('Collection purge behavior', getHarness => {
            let harness;

            before(() => {
                harness = getHarness();
            });

            it('purges only expired collections that are no longer configured', async function () {
                this.timeout(40_000);

                const certsObject = await harness.objects.getObjectAsync('system.certificates');
                if (!certsObject) {
                    throw new Error('system.certificates object not found');
                }

                certsObject.native = certsObject.native || {};
                certsObject.native.collections = {
                    keepMe: {
                        from: 'acme.0',
                        tsExpires: Date.now() - 10_000,
                        cert: 'dummy',
                        key: 'dummy',
                        chain: [],
                        domains: ['keep.example.com'],
                        staging: true,
                    },
                    removeMe: {
                        from: 'acme.0',
                        tsExpires: Date.now() - 10_000,
                        cert: 'dummy',
                        key: 'dummy',
                        chain: [],
                        domains: ['remove.example.com'],
                        staging: true,
                    },
                    foreignCollection: {
                        from: 'web.0',
                        tsExpires: Date.now() - 10_000,
                        cert: 'dummy',
                        key: 'dummy',
                        chain: [],
                        domains: ['foreign.example.com'],
                        staging: true,
                    },
                };
                await harness.objects.setObjectAsync('system.certificates', certsObject);

                const adapterObject = await harness.objects.getObjectAsync('system.adapter.acme.0');
                if (!adapterObject) {
                    throw new Error('system.adapter.acme.0 object not found');
                }

                Object.assign(adapterObject.native, {
                    maintainerEmail: 'test@example.com',
                    http01Active: false,
                    dns01Active: false,
                    collections: [
                        {
                            id: 'keepMe',
                            commonName: 'keep.example.com',
                            altNames: '',
                        },
                    ],
                });

                await harness.objects.setObjectAsync(adapterObject._id, adapterObject);
                await harness.startAdapterAndWait();
                await new Promise(resolve => setTimeout(resolve, 3_000));

                const updated = await harness.objects.getObjectAsync('system.certificates');
                const updatedCollections = updated?.native?.collections || {};

                if (!updatedCollections.keepMe) {
                    throw new Error('Configured expired collection was incorrectly removed');
                }
                if (updatedCollections.removeMe) {
                    throw new Error('Expired de-configured collection was not removed');
                }
                if (!updatedCollections.foreignCollection) {
                    throw new Error('Collection from another adapter should not be removed');
                }
            });
        });

        suite('HTTP-01 and wildcard guards', getHarness => {
            let harness;

            before(() => {
                harness = getHarness();
            });

            it('aborts wildcard issuance when only HTTP-01 is active', async function () {
                this.timeout(60_000);

                await configureHttpOnlyCollection(harness, {
                    id: 'wildOnly',
                    commonName: '*.example.com',
                    port: 18081,
                    stopConflicting: true,
                });

                await harness.startAdapter(createAcmeMockEnv());
                await waitForAdapterStop(harness);

                const certsObject = await harness.objects.getObjectAsync('system.certificates');
                const collections = certsObject?.native?.collections || {};
                assert.equal(collections.wildOnly, undefined, 'Wildcard collection must not be created in HTTP-only mode');
            });
        });

        suite('HTTP-01 stop/restore with enabled stop option', getHarness => {
            let harness;

            before(() => {
                harness = getHarness();
            });

            it('temporarily disables and restores conflicting adapter when stop option is enabled', async function () {
                this.timeout(90_000);

                const conflictId = 'system.adapter.simple-api.0';
                const host = await getAcmeHost(harness);
                const port = 18082;

                await createConflictingAdapter(harness, {
                    id: conflictId,
                    host,
                    bind: '0.0.0.0',
                    port,
                    enabled: true,
                });

                const enabledTransitions = [];
                harness.on('objectChange', (id, obj) => {
                    if (id === conflictId && obj?.common && typeof obj.common.enabled === 'boolean') {
                        enabledTransitions.push(obj.common.enabled);
                    }
                });

                await configureHttpOnlyCollection(harness, {
                    id: 'normal-enabled',
                    commonName: 'normal-enabled.example.com',
                    port,
                    stopConflicting: true,
                });

                await harness.startAdapter(createAcmeMockEnv());
                await waitForAdapterStop(harness);

                const after = await harness.objects.getObjectAsync(conflictId);
                const falseIndex = enabledTransitions.indexOf(false);
                const trueAfterFalseIndex = enabledTransitions.findIndex((val, idx) => idx > falseIndex && val === true);

                assert.equal(after?.common?.enabled, true, 'Conflicting adapter must be re-enabled at the end');
                assert.ok(falseIndex >= 0, 'Conflicting adapter should be disabled during challenge processing');
                assert.ok(trueAfterFalseIndex >= 0, 'Conflicting adapter should be enabled again after processing');
            });
        });

        suite('HTTP-01 with disabled stop option', getHarness => {
            let harness;

            before(() => {
                harness = getHarness();
            });

            it('does not disable conflicting adapter when stop option is disabled', async function () {
                this.timeout(90_000);

                const conflictId = 'system.adapter.simple-api.0';
                const host = await getAcmeHost(harness);
                const port = 18083;

                await createConflictingAdapter(harness, {
                    id: conflictId,
                    host,
                    bind: '0.0.0.0',
                    port,
                    enabled: true,
                });

                const enabledTransitions = [];
                harness.on('objectChange', (id, obj) => {
                    if (id === conflictId && obj?.common && typeof obj.common.enabled === 'boolean') {
                        enabledTransitions.push(obj.common.enabled);
                    }
                });

                await configureHttpOnlyCollection(harness, {
                    id: 'normal-disabled',
                    commonName: 'normal-disabled.example.com',
                    port,
                    stopConflicting: false,
                });

                await harness.startAdapter(createAcmeMockEnv());
                await waitForAdapterStop(harness);

                const after = await harness.objects.getObjectAsync(conflictId);
                assert.equal(after?.common?.enabled, true, 'Conflicting adapter should stay enabled');
                assert.ok(!enabledTransitions.includes(false), 'Conflicting adapter must not be disabled when stop option is off');
            });
        });

        suite('HTTP-01 restore on error path', getHarness => {
            let harness;

            before(() => {
                harness = getHarness();
            });

            it('restores conflicting adapter even when request fails because port stays occupied', async function () {
                this.timeout(90_000);

                const conflictId = 'system.adapter.simple-api.0';
                const host = await getAcmeHost(harness);
                const port = 18084;
                const blocker = net.createServer();

                await new Promise((resolve, reject) => {
                    blocker.once('error', reject);
                    blocker.listen(port, '0.0.0.0', () => resolve());
                });

                try {
                    await createConflictingAdapter(harness, {
                        id: conflictId,
                        host,
                        bind: '0.0.0.0',
                        port,
                        enabled: true,
                    });

                    const enabledTransitions = [];
                    harness.on('objectChange', (id, obj) => {
                        if (id === conflictId && obj?.common && typeof obj.common.enabled === 'boolean') {
                            enabledTransitions.push(obj.common.enabled);
                        }
                    });

                    await configureHttpOnlyCollection(harness, {
                        id: 'normal-error',
                        commonName: 'normal-error.example.com',
                        port,
                        stopConflicting: true,
                    });

                    await harness.startAdapter(createAcmeMockEnv());
                    await waitForAdapterStop(harness);

                    const after = await harness.objects.getObjectAsync(conflictId);
                    const falseIndex = enabledTransitions.indexOf(false);
                    const trueAfterFalseIndex = enabledTransitions.findIndex((val, idx) => idx > falseIndex && val === true);

                    assert.equal(
                        after?.common?.enabled,
                        true,
                        'Conflicting adapter must be re-enabled even after HTTP-01 failure',
                    );
                    assert.ok(falseIndex >= 0, 'Conflicting adapter should be disabled during the failed run');
                    assert.ok(trueAfterFalseIndex >= 0, 'Conflicting adapter should be re-enabled after failed run');
                } finally {
                    await new Promise(resolve => blocker.close(() => resolve()));
                }
            });
        });
    },
});