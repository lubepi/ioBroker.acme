'use strict';

import { Resolver } from 'node:dns/promises';

// Use public resolvers to avoid stale negative cache on the ioBroker host.
const publicResolver = new Resolver();
publicResolver.setServers(['1.1.1.1', '8.8.8.8']);

/**
 * ACME DNS-01 challenge handler for Netcup CCP DNS API
 *
 * Required credentials (passed via create(options)):
 *   - customerNumber  : Netcup customer number (Kundennummer)
 *   - apiKey          : Netcup API key (from CCP → Master Data → API)
 *   - apiPassword     : Netcup API password (from CCP → Master Data → API)
 *
 * Note on subdomain / apex-domain detection:
 *   The implementation uses a simple heuristic (last two labels = apex).
 *   This works for standard TLDs (.com, .de, .net, …).
 *   For ccSLDs like .co.uk the public-suffix list would be needed.
 *   All common Netcup domains use single-label TLDs, so this is sufficient.
 */

const API_ENDPOINT = 'https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON';

interface Logger {
    warn: (msg: string) => void;
    error: (msg: string) => void;
    debug: (msg: string) => void;
}

const noopLogger: Logger = {
    warn: (msg: string) => console.warn(msg),
    error: (msg: string) => console.error(msg),
    debug: (msg: string) => console.log(msg),
};

interface NetcupOptions {
    customerNumber: string | number;
    apiKey: string;
    apiPassword: string;
    log?: Logger;
}

interface DnsRecord {
    id?: string;
    hostname: string;
    type: string;
    destination: string;
    deleterecord?: boolean;
    [key: string]: unknown;
}

interface ChallengeData {
    challenge: {
        dnsHost: string;
        dnsAuthorization: string;
    };
}

/**
 * Send a JSON request to the Netcup CCP API.
 * @param throwOnError - if false, returns the raw response even on non-2xxx status (used by get/remove)
 */
async function apiCall(action: string, param: Record<string, unknown>, throwOnError = true): Promise<any> {
    const body = JSON.stringify({ action, param });

    const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
    });

    if (!response.ok) {
        throw new Error(`Netcup HTTP error: ${response.status} ${response.statusText}`);
    }

    const rawText = await response.text();
    let json: { statuscode: number; longmessage?: string; shortmessage?: string; responsedata: any };
    try {
        json = JSON.parse(rawText);
    } catch {
        throw new Error(`Netcup API returned non-JSON response: ${rawText.slice(0, 200)}`);
    }

    // Netcup uses 2xxx for success (2000 = OK, 2011 = object created/updated, etc.)
    const isSuccess = json.statuscode >= 2000 && json.statuscode < 3000;

    if (!isSuccess && throwOnError) {
        throw new Error(
            `Netcup API error [${json.statuscode}]: ${json.longmessage ?? json.shortmessage ?? 'unknown error'}`,
        );
    }

    return isSuccess ? json.responsedata : null;
}

/**
 * Login and return the apisessionid.
 */
async function login(customerNumber: string | number, apiKey: string, apiPassword: string): Promise<string> {
    const data = await apiCall('login', {
        customernumber: String(customerNumber),
        apikey: apiKey,
        apipassword: apiPassword,
    });
    return data.apisessionid as string;
}

/**
 * Logout. Errors are swallowed intentionally (session may already be expired).
 */
async function logout(customerNumber: string | number, apiKey: string, apisessionid: string): Promise<void> {
    try {
        await apiCall('logout', {
            customernumber: String(customerNumber),
            apikey: apiKey,
            apisessionid,
        });
    } catch {
        // Ignore logout errors
    }
}

/**
 * Find the correct DNS zone and relative hostname for a given full DNS name.
 * Uses infoDnsZone to probe from most-specific to least-specific, exactly like
 * the official froonix/acme-dns-nc PHP reference implementation.
 *
 * Example: "_acme-challenge.sub.example.de"
 *   → tries "sub.example.de" → not found
 *   → tries "example.de"     → found  ✓
 *   → rootDomain = "example.de", hostname = "_acme-challenge.sub"
 */
async function findZone(
    fullDomain: string,
    customerNumber: string | number,
    apiKey: string,
    apisessionid: string,
    log: Logger,
): Promise<{ rootDomain: string; hostname: string }> {
    const parts = fullDomain.split('.');

    // Walk from most-specific (all parts minus the first) toward the apex
    for (let i = 1; i < parts.length - 1; i++) {
        const candidate = parts.slice(i).join('.');
        const result = await apiCall(
            'infoDnsZone',
            {
                customernumber: String(customerNumber),
                apikey: apiKey,
                apisessionid,
                domainname: candidate,
            },
            false, // don't throw – 5028/5029 means zone not found
        );

        // Only accept the zone if the response contains a name field matching the candidate.
        // An empty {} response (sometimes returned by Netcup for subdomains) must NOT be accepted.
        if (result !== null && typeof result === 'object' && result.name) {
            const hostname = parts.slice(0, i).join('.') || '@';
            log.warn(`[acme-dns-01-netcup] findZone: "${fullDomain}" → zone="${candidate}", hostname="${hostname}"`);
            return { rootDomain: candidate, hostname };
        }
    }

    // Fall back to last-two-labels heuristic
    const rootDomain = parts.slice(-2).join('.');
    const hostname = parts.slice(0, -2).join('.') || '@';
    log.warn(`[acme-dns-01-netcup] findZone: no zone found via API for "${fullDomain}", using fallback zone="${rootDomain}", hostname="${hostname}"`);
    return { rootDomain, hostname };
}

/**
 * Create an acme-dns-01-netcup challenge handler.
 */
export function create(options: NetcupOptions): {
    init: () => Promise<null>;
    set: (data: ChallengeData) => Promise<null>;
    get: (data: ChallengeData) => Promise<{ dnsAuthorization: string } | null>;
    remove: (data: ChallengeData) => Promise<null>;
    shutdown: () => void;
} {
    const { customerNumber, apiKey, apiPassword } = options;
    const log: Logger = options.log ?? noopLogger;

    if (!customerNumber || !apiKey || !apiPassword) {
        throw new Error('acme-dns-01-netcup: customerNumber, apiKey and apiPassword are all required');
    }

    log.warn(`[acme-dns-01-netcup] create() called, customerNumber="${customerNumber}"`);

    return {
        async init(): Promise<null> {
            return null;
        },

        async set(data: ChallengeData): Promise<null> {
            const { dnsHost, dnsAuthorization } = data.challenge;
            log.warn(`[acme-dns-01-netcup] set called, dnsHost="${dnsHost}" value="${dnsAuthorization}"`);

            let apisessionid: string;
            try {
                apisessionid = await login(customerNumber, apiKey, apiPassword);
            } catch (err) {
                log.error(`[acme-dns-01-netcup] set: login failed: ${err}`);
                throw err;
            }
            try {
                const { rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid, log);
                log.warn(`[acme-dns-01-netcup] set: creating TXT hostname="${hostname}" in zone="${rootDomain}"`);

                const setResult = await apiCall('updateDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                    dnsrecordset: {
                        dnsrecords: [
                            {
                                hostname,
                                type: 'TXT',
                                destination: dnsAuthorization,
                                deleterecord: false,
                            } satisfies DnsRecord,
                        ],
                    },
                });
                log.warn(`[acme-dns-01-netcup] set: updateDnsRecords response=${JSON.stringify(setResult)}`);
            } finally {
                await logout(customerNumber, apiKey, apisessionid!);
            }

            // Poll public DNS until the TXT record is resolvable.
            // acme.js does its own dns.resolveTxt() check immediately after set() returns,
            // so we must not return until the record is actually visible in DNS.
            const maxAttempts = 30;
            const retryDelayMs = 30_000; // 30 s per attempt → up to 15 min total
            log.warn(`[acme-dns-01-netcup] set: waiting for DNS propagation (polling every ${retryDelayMs / 1000}s, max ${maxAttempts} attempts)...`);

            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    const results = await publicResolver.resolveTxt(dnsHost); {
                        log.warn(`[acme-dns-01-netcup] set: DNS record confirmed after attempt ${attempt}/${maxAttempts}`);
                        return null;
                    }
                    log.warn(`[acme-dns-01-netcup] set: TXT not yet visible (attempt ${attempt}/${maxAttempts}), waiting...`);
                } catch (err: any) {
                    log.warn(`[acme-dns-01-netcup] set: DNS lookup failed (attempt ${attempt}/${maxAttempts}): ${err.code ?? err.message}, waiting...`);
                }
                await new Promise<void>(resolve => setTimeout(resolve, retryDelayMs));
            }

            throw new Error(`[acme-dns-01-netcup] DNS record "${dnsHost}" not visible after ${maxAttempts} attempts`);
        },

        async get(data: ChallengeData): Promise<{ dnsAuthorization: string } | null> {
            const { dnsHost, dnsAuthorization } = data.challenge;
            log.warn(`[acme-dns-01-netcup] get: checking dnsHost="${dnsHost}"`);
            // set() already waited for DNS propagation, so this is just a quick confirmation.
            try {
                const results = await publicResolver.resolveTxt(dnsHost);
                const found = results.flat().includes(dnsAuthorization);
                log.warn(`[acme-dns-01-netcup] get: found=${found}`);
                return found ? { dnsAuthorization } : null;
            } catch (err: any) {
                log.warn(`[acme-dns-01-netcup] get: DNS lookup failed: ${err.code ?? err.message}`);
                return null;
            }
        },

        async remove(data: ChallengeData): Promise<null> {
            const { dnsHost, dnsAuthorization } = data.challenge;
            log.warn(`[acme-dns-01-netcup] remove: dnsHost="${dnsHost}"`);

            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                const { rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid, log);
                // Use throwOnError=false: zone may have no records at all
                const recordsData = await apiCall(
                    'infoDnsRecords',
                    {
                        customernumber: String(customerNumber),
                        apikey: apiKey,
                        apisessionid,
                        domainname: rootDomain,
                    },
                    false,
                );

                const records: DnsRecord[] = recordsData?.dnsrecords ?? [];
                const toDelete = records
                    .filter(r => r.type === 'TXT' && r.hostname === hostname && r.destination === dnsAuthorization)
                    .map(r => ({ ...r, deleterecord: true }));

                if (toDelete.length === 0) {
                    return null;
                }

                await apiCall('updateDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                    dnsrecordset: { dnsrecords: toDelete },
                });
            } finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
            return null;
        },

        shutdown(): void {
            // no-op
        },
    };
}
