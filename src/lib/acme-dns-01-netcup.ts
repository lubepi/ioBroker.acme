'use strict';

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

interface NetcupOptions {
    customerNumber: string | number;
    apiKey: string;
    apiPassword: string;
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
 */
async function apiCall(action: string, param: Record<string, unknown>): Promise<any> {
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

    // Netcup uses statuscode 2000 for success
    if (json.statuscode !== 2000) {
        throw new Error(
            `Netcup API error [${json.statuscode}]: ${json.longmessage ?? json.shortmessage ?? 'unknown error'}`,
        );
    }

    return json.responsedata;
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
 * Split a full DNS name like "_acme-challenge.sub.example.com" into
 * { rootDomain: 'example.com', hostname: '_acme-challenge.sub' }.
 */
function splitDomain(fullDomain: string): { rootDomain: string; hostname: string } {
    const parts = fullDomain.split('.');
    if (parts.length < 2) {
        throw new Error(`Cannot split domain: ${fullDomain}`);
    }
    const rootDomain = parts.slice(-2).join('.');
    const hostname = parts.slice(0, -2).join('.') || '@';
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

    if (!customerNumber || !apiKey || !apiPassword) {
        throw new Error('acme-dns-01-netcup: customerNumber, apiKey and apiPassword are all required');
    }

    return {
        async init(): Promise<null> {
            return null;
        },

        async set(data: ChallengeData): Promise<null> {
            const { dnsHost, dnsAuthorization } = data.challenge;
            const { rootDomain, hostname } = splitDomain(dnsHost);

            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                await apiCall('updateDnsRecords', {
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
            } finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
            return null;
        },

        async get(data: ChallengeData): Promise<{ dnsAuthorization: string } | null> {
            const { dnsHost, dnsAuthorization } = data.challenge;
            const { rootDomain, hostname } = splitDomain(dnsHost);

            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                const recordsData = await apiCall('infoDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                });

                const records: DnsRecord[] = recordsData?.dnsrecords ?? [];
                const found = records.find(
                    r => r.type === 'TXT' && r.hostname === hostname && r.destination === dnsAuthorization,
                );
                return found ? { dnsAuthorization: found.destination } : null;
            } finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
        },

        async remove(data: ChallengeData): Promise<null> {
            const { dnsHost, dnsAuthorization } = data.challenge;
            const { rootDomain, hostname } = splitDomain(dnsHost);

            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                const recordsData = await apiCall('infoDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                });

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
