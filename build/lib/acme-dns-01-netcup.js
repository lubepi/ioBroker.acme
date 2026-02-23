'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.create = create;
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
/**
 * Send a JSON request to the Netcup CCP API.
 * @param throwOnError - if false, returns the raw response even on non-2xxx status (used by get/remove)
 */
async function apiCall(action, param, throwOnError = true) {
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
    let json;
    try {
        json = JSON.parse(rawText);
    }
    catch {
        throw new Error(`Netcup API returned non-JSON response: ${rawText.slice(0, 200)}`);
    }
    // Netcup uses 2xxx for success (2000 = OK, 2011 = object created/updated, etc.)
    const isSuccess = json.statuscode >= 2000 && json.statuscode < 3000;
    if (!isSuccess && throwOnError) {
        throw new Error(`Netcup API error [${json.statuscode}]: ${json.longmessage ?? json.shortmessage ?? 'unknown error'}`);
    }
    return isSuccess ? json.responsedata : null;
}
/**
 * Login and return the apisessionid.
 */
async function login(customerNumber, apiKey, apiPassword) {
    const data = await apiCall('login', {
        customernumber: String(customerNumber),
        apikey: apiKey,
        apipassword: apiPassword,
    });
    return data.apisessionid;
}
/**
 * Logout. Errors are swallowed intentionally (session may already be expired).
 */
async function logout(customerNumber, apiKey, apisessionid) {
    try {
        await apiCall('logout', {
            customernumber: String(customerNumber),
            apikey: apiKey,
            apisessionid,
        });
    }
    catch {
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
async function findZone(fullDomain, customerNumber, apiKey, apisessionid) {
    const parts = fullDomain.split('.');
    // Walk from most-specific (all parts minus the first) toward the apex
    for (let i = 1; i < parts.length - 1; i++) {
        const candidate = parts.slice(i).join('.');
        const result = await apiCall('infoDnsZone', {
            customernumber: String(customerNumber),
            apikey: apiKey,
            apisessionid,
            domainname: candidate,
        }, false);
        // Only accept the zone if the response contains a name field matching the candidate.
        // An empty {} response (sometimes returned by Netcup for subdomains) must NOT be accepted.
        if (result !== null && typeof result === 'object' && result.name) {
            const hostname = parts.slice(0, i).join('.') || '@';
            console.log(`[acme-dns-01-netcup] findZone: "${fullDomain}" → zone="${candidate}", hostname="${hostname}"`);
            return { rootDomain: candidate, hostname };
        }
    }
    // Fall back to last-two-labels heuristic
    const rootDomain = parts.slice(-2).join('.');
    const hostname = parts.slice(0, -2).join('.') || '@';
    console.warn(`[acme-dns-01-netcup] findZone: no zone found via API for "${fullDomain}", using fallback zone="${rootDomain}", hostname="${hostname}"`);
    return { rootDomain, hostname };
}
/**
 * Create an acme-dns-01-netcup challenge handler.
 */
function create(options) {
    const { customerNumber, apiKey, apiPassword } = options;
    if (!customerNumber || !apiKey || !apiPassword) {
        throw new Error('acme-dns-01-netcup: customerNumber, apiKey and apiPassword are all required');
    }
    return {
        // Default propagation delay of 30s; can be overridden via dns01PpropagationDelay in adapter config.
        propagationDelay: 30000,
        async init() {
            return null;
        },
        async set(data) {
            const { dnsHost, dnsAuthorization } = data.challenge;
            console.log(`[acme-dns-01-netcup] set called, full data: ${JSON.stringify(data)}`);
            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                const { rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid);
                console.log(`[acme-dns-01-netcup] set: creating TXT record hostname="${hostname}" in zone="${rootDomain}"`);
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
                            },
                        ],
                    },
                });
                console.log(`[acme-dns-01-netcup] set: TXT record created successfully`);
            }
            finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
            return null;
        },
        async get(data) {
            const { dnsHost, dnsAuthorization } = data.challenge;
            console.log(`[acme-dns-01-netcup] get: checking dnsHost="${dnsHost}"`);
            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                const { rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid);
                // Use throwOnError=false: error 5029 (no records) must return null, not throw
                const recordsData = await apiCall('infoDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                }, false);
                const records = recordsData?.dnsrecords ?? [];
                const found = records.find(r => r.type === 'TXT' && r.hostname === hostname && r.destination === dnsAuthorization);
                console.log(`[acme-dns-01-netcup] get: zone="${rootDomain}" hostname="${hostname}" found=${!!found} (${records.length} records total)`);
                return found ? { dnsAuthorization: found.destination } : null;
            }
            catch (err) {
                // Any unexpected error: treat as "record not visible yet"
                console.error(`[acme-dns-01-netcup] get: unexpected error (returning null): ${err}`);
                return null;
            }
            finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
        },
        async remove(data) {
            const { dnsHost, dnsAuthorization } = data.challenge;
            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                const { rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid);
                // Use throwOnError=false: zone may have no records at all
                const recordsData = await apiCall('infoDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                }, false);
                const records = recordsData?.dnsrecords ?? [];
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
            }
            finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
            return null;
        },
        shutdown() {
            // no-op
        },
    };
}
