'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.create = create;
const promises_1 = require("node:dns/promises");
// Fallback public resolvers (used by get() for quick confirmation check).
const publicResolver = new promises_1.Resolver();
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
const noopLogger = {
    warn: (msg) => console.warn(msg),
    error: (msg) => console.error(msg),
    debug: (msg) => console.log(msg),
};
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
async function findZone(fullDomain, customerNumber, apiKey, apisessionid, log) {
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
function create(options) {
    const { customerNumber, apiKey, apiPassword } = options;
    const log = options.log ?? noopLogger;
    if (!customerNumber || !apiKey || !apiPassword) {
        throw new Error('acme-dns-01-netcup: customerNumber, apiKey and apiPassword are all required');
    }
    log.warn(`[acme-dns-01-netcup] create() called, customerNumber="${customerNumber}"`);
    return {
        async init() {
            return null;
        },
        async set(data) {
            const { dnsHost, dnsAuthorization } = data.challenge;
            log.warn(`[acme-dns-01-netcup] set called, dnsHost="${dnsHost}" value="${dnsAuthorization}"`);
            // Step 1: Create the TXT record via Netcup API
            let rootDomain;
            let hostname;
            let apisessionid;
            try {
                apisessionid = await login(customerNumber, apiKey, apiPassword);
            }
            catch (err) {
                log.error(`[acme-dns-01-netcup] set: login failed: ${err}`);
                throw err;
            }
            try {
                ({ rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid, log));
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
                            },
                        ],
                    },
                });
                log.warn(`[acme-dns-01-netcup] set: updateDnsRecords response=${JSON.stringify(setResult)}`);
            }
            finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
            // Step 2: Poll the authoritative NS servers directly until the TXT record appears.
            // We look up the NS servers for rootDomain, then query them directly every 10 s.
            // This is more reliable than trusting the Netcup API state field, because "state=yes"
            // seems to mean "internally processed" but the NS may still need a few extra seconds.
            // Netcup serialises zone updates: if a remove() preceded this set(), the zone
            // update queue may already contain one pending update (~4–5 min), which means
            // our record is processed only after that — requiring up to ~10 min total.
            // Use 120 attempts × 10 s = 20 min to safely cover two consecutive zone updates.
            const maxAttempts = 120;
            const retryDelayMs = 10000; // 10 s per attempt → up to 20 min total
            // Build a resolver that queries Netcup's authoritative NS servers for rootDomain.
            let authResolver;
            try {
                const nsNames = await publicResolver.resolveNs(rootDomain);
                const nsIps = [];
                for (const ns of nsNames) {
                    try {
                        const ips = await publicResolver.resolve4(ns);
                        nsIps.push(...ips);
                    }
                    catch {
                        // ignore single NS lookup failures
                    }
                }
                if (nsIps.length === 0)
                    throw new Error('no NS IPs found');
                authResolver = new promises_1.Resolver();
                authResolver.setServers(nsIps.map(ip => `${ip}:53`));
                log.warn(`[acme-dns-01-netcup] set: authoritative NS for ${rootDomain}: ${nsIps.join(', ')}`);
            }
            catch (err) {
                log.warn(`[acme-dns-01-netcup] set: NS lookup failed (${err}), falling back to public resolvers`);
                authResolver = publicResolver;
            }
            log.warn(`[acme-dns-01-netcup] set: polling authoritative NS for TXT record (every ${retryDelayMs / 1000}s, max ${maxAttempts} attempts = ${maxAttempts * retryDelayMs / 60000} min)...`);
            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                await new Promise(resolve => setTimeout(resolve, retryDelayMs));
                try {
                    const results = await authResolver.resolveTxt(dnsHost);
                    const found = results.flat().includes(dnsAuthorization);
                    log.debug(`[acme-dns-01-netcup] set: TXT lookup attempt ${attempt}/${maxAttempts}: found=${found}`);
                    if (found) {
                        log.warn(`[acme-dns-01-netcup] set: TXT record confirmed on authoritative NS after attempt ${attempt}/${maxAttempts}`);
                        return null;
                    }
                }
                catch (err) {
                    // ENOTFOUND / ENODATA = record not yet visible, keep polling
                    log.debug(`[acme-dns-01-netcup] set: TXT lookup attempt ${attempt}/${maxAttempts}: ${err.code ?? err.message}`);
                }
            }
            throw new Error(`[acme-dns-01-netcup] TXT record "${dnsHost}" not visible on authoritative NS after ${maxAttempts} attempts (${maxAttempts * retryDelayMs / 60000} min)`);
        },
        async get(data) {
            const { dnsHost, dnsAuthorization } = data.challenge;
            log.warn(`[acme-dns-01-netcup] get: checking dnsHost="${dnsHost}"`);
            // set() already waited for DNS propagation, so this is just a quick confirmation.
            try {
                const results = await publicResolver.resolveTxt(dnsHost);
                const found = results.flat().includes(dnsAuthorization);
                log.warn(`[acme-dns-01-netcup] get: found=${found}`);
                return found ? { dnsAuthorization } : null;
            }
            catch (err) {
                log.warn(`[acme-dns-01-netcup] get: DNS lookup failed: ${err.code ?? err.message}`);
                return null;
            }
        },
        async remove(data) {
            const { dnsHost, dnsAuthorization } = data.challenge;
            log.warn(`[acme-dns-01-netcup] remove: dnsHost="${dnsHost}"`);
            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                const { rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid, log);
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
