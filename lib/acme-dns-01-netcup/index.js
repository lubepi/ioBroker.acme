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
 *   For ccSLDs like .co.uk you would have to carry the public-suffix list.
 *   All common Netcup domains use single-label TLDs, so this is sufficient.
 */

const API_ENDPOINT = 'https://ccp.netcup.net/run/webservice/servers/endpoint.php';

/**
 * Send a JSON request to the Netcup CCP API.
 * @param {string} action
 * @param {Record<string, unknown>} param
 * @returns {Promise<unknown>} responsedata field of the response
 */
async function apiCall(action, param) {
    const body = JSON.stringify({ action, param });

    const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
    });

    if (!response.ok) {
        throw new Error(`Netcup HTTP error: ${response.status} ${response.statusText}`);
    }

    const json = await response.json();

    // Netcup uses statuscode 2000 for success
    if (json.statuscode !== 2000) {
        throw new Error(
            `Netcup API error [${json.statuscode}]: ${json.longmessage || json.shortmessage || 'unknown error'}`,
        );
    }

    return json.responsedata;
}

/**
 * Login and return the apisessionid.
 * @param {string|number} customerNumber
 * @param {string} apiKey
 * @param {string} apiPassword
 * @returns {Promise<string>}
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
 * @param {string|number} customerNumber
 * @param {string} apiKey
 * @param {string} apisessionid
 */
async function logout(customerNumber, apiKey, apisessionid) {
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
 * @param {string} fullDomain
 * @returns {{ rootDomain: string; hostname: string }}
 */
function splitDomain(fullDomain) {
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
 *
 * @param {{ customerNumber: string|number; apiKey: string; apiPassword: string }} options
 */
module.exports.create = function create(options) {
    const { customerNumber, apiKey, apiPassword } = options;

    if (!customerNumber || !apiKey || !apiPassword) {
        throw new Error('acme-dns-01-netcup: customerNumber, apiKey and apiPassword are all required');
    }

    return {
        /**
         * Called once by the ACME client before any challenges.
         * @returns {Promise<null>}
         */
        async init() {
            return null;
        },

        /**
         * Create the DNS TXT record for the challenge.
         * @param {{ challenge: { dnsHost: string; dnsAuthorization: string } }} data
         * @returns {Promise<null>}
         */
        async set(data) {
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
                            },
                        ],
                    },
                });
            } finally {
                await logout(customerNumber, apiKey, apisessionid);
            }

            return null;
        },

        /**
         * Check whether the TXT record is already visible (used for propagation check).
         * @param {{ challenge: { dnsHost: string; dnsAuthorization: string } }} data
         * @returns {Promise<{ dnsAuthorization: string }|null>}
         */
        async get(data) {
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

                const records = recordsData?.dnsrecords ?? [];
                const found = records.find(
                    r => r.type === 'TXT' && r.hostname === hostname && r.destination === dnsAuthorization,
                );
                return found ? { dnsAuthorization: found.destination } : null;
            } finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
        },

        /**
         * Delete the DNS TXT record after the challenge has been verified.
         * @param {{ challenge: { dnsHost: string; dnsAuthorization: string } }} data
         * @returns {Promise<null>}
         */
        async remove(data) {
            const { dnsHost, dnsAuthorization } = data.challenge;
            const { rootDomain, hostname } = splitDomain(dnsHost);

            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                // First fetch existing records so we have the record ID
                const recordsData = await apiCall('infoDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                });

                const records = recordsData?.dnsrecords ?? [];
                const toDelete = records
                    .filter(r => r.type === 'TXT' && r.hostname === hostname && r.destination === dnsAuthorization)
                    .map(r => ({ ...r, deleterecord: true }));

                if (toDelete.length === 0) {
                    // Record already gone – nothing to do
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

        /**
         * Called by the adapter during shutdown – nothing to clean up here.
         */
        shutdown() {
            // no-op
        },
    };
};
