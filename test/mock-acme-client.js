const Module = require('node:module');

const originalLoad = Module._load;

function patchAcmeExports(acme) {
    if (!acme || acme.__acmeMockPatched) {
        return acme;
    }

    // Replace networked ACME client methods with deterministic local stubs for integration tests.
    acme.Client = class MockAcmeClient {
        async createAccount() {
            return {
                url: 'https://example.invalid/acme/account/1',
            };
        }

        async createOrder() {
            throw new Error('MOCK_ACME_CREATE_ORDER_STOP');
        }

        async waitForValidStatus(order) {
            return order;
        }

        async getCertificate() {
            throw new Error('MOCK_ACME_GET_CERTIFICATE_STOP');
        }

        async auto() {
            throw new Error('MOCK_ACME_AUTO_STOP');
        }
    };

    Object.defineProperty(acme, '__acmeMockPatched', {
        value: true,
        enumerable: false,
        configurable: false,
    });

    return acme;
}

Module._load = function patchedLoad(request, parent, isMain) {
    const loaded = originalLoad.call(this, request, parent, isMain);
    if (request === 'acme-client') {
        return patchAcmeExports(loaded);
    }
    return loaded;
};
