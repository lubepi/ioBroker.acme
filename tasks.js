const fs = require('fs');
const { deleteFoldersRecursive, buildReact, copyFiles, npmInstall } = require('@iobroker/build-tools');

const FEDERATION_NAME = 'ConfigCustomAcmeSet';

function buildAdmin() {
    return buildReact(`${__dirname}/src-admin/`, { rootDir: `${__dirname}/src-admin/`, vite: true });
}

function cleanAdmin() {
    deleteFoldersRecursive(`${__dirname}/admin/custom`);
    deleteFoldersRecursive(`${__dirname}/src-admin/build`);
}

/**
 * Patch customComponents.js to work as a classic script (type="text/javascript").
 *
 * @module-federation/vite generates ES-module output with:
 *   - export{X as get,Y as init}  → invalid in classic script context
 *   - import.meta.url             → invalid in classic script context
 *
 * ioBroker Admin loads custom components via <script type="text/javascript">, so
 * we convert the entry point to a self-contained IIFE-compatible file that sets
 * window["ConfigCustomAcmeSet"] = {get, init}.
 */
function patchCustomComponents() {
    const file = `${__dirname}/admin/custom/customComponents.js`;
    let content = fs.readFileSync(file, 'utf8');

    // 1. Capture the script's own URL at top-level execution time (before any async code).
    //    document.currentScript is only valid synchronously during script execution,
    //    so we store it in a variable that all lazy loaders can close over.
    const urlCapture =
        'var __mf_scriptUrl=' +
        '(typeof document!=="undefined"&&document.currentScript&&document.currentScript.src)' +
        '||(typeof __filename!=="undefined"?__filename:"");';
    content = urlCapture + '\n' + content;

    // 2. Replace all import.meta.url references with the captured variable.
    content = content.replace(/import\.meta\.url/g, '__mf_scriptUrl');

    // 3. Replace ES-module export with a window global assignment so the file
    //    works when loaded as a classic <script> tag.
    content = content.replace(
        /export\{(\w+) as get,(\w+) as init\};?\s*$/,
        `window["${FEDERATION_NAME}"]={get:$1,init:$2};`,
    );

    fs.writeFileSync(file, content);
    console.log(`Patched ${file} for classic-script compatibility`);
}

function copyAllAdminFiles() {
    copyFiles(
        ['src-admin/build/**/*', '!src-admin/build/index.html', '!src-admin/build/mf-manifest.json'],
        'admin/custom/',
    );
    copyFiles(['src-admin/src/i18n/*.json'], 'admin/custom/i18n');
}

if (process.argv.includes('--admin-0-clean')) {
    cleanAdmin();
} else if (process.argv.includes('--admin-1-npm')) {
    npmInstall(`${__dirname}/src-admin/`).catch(e => console.error(e));
} else if (process.argv.includes('--admin-2-compile')) {
    buildAdmin().catch(e => console.error(e));
} else if (process.argv.includes('--admin-3-copy')) {
    copyAllAdminFiles();
    patchCustomComponents();
} else {
    cleanAdmin();
    npmInstall(`${__dirname}/src-admin/`)
        .then(() => buildAdmin())
        .then(() => copyAllAdminFiles())
        .then(() => patchCustomComponents())
        .catch(e => console.error(e));
}
