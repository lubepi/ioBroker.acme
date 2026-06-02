
const __mfCacheGlobalKey = "__mf_module_cache__";
globalThis[__mfCacheGlobalKey] ||= { share: {}, remote: {} };
globalThis[__mfCacheGlobalKey].share ||= {};
globalThis[__mfCacheGlobalKey].remote ||= {};
const __mfModuleCache = globalThis[__mfCacheGlobalKey];

const __mfImport = (src) =>
  globalThis.System && typeof globalThis.System.import === 'function'
    ? globalThis.System.import(src)
    : import(src);


(async () => {
  const { initHost } = await __mfImport("./assets/hostInit-e2PfyX9f.js");
  await initHost();
})().then(() => __mfImport("./assets/index-C97zkeEd.js"));
