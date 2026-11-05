// Loaded only into the disposable benchmark installation, with sandbox off.
// ALIX_BENCH_URLS and ALIX_BENCH_TIMEOUT are supplied by the host harness.
Components.utils.importGlobalProperties(["fetch"]);
let reportChain = Promise.resolve();
const emit = data => {
  const record = JSON.stringify(data);
  dump("ALIX_BENCH:" + record + "\n");
  reportChain = reportChain.then(() => fetch(ALIX_BENCH_COLLECTOR +
    "?data=" + encodeURIComponent(record), { credentials: "omit" }))
    .catch(error => dump("ALIX_BENCH_REPORT_ERROR:" + error + "\n"));
};
Services.io.getProtocolHandler("resource").QueryInterface(Ci.nsIResProtocolHandler)
  .setSubstitution("alixbench", Services.io.newURI("file:///tmp/zenbench/"));
ChromeUtils.registerWindowActor("AlixBench", {
  parent: { esModuleURI: "resource://alixbench/BenchParent.sys.mjs" },
  child: { esModuleURI: "resource://alixbench/BenchChild.sys.mjs",
           events: { MozAfterPaint: {}, DOMContentLoaded: {}, load: {} } },
  allFrames: false,
  safeForUntrustedWebProcess: true,
});
emit({ event: "autoconfig_ready" });
Services.obs.addObserver(function ready(window) {
  Services.obs.removeObserver(ready, "browser-delayed-startup-finished");
  emit({ event: "browser_ready" });
  const tab = window.gBrowser.addTab("about:blank", {
    triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
    skipAnimation: true,
  });
  window.gBrowser.selectedTab = tab;
  const browser = tab.linkedBrowser;
  let index = -1;
  let started = 0;
  let timer;
  let collecting = false;
  let loadStatus = null;
  Services.obs.addObserver((_, topic, payload) => {
    const data = JSON.parse(payload);
    if (index >= 0 && data.context === browser.browsingContext.id && data.time_origin >= started) {
      emit({ event: "paint", index, ...data });
    }
  }, "alix-benchmark-paint");
  async function collect(timedOut) {
    if (collecting || index < 0) return;
    collecting = true;
    window.clearTimeout(timer);
    let data;
    try {
      data = await Promise.race([
        browser.browsingContext.currentWindowGlobal.getActor("AlixBench").sendQuery("timings"),
        new Promise((_, reject) => window.setTimeout(() => reject(new Error("content timing query timeout")), 5000)),
      ]);
    } catch (error) {
      data = { error: String(error) };
    }
    // An initial about:blank load may stop after navigation has been queued,
    // while the real content process is still starting. Keep the hard deadline
    // and wait for the newly requested document instead of timing the old one.
    if (!timedOut &&
        (data.error || data.url === "about:blank" || data.state !== "complete" || data.time_origin < started)) {
      collecting = false;
      timer = window.setTimeout(() => collect(Date.now() - started >= ALIX_BENCH_TIMEOUT), 500);
      return;
    }
    emit({ event: "page", index, requested_url: ALIX_BENCH_URLS[index],
           guest_wall_ms: Date.now() - started, timed_out: timedOut,
           load_status: loadStatus, ...data });
    if (!timedOut && !data.error && !data.error_page) {
      for (let sample = 0; sample < ALIX_BENCH_INPUT_SAMPLES; sample++) {
        try {
          const actor = browser.browsingContext.currentWindowGlobal.getActor("AlixBench");
          window.focus();
          browser.focus();
          const ready = await actor.sendQuery("input_prepare", {
            sample, title: ALIX_BENCH_PAGE_TITLE || "Add Two Numbers",
            ...(ALIX_BENCH_NATIVE_INPUT ? { native_input: true, index } : {}),
          });
          if (!ready.supported) break;
          emit({ event: "input_ready", index, sample, expected: ready.expected,
                 selected_tab: window.gBrowser.selectedTab === tab,
                 visibility: ready.visibility, document_focused: ready.document_focused,
                 focused: ready.focused,
                 ...(ready.native_marker ? { native_marker: ready.native_marker } : {}) });
          const response = await actor.sendQuery("input_result");
          emit({ event: "input", index, sample, ...response,
                 selected_tab: window.gBrowser.selectedTab === tab });
          if (response.error) break;
        } catch (error) {
          emit({ event: "input", index, sample, error: String(error) });
          break;
        }
      }
    }
    if (ALIX_BENCH_SCROLLBAR && !timedOut && !data.error) {
      const actor = browser.browsingContext.currentWindowGlobal.getActor("AlixBench");
      const ready = await actor.sendQuery("scrollbar_prepare");
      emit({ event: "scrollbar_ready", index, ...ready });
      emit({ event: "scrollbar", index, ...await actor.sendQuery("scrollbar_result") });
    }
    window.setTimeout(next, 1000);
  }
  function next() {
    index++;
    if (index >= ALIX_BENCH_URLS.length) {
      if (ALIX_BENCH_PAGE_TITLE !== null) {
        // Exercise Gecko's native title setter with a controlled complete
        // string, independently of delayed tab-label updates during startup.
        window.docShell.treeOwner.QueryInterface(Ci.nsIBaseWindow).title = ALIX_BENCH_PAGE_TITLE;
        emit({ event: "native_title_set", title: ALIX_BENCH_PAGE_TITLE });
      }
      emit({ event: "complete" });
      return;
    }
    collecting = false;
    loadStatus = null;
    started = Date.now();
    emit({ event: "navigation", index, url: ALIX_BENCH_URLS[index] });
    timer = window.setTimeout(() => collect(true), ALIX_BENCH_TIMEOUT);
    browser.loadURI(Services.io.newURI(ALIX_BENCH_URLS[index]), {
      triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal(),
    });
  }
  window.__alixBenchListener = {
    QueryInterface: ChromeUtils.generateQI(["nsIWebProgressListener", "nsISupportsWeakReference"]),
    onStateChange(progress, request, flags, status) {
      if (index >= 0 && progress.isTopLevel &&
          (flags & Ci.nsIWebProgressListener.STATE_STOP) &&
          (flags & Ci.nsIWebProgressListener.STATE_IS_WINDOW) &&
          status !== Cr.NS_BINDING_ABORTED) {
        loadStatus = status;
        emit({ event: "load_stop", index, status });
        const completedIndex = index;
        window.setTimeout(() => { if (index === completedIndex) collect(false); }, 1000);
      }
    },
    onLocationChange() {}, onProgressChange() {}, onStatusChange() {}, onSecurityChange() {},
    onContentBlockingEvent() {},
  };
  browser.addProgressListener(window.__alixBenchListener, Ci.nsIWebProgress.NOTIFY_STATE_WINDOW);
  window.setTimeout(next, 1000);
}, "browser-delayed-startup-finished");
