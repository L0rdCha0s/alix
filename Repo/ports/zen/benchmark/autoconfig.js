// Loaded only into the disposable benchmark installation, with sandbox off.
// ALIX_BENCH_URLS and ALIX_BENCH_TIMEOUT are supplied by the host harness.
Components.utils.importGlobalProperties(["fetch"]);
if (ALIX_BENCH_MEDIA_LOCAL_DECODE) {
  Services.prefs.setBoolPref("media.allow-audio-non-utility", true);
}
if (ALIX_BENCH_MEDIA_DISABLE_AV1) {
  Services.prefs.setBoolPref("media.av1.enabled", false);
}
if (ALIX_BENCH_MEDIA_DECODER_LOGS) {
  Services.prefs.setIntPref("logging.PlatformDecoderModule", 5);
  Services.prefs.setIntPref("logging.FFmpegVideo", 4);
  Services.prefs.setIntPref("logging.MediaDecoder", 4);
}
Services.env.set("ALIX_SWGL_DIAGNOSTICS", "1");
Services.env.set("ALIX_SWGL_MASK_CACHE_READBACK", "1");
if (typeof ALIX_BENCH_SWGL_MASK_CACHE === "string" && ALIX_BENCH_SWGL_MASK_CACHE !== "default") {
  Services.env.set("ALIX_SWGL_MASK_CACHE", ALIX_BENCH_SWGL_MASK_CACHE === "enabled" ? "1" : "0");
}
if (ALIX_BENCH_PRESENT_DIAGNOSTICS) {
  Services.env.set("ALIX_PRESENT_DIAGNOSTICS", "1");
}
if (ALIX_BENCH_GC_PROFILE_MS) {
  Services.env.set("JS_GC_PROFILE", ALIX_BENCH_GC_PROFILE_MS + ",main");
  Services.env.set("JS_GC_PROFILE_FILE", "/tmp/zenbench/gc-profile.log");
  if (ALIX_BENCH_GC_DETAIL) Services.env.set("MOZ_GCTIMER", "/tmp/zenbench/gc-detail.log");
}
if (ALIX_BENCH_SWGL_POLICY !== "default") {
  Services.env.set("ALIX_SWGL_FORCE_FULL_REDRAW", ALIX_BENCH_SWGL_POLICY === "full" ? "1" : "0");
}
let reportChain = Promise.resolve();
const emit = data => {
  const record = JSON.stringify(data);
  dump("ALIX_BENCH:" + record + "\n");
  reportChain = reportChain.then(() => fetch(ALIX_BENCH_COLLECTOR +
    "?data=" + encodeURIComponent(record), { credentials: "omit" }))
    .catch(error => dump("ALIX_BENCH_REPORT_ERROR:" + error + "\n"));
  return reportChain;
};
const startupEffects = {
  mode: ALIX_BENCH_STARTUP_EFFECTS,
  version: Services.appinfo.version,
  build_id: Services.appinfo.appBuildID,
  previous_version: Services.prefs.getStringPref("zen.updates.last-version", ""),
  previous_build_id: Services.prefs.getStringPref("zen.updates.last-build-id", ""),
};
if (ALIX_BENCH_STARTUP_EFFECTS === "quiescent") {
  Services.prefs.setStringPref("zen.updates.last-version", startupEffects.version);
  Services.prefs.setStringPref("zen.updates.last-build-id", startupEffects.build_id);
}
emit({ event: "startup_effects", ...startupEffects,
  current_version: Services.prefs.getStringPref("zen.updates.last-version", ""),
  current_build_id: Services.prefs.getStringPref("zen.updates.last-build-id", ""),
});
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
  let previousDocumentId = null;
  let timer;
  let collecting = false;
  let loadStatus = null;
  const currentDocument = data => !!data.document_id && data.document_id !== previousDocumentId &&
    data.document_id === String(browser.browsingContext.currentWindowGlobal?.innerWindowId);
  if (ALIX_BENCH_MEDIA_NETWORK_DIAGNOSTICS) {
    const requests = new Map();
    const read = getter => { try { return getter(); } catch (_) { return null; } };
    for (const topic of ["http-on-modify-request", "http-on-examine-response", "http-on-stop-request"]) {
      Services.obs.addObserver(subject => {
        try {
          const channel = subject.QueryInterface(Ci.nsIHttpChannel);
          const host = channel.URI.host, path = channel.URI.pathQueryRef.split("?")[0];
          if (index < 0 || !(host.endsWith(".googlevideo.com") ||
              (host === "www.youtube.com" && path === "/youtubei/v1/player"))) return;
          const id = String(channel.channelId), now = window.performance.now();
          const query = new window.URL(channel.URI.spec).searchParams;
          if (topic === "http-on-modify-request") requests.set(id, now);
          emit({ event: "media_network", index, phase: topic, channel_id: id, host, path,
            method: channel.requestMethod, chrome_ms: now,
            format_id: query.get("itag"), format_mime: query.get("mime"), query_range: query.get("range"),
            elapsed_ms: requests.has(id) ? now - requests.get(id) : null,
            status: read(() => channel.responseStatus),
            result: read(() => "0x" + (channel.status >>> 0).toString(16)),
            content_type: read(() => channel.getResponseHeader("Content-Type")),
            content_length: read(() => channel.contentLength),
            content_range: read(() => channel.getResponseHeader("Content-Range")),
            request_range: read(() => channel.getRequestHeader("Range")),
            transfer_bytes: read(() => channel.transferSize),
            body_bytes: read(() => channel.encodedBodySize) });
          if (topic === "http-on-stop-request") requests.delete(id);
        } catch (error) { emit({ event: "media_network", index, phase: topic, error: String(error) }); }
      }, topic);
    }
  }
  const chromeVisualState = () => {
    const sweep = window.document.getElementById("zen-update-animation");
    const border = window.document.getElementById("zen-update-animation-border");
    return { update_sweep_present: !!sweep, update_border_present: !!border,
      sweep_inline_style: sweep?.getAttribute("style") || "",
      border_inline_style: border?.getAttribute("style") || "" };
  };
  const wrapper = window.document.getElementById("zen-main-app-wrapper");
  if (!wrapper) throw new Error("missing native Zen chrome wrapper");
  const chromeObserver = new window.MutationObserver(mutations => {
    if (mutations.some(record => [...record.addedNodes, ...record.removedNodes]
      .some(node => node.id === "zen-update-animation" || node.id === "zen-update-animation-border"))) {
      emit({ event: "chrome_effect", index, guest_wall_ms: Date.now(), ...chromeVisualState() });
    }
  });
  chromeObserver.observe(wrapper, { childList: true });
  emit({ event: "chrome_effect", index, guest_wall_ms: Date.now(), ...chromeVisualState() });
  Services.obs.addObserver((_, topic, payload) => {
    const data = JSON.parse(payload);
    if (index >= 0 && data.context === browser.browsingContext.id && currentDocument(data)) {
      emit({ event: "paint", index, ...data });
    }
  }, "alix-benchmark-paint");
  Services.obs.addObserver((_, topic, payload) => {
    const data = JSON.parse(payload);
    if (index >= 0 && data.context === browser.browsingContext.id && currentDocument(data))
      emit({ event: "media_progress", index, ...data });
  }, "alix-benchmark-media-progress");
  Services.obs.addObserver((_, topic, payload) => {
    const data = JSON.parse(payload);
    if (index >= 0 && data.context === browser.browsingContext.id && currentDocument(data))
      emit({ event: "media_debug", index, ...data });
  }, "alix-benchmark-media-debug");
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
        (data.error || data.url === "about:blank" || data.state !== "complete" || !currentDocument(data))) {
      collecting = false;
      timer = window.setTimeout(() => collect(Date.now() - started >= ALIX_BENCH_TIMEOUT), 500);
      return;
    }
    emit({ event: "page", index, requested_url: ALIX_BENCH_URLS[index],
           guest_wall_ms: Date.now() - started, timed_out: timedOut,
           guest_started_wall_ms: started, previous_document_id: previousDocumentId,
           origin_minus_request_ms: data.time_origin - started,
           load_status: loadStatus, ...data });
    if (ALIX_BENCH_MEDIA_DIAGNOSTICS && !timedOut && !data.error && !data.error_page) {
      try {
        const result = await browser.browsingContext.currentWindowGlobal.getActor("AlixBench").sendQuery("media_capabilities");
        const prefs = {};
        for (const name of ["media.rdd-process.enabled", "media.utility-process.enabled",
          "media.allow-audio-non-utility", "media.av1.enabled", "media.ffmpeg.enabled",
          "media.mediasource.enabled", "media.mediasource.webm.enabled"]) {
          try { prefs[name] = Services.prefs.getBoolPref(name); } catch (_) { prefs[name] = null; }
        }
        await emit({ event: "media_capabilities", index, prefs, ...result });
      } catch (error) { await emit({ event: "media_capabilities", index, error: String(error) }); }
    }
    if (ALIX_BENCH_MEDIA_FIXTURE && !timedOut && !data.error && !data.error_page) {
      try {
        const ready = await browser.browsingContext.currentWindowGlobal.getActor("AlixBench").sendQuery("media_prepare",
          { url: ALIX_BENCH_MEDIA_FIXTURE, mse: ALIX_BENCH_MEDIA_MSE, displayWidth: ALIX_BENCH_MEDIA_DISPLAY_WIDTH });
        await emit({ event: "media_prepared", index, ...ready });
      } catch (error) { await emit({ event: "media_prepared", index, error: String(error) }); }
    }
    if (ALIX_BENCH_MEDIA_LIVE && !timedOut && !data.error && !data.error_page) {
      try {
        window.focus();
        browser.focus();
        for (let attempt = 0; attempt < 3; attempt++) {
          const actor = browser.browsingContext.currentWindowGlobal.getActor("AlixBench");
          const ready = await actor.sendQuery("media_live_prepare", { attempt });
          await emit({ event: "media_live_ready", index, ...ready });
          const status = await actor.sendQuery("media_start_status");
          await emit({ event: "media_start_status", index, attempt, ...status });
          // Retry only a player that never started. Keep its original frame
          // counters and trusted-input history; no playback losses are reset.
          if (!status.paused || status.current_time > 0 || status.frames > 0) break;
        }
      } catch (error) { await emit({ event: "media_live_ready", index, error: String(error) }); }
    }
    if (!ALIX_BENCH_MEDIA_LIVE && !timedOut && !data.error && !data.error_page) {
      for (let sample = 0; sample < ALIX_BENCH_INPUT_SAMPLES; sample++) {
        try {
          const actor = browser.browsingContext.currentWindowGlobal.getActor("AlixBench");
          window.focus();
          browser.focus();
          const clockBefore = ALIX_BENCH_INPUT_CLOCK_SYNC ?
            await actor.sendQuery("clock_sync", { url: ALIX_BENCH_CLOCK_URL }) : null;
          const ready = await actor.sendQuery("input_prepare", {
            sample, title: ALIX_BENCH_PAGE_TITLE || "Add Two Numbers",
            ...(ALIX_BENCH_NATIVE_INPUT ? { native_input: true, index } : {}),
          });
          if (!ready.supported) break;
          emit({ event: "input_ready", index, sample, expected: ready.expected,
                 chrome_visual_state: chromeVisualState(),
                 selected_tab: window.gBrowser.selectedTab === tab,
                 visibility: ready.visibility, document_focused: ready.document_focused,
                 focused: ready.focused,
                 ...(ready.corner_fixture ? { corner_fixture: ready.corner_fixture } : {}),
                 ...(ready.native_marker ? { native_marker: ready.native_marker,
                   native_response_marker: ready.native_response_marker } : {}) });
          const response = await actor.sendQuery("input_result");
          const clockAfter = ALIX_BENCH_INPUT_CLOCK_SYNC ?
            await actor.sendQuery("clock_sync", { url: ALIX_BENCH_CLOCK_URL }) : null;
          await emit({ event: "input", index, sample, ...response,
                 chrome_visual_state: chromeVisualState(),
                 ...(clockBefore ? { clock_before: clockBefore, clock_after: clockAfter } : {}),
                 selected_tab: window.gBrowser.selectedTab === tab });
          if (response.error) break;
        } catch (error) {
          emit({ event: "input", index, sample, error: String(error) });
          break;
        }
      }
    }
    if ((ALIX_BENCH_MEDIA_FIXTURE || ALIX_BENCH_MEDIA_LIVE) && !timedOut && !data.error && !data.error_page) {
      try {
        const result = await browser.browsingContext.currentWindowGlobal.getActor("AlixBench").sendQuery("media_playback",
          { observeSeconds: ALIX_BENCH_MEDIA_OBSERVE_SECONDS, debugSnapshots: ALIX_BENCH_MEDIA_DEBUG_SNAPSHOTS });
        if (ALIX_BENCH_GC_PROFILE_MS) {
          const files = [["gc-profile.log", "gc_profile_chunk"]];
          if (ALIX_BENCH_GC_DETAIL) files.push(["gc-detail.log", "gc_detail_chunk"]);
          for (const [path, event] of files) {
            try {
              const bytes = await window.IOUtils.read("/tmp/zenbench/" + path, { maxBytes: 131072 });
              let text = "";
              for (const line of new window.TextDecoder().decode(bytes).split("\n")) {
                if (!line) continue;
                const bounded = line.slice(0, 4095) + "\n";
                if (text.length + bounded.length > 4096) {
                  await emit({ event, index, text });
                  text = "";
                }
                text += bounded;
              }
              if (text) await emit({ event, index, text });
            } catch (error) { await emit({ event: "gc_profile_error", index, path, error: String(error) }); }
          }
        }
        await emit({ event: "media_playback", index, ...result });
        if (!ALIX_BENCH_MEDIA_DEBUG_SNAPSHOTS) {
          try {
            const info = await browser.browsingContext.currentWindowGlobal.getActor("AlixBench").sendQuery("media_debug");
            await emit({ event: "media_debug", index, ...info });
          } catch (error) { await emit({ event: "media_debug", index, error: String(error) }); }
        }
      } catch (error) { await emit({ event: "media_playback", index, error: String(error) }); }
    }
    if (ALIX_BENCH_DIAGNOSTICS && !timedOut && !data.error && !data.error_page) {
      try {
        const actor = browser.browsingContext.currentWindowGlobal.getActor("AlixBench");
        const started = Date.now();
        const diagnostics = await actor.sendQuery("diagnostics", { samples: ALIX_BENCH_DIAGNOSTIC_SAMPLES });
        await emit({ event: "diagnostics", index, parent_elapsed_ms: Date.now() - started, ...diagnostics });
      } catch (error) {
        await emit({ event: "diagnostics", index, error: String(error) });
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
      emit({ event: "chrome_effect", index, guest_wall_ms: Date.now(), ...chromeVisualState() });
      chromeObserver.disconnect();
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
    previousDocumentId = String(browser.browsingContext.currentWindowGlobal?.innerWindowId);
    emit({ event: "navigation", index, url: ALIX_BENCH_URLS[index],
      guest_started_wall_ms: started, previous_document_id: previousDocumentId });
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
  if (ALIX_BENCH_RENAME_PROBE) {
    // This configuration exists only in the disposable clone. Move an
    // untouched payload, let the host observe its committed unloaded extent,
    // then restore the name before starting navigation measurements.
    (async () => {
      try {
        const source = ALIX_BENCH_RENAME_PROBE;
        const moved = source + ".alixbench-moved";
        await window.IOUtils.move(source, moved, { noOverwrite: true });
        await emit({ event: "rename_probe_moved", source, moved });
        await window.IOUtils.move(moved, source, { noOverwrite: true });
        await emit({ event: "rename_probe_restored", source });
        window.setTimeout(next, 1000);
      } catch (error) {
        await emit({ event: "rename_probe_error", error: String(error) });
      }
    })();
  } else window.setTimeout(next, 1000);
}, "browser-delayed-startup-finished");
