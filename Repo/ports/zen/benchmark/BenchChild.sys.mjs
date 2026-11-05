export class AlixBenchChild extends JSWindowActorChild {
  handleEvent() {
    if (this._reportedPaint) return;
    const performance = this.contentWindow.performance;
    const paint = performance.getEntriesByType("paint").find(x => x.name === "first-contentful-paint");
    if (!paint) return;
    this._reportedPaint = true;
    this.sendAsyncMessage("paint", {
      url: this.contentWindow.location.href,
      milliseconds: paint.startTime,
      time_origin: performance.timeOrigin,
    });
  }
  receiveMessage(message) {
    const window = this.contentWindow;
    const performance = window.performance;
    if (message.name === "input_prepare") {
      const document = window.document;
      const button = document.getElementById("addBtn");
      const a = document.getElementById("a");
      const result = document.getElementById("result");
      if (!button || !a || !result || document.title !== (message.data.title || "Add Two Numbers")) return { supported: false };
      const expected = "Result: " + (message.data.sample + 13);
      a.value = String(message.data.sample + 11);
      let nativeMarker;
      if (message.data.native_input) {
        let marker = document.getElementById("alix-native-input-marker");
        if (!marker) {
          marker = document.createElement("canvas");
          marker.id = "alix-native-input-marker";
          marker.width = marker.height = 8;
          marker.setAttribute("aria-hidden", "true");
          marker.style.cssText = "all:initial;position:fixed;top:16px;right:16px;" +
            "width:8px;height:8px;display:block;z-index:2147483647;pointer-events:none;" +
            "user-select:none;contain:strict;image-rendering:pixelated";
          document.documentElement.appendChild(marker);
        }
        // Four distinct opaque colors, changed for every sample/navigation.
        // A previous frame's marker cannot satisfy the next readiness gate.
        const serial = message.data.index * 20 + message.data.sample + 1;
        const colors = [
          [(29 + serial * 37) % 256, 17, 211],
          [227, (43 + serial * 53) % 256, 31],
          [41, 199, (67 + serial * 71) % 256],
          [(113 + serial * 97) % 256, 23, 173],
        ];
        const context = marker.getContext("2d");
        for (let quadrant = 0; quadrant < 4; quadrant++) {
          context.fillStyle = "rgb(" + colors[quadrant].join(",") + ")";
          context.fillRect((quadrant % 2) * 4, Math.floor(quadrant / 2) * 4, 4, 4);
        }
        nativeMarker = { width: 8, height: 8, quadrant_rgb: colors,
          device_pixel_ratio: window.devicePixelRatio, inset_css_pixels: 16 };
      }
      this._inputResult = null;
      this._inputPromise = new Promise(resolve => {
        let received = null;
        let lastKey = null;
        const keydown = event => {
          lastKey = { key: event.key, trusted: event.isTrusted };
          if (event.key === "Enter" && event.isTrusted) received = performance.now();
        };
        const paint = () => {
          if (received === null || result.textContent !== expected) return;
          finish({ trusted: true, expected, actual: result.textContent,
                   event_to_paint_ms: performance.now() - received });
        };
        const finish = data => {
          window.clearTimeout(timeout);
          button.removeEventListener("keydown", keydown);
          window.windowRoot.removeEventListener("MozAfterPaint", paint);
          this._inputResult = { ...data, visibility: document.visibilityState,
            document_focused: document.hasFocus(), focused: document.activeElement?.id };
          resolve(this._inputResult);
        };
        const timeout = window.setTimeout(() => finish({ error: "keyboard response timeout",
          last_key: lastKey, actual: result.textContent, expected,
          focused: document.activeElement?.id, document_focused: document.hasFocus() }),
          message.data.native_input ? 30000 : 15000);
        button.addEventListener("keydown", keydown);
        // Gecko directs privileged paint notifications to the parent target,
        // not the web content window (dom.send_after_paint_to_content=false).
        window.windowRoot.addEventListener("MozAfterPaint", paint);
      });
      button.focus();
      return { supported: true, expected, visibility: document.visibilityState,
        document_focused: document.hasFocus(), focused: document.activeElement?.id,
        ...(nativeMarker ? { native_marker: nativeMarker } : {}) };
    }
    if (message.name === "input_result") return this._inputPromise;
    if (message.name === "scrollbar_prepare") {
      const before = window.scrollY;
      this._scrollbarPromise = new Promise(resolve => {
        const finish = data => {
          window.clearTimeout(timer);
          window.removeEventListener("scroll", scroll);
          resolve(data);
        };
        const scroll = () => { if (window.scrollY !== before) finish({ before, scroll_y: window.scrollY }); };
        const timer = window.setTimeout(() => finish({ error: "scrollbar drag timed out", before, scroll_y: window.scrollY }), 30000);
        window.addEventListener("scroll", scroll);
      });
      return { before, scroll_height: window.document.documentElement.scrollHeight, viewport_height: window.innerHeight };
    }
    if (message.name === "scrollbar_result") return this._scrollbarPromise;
    return {
      url: window.location.href,
      document_uri: window.document.documentURI,
      error_page: /^about:(neterror|certerror|blocked)/.test(window.document.documentURI),
      title: window.document.title,
      state: window.document.readyState,
      time_origin: performance.timeOrigin,
      text: window.document.body?.innerText.slice(0, 160),
      paints: performance.getEntriesByType("paint").map(entry => ({
        name: entry.name, milliseconds: entry.startTime,
      })),
      navigation: performance.getEntriesByType("navigation").map(entry => ({
        start: entry.startTime, response: entry.responseStart,
        dom: entry.domContentLoadedEventEnd, load: entry.loadEventEnd,
        bytes: entry.transferSize, duration: entry.duration,
      })),
      resources: performance.getEntriesByType("resource").length,
    };
  }
}
