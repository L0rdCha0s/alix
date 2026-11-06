export class AlixBenchChild extends JSWindowActorChild {
  watchMedia(video, mode) {
    const state = this._media = { video, mode, frames: [], chunks: 0, presented: 0,
      trusted_play: false, already_playing: false, play_error: null,
      watched_at_ms: this.contentWindow.performance.now(), watched_media_time: video.currentTime };
    state.media_events = [];
    for (const type of ["error", "abort", "emptied", "stalled", "waiting", "loadedmetadata"]) {
      this.contentWindow.document.addEventListener(type, event => {
        if (event.target !== video) return;
        const quality = video.getVideoPlaybackQuality();
        const data = { wall_ms: this.contentWindow.performance.now(), media_time: video.currentTime,
          frames: quality.totalVideoFrames, dropped: quality.droppedVideoFrames,
          callbacks: state.presented, ready_state: video.readyState, paused: video.paused,
          last_frame_ms: state.last_frame_delivered_ms ?? null, playback_rate: video.playbackRate,
          time_origin: this.contentWindow.performance.timeOrigin, media_event: type,
          playing: !video.paused && (state.trusted_play || state.already_playing),
          seeking: video.seeking, ended: video.ended, connected: video.isConnected,
          width: video.videoWidth, height: video.videoHeight, network_state: video.networkState,
          duration: Number.isFinite(video.duration) ? video.duration : null,
          ad_showing: this.contentWindow.document.getElementById("movie_player")?.classList.contains("ad-showing") || false,
          source_scheme: video.currentSrc.split(":")[0],
          media_error: video.error ? { code: video.error.code, message: video.error.message } : null,
          buffered_end: video.buffered.length ? video.buffered.end(video.buffered.length - 1) : null };
        state.media_events.push(data);
        if (state.media_events.length > 64) state.media_events.shift();
        this.sendAsyncMessage("media_progress", data);
      }, { capture: true });
    }
    if (typeof video.requestVideoFrameCallback === "function") {
      const frame = (now, metadata) => {
        state.presented++;
        state.last_frame_delivered_ms = this.contentWindow.performance.now();
        if (state.frames.length < 16) state.frames.push({ callback_ms: now, delivered_ms: state.last_frame_delivered_ms, media_time: metadata.mediaTime,
          presented_frames: metadata.presentedFrames, width: metadata.width, height: metadata.height });
        video.requestVideoFrameCallback(frame);
      };
      video.requestVideoFrameCallback(frame);
    }
    return state;
  }
  async prepareLiveMedia({ attempt = 0 } = {}) {
    const window = this.contentWindow, document = window.document, until = window.performance.now() + 20000;
    let video;
    while (window.performance.now() < until) {
      video = [...document.querySelectorAll("video")].find(v => v.getBoundingClientRect().width > 100);
      if (video) break;
      await new Promise(resolve => window.setTimeout(resolve, 200));
    }
    if (!video) throw new Error("No live video element: " + document.body.innerText.slice(0, 1800));
    let previous = "", stableSince = window.performance.now();
    while (window.performance.now() < until) {
      const rect = document.getElementById("movie_player")?.getBoundingClientRect() || video.getBoundingClientRect();
      const geometry = [rect.x, rect.y, rect.width, rect.height].join(",");
      if (geometry !== previous) { previous = geometry; stableSince = window.performance.now(); }
      if (window.performance.now() - stableSince >= 2000) break;
      await new Promise(resolve => window.setTimeout(resolve, 200));
    }
    const state = this._media?.video === video ? this._media : this.watchMedia(video, "live"), actions = [];
    if (!state.input_events) {
      state.input_events = [];
      document.addEventListener("click", event => {
        const rect = document.getElementById("movie_player")?.getBoundingClientRect();
        const insidePlayer = !!rect && event.clientX >= rect.left && event.clientX < rect.right &&
          event.clientY >= rect.top && event.clientY < rect.bottom;
        if (event.isTrusted && insidePlayer) state.trusted_play = true;
        if (state.input_events.length < 8) state.input_events.push({ trusted: event.isTrusted,
          wall_ms: window.performance.now(), x: event.clientX, y: event.clientY,
          inside_player: insidePlayer,
          target: event.target?.className?.toString() || event.target?.nodeName });
      }, { capture: true });
    }
    const largePlay = document.querySelector(".ytp-large-play-button");
    const largeRect = largePlay?.getBoundingClientRect();
    const playSelector = largeRect?.width > 0 && largeRect?.height > 0 ? ".ytp-large-play-button" : ".ytp-play-button";
    for (const [needed, selector] of [[video.muted, ".ytp-mute-button"], [video.paused || video.ended, playSelector]]) {
      if (!needed) continue;
      const button = document.querySelector(selector);
      if (!button) throw new Error("Missing live player control " + selector);
      const rect = button.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) throw new Error("Live player control not visible " + selector);
      button.addEventListener("click", event => { if (event.isTrusted) state.trusted_play = true; }, { capture: true });
      const x = rect.x + rect.width / 2, y = rect.y + rect.height / 2;
      const hit = document.elementFromPoint(x, y);
      actions.push({ selector, x, y, hit_test: hit?.nodeName, hit_class: hit?.className?.toString() });
    }
    state.already_playing = !video.paused && !video.muted;
    const marker = document.createElement("div"), colors = [[61,217,113],[233,71,181],[129,43,229],[19,167,251]];
    document.getElementById("alix-bench-media-ready-marker")?.remove();
    marker.id = "alix-bench-media-ready-marker";
    colors[0][0] = (colors[0][0] + attempt * 37) % 256;
    marker.style.cssText = "all:initial;position:fixed;top:16px;right:16px;width:8px;height:8px;z-index:2147483647;pointer-events:none";
    colors.forEach((color, i) => {
      const part = document.createElement("div");
      part.style.cssText = "all:initial;position:absolute;width:4px;height:4px;left:" + (i%2)*4 + "px;top:" + Math.floor(i/2)*4 + "px;background:rgb(" + color.join(",") + ")";
      marker.appendChild(part);
    });
    document.documentElement.appendChild(marker);
    const mediaRect = (document.getElementById("movie_player") || video).getBoundingClientRect();
    return { actions, attempt, already_playing: state.already_playing, viewport_width: window.innerWidth,
      rect: { x: mediaRect.x, y: mediaRect.y, width: mediaRect.width, height: mediaRect.height },
      native_marker: { width:8, height:8, quadrant_rgb:colors, kind:"dom", device_pixel_ratio:window.devicePixelRatio, inset_css_pixels:16 } };
  }
  async prepareMedia({ url, mse, displayWidth }) {
    const window = this.contentWindow, document = window.document;
    const panel = document.createElement("section");
    panel.style.cssText = "position:fixed;left:24px;top:150px;padding:12px;background:#152238;color:white;z-index:1000";
    panel.textContent = mse ? "HTML5 VP9/Opus: Media Source" : "HTML5 VP9/Opus: direct resource";
    const video = document.createElement("video");
    video.width = 320; video.height = 180; video.controls = true; video.loop = true;
    video.style.cssText = "display:block;width:320px;height:180px;background:black";
    panel.appendChild(video); document.body.appendChild(panel);
    const state = this.watchMedia(video, mse ? "mse" : "direct");
    const metadata = new Promise((resolve, reject) => {
      const timer = window.setTimeout(() => reject(new Error("media metadata timeout")), 20000);
      video.addEventListener("loadedmetadata", () => { window.clearTimeout(timer); resolve(); }, { once: true });
      video.addEventListener("error", () => { window.clearTimeout(timer); reject(new Error(video.error?.message || "media resource error")); }, { once: true });
    });
    if (mse) {
      const source = state.source = new window.MediaSource();
      const opened = new Promise(resolve => source.addEventListener("sourceopen", resolve, { once: true }));
      video.src = window.URL.createObjectURL(source);
      await opened;
      const response = await window.fetch(url);
      if (!response.ok) throw new Error("media fixture HTTP " + response.status);
      const bytes = await response.arrayBuffer();
      const hash = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
      hash.init(Ci.nsICryptoHash.SHA256);
      hash.update(new Uint8Array(bytes), bytes.byteLength);
      state.download_sha256 = [...hash.finish(false)].map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
      state.download_bytes = bytes.byteLength;
      const buffer = source.addSourceBuffer('video/webm; codecs="vp9, opus"');
      for (let offset = 0; offset < bytes.byteLength; offset += 65536) {
        await new Promise((resolve, reject) => {
          const done = () => { buffer.removeEventListener("error", failed); resolve(); };
          const failed = () => { buffer.removeEventListener("updateend", done); reject(new Error("Media Source append failed")); };
          buffer.addEventListener("updateend", done, { once: true });
          buffer.addEventListener("error", failed, { once: true });
          buffer.appendBuffer(bytes.slice(offset, offset + 65536));
        });
        state.chunks++;
      }
      source.endOfStream();
    } else video.src = url;
    await metadata;
    if (displayWidth) {
      video.width = displayWidth;
      video.height = Math.round(displayWidth * video.videoHeight / video.videoWidth);
      video.style.width = video.width + "px"; video.style.height = video.height + "px";
    }
    const button = document.getElementById("addBtn");
    if (!button) throw new Error("missing native media play control");
    button.addEventListener("click", event => {
      state.trusted_play = event.isTrusted;
      state.play_started_ms = window.performance.now(); state.play_start_media_time = video.currentTime;
      video.play().catch(error => { state.play_error = String(error); });
    });
    return { mode: state.mode, width: video.videoWidth, height: video.videoHeight, chunks_appended: state.chunks,
      download_sha256: state.download_sha256 || null, download_bytes: state.download_bytes || null };
  }
  async mediaDebug() {
    const window = this.contentWindow, video = this._media?.video;
    if (!video?.mozRequestDebugInfo) throw new Error("native media debug interface unavailable");
    let timer;
    try {
      const source = video.mozMediaSourceObject;
      const [info, sourceInfo] = await Promise.race([Promise.all([video.mozRequestDebugInfo(),
        source?.mozDebugReaderData ? source.mozDebugReaderData() : null]), new Promise((_, reject) => {
        timer = window.setTimeout(() => reject(new Error("media debug queue timeout")), 3000);
      })]);
      return { time_origin: window.performance.timeOrigin, wall_ms: window.performance.now(),
        compositor_dropped_frames: info.compositorDroppedFrames, decoder: info.decoder,
        media_source: sourceInfo, media_source_state: source?.readyState || null,
        buffered_ranges: Array.from({ length: video.buffered.length }, (_, i) => ({ start: video.buffered.start(i), end: video.buffered.end(i) })) };
    } finally { window.clearTimeout(timer); }
  }
  async mediaPlayback({ observeSeconds = 0, debugSnapshots = false } = {}) {
    const window = this.contentWindow, state = this._media;
    if (!state) throw new Error("media was not prepared");
    const video = state.video, started = window.performance.now();
    const samples = [], snapshot = () => {
      const quality = video.getVideoPlaybackQuality();
      return { wall_ms: window.performance.now(), media_time: video.currentTime,
        frames: quality.totalVideoFrames, dropped: quality.droppedVideoFrames,
        width: video.videoWidth, height: video.videoHeight,
        duration: Number.isFinite(video.duration) ? video.duration : null,
        ad_showing: window.document.getElementById("movie_player")?.classList.contains("ad-showing") || false,
        callbacks: state.presented, ready_state: video.readyState, paused: video.paused,
        last_frame_ms: state.last_frame_delivered_ms ?? null, playback_rate: video.playbackRate };
    };
    let lastProgress = -Infinity;
    let lastDebug = -Infinity, debugPending = false;
    const progress = () => {
      const data = snapshot();
      if (data.wall_ms - lastProgress < 500) return;
      lastProgress = data.wall_ms;
      this.sendAsyncMessage("media_progress", { ...data, time_origin: window.performance.timeOrigin,
        playing: !video.paused && (state.trusted_play || state.already_playing),
        seeking: video.seeking, ended: video.ended,
        buffered_end: video.buffered.length ? video.buffered.end(video.buffered.length - 1) : null });
      if (debugSnapshots && !debugPending && data.wall_ms - lastDebug >= 2000) {
        lastDebug = data.wall_ms; debugPending = true;
        this.mediaDebug().then(info => this.sendAsyncMessage("media_debug", info))
          .catch(error => { try { this.sendAsyncMessage("media_debug", {
            time_origin: window.performance.timeOrigin, wall_ms: window.performance.now(), error: String(error) }); } catch (_) {} })
          .finally(() => { debugPending = false; });
      }
    };
    while (window.performance.now() - started < 20000) {
      progress();
      if (video.error || state.play_error) break;
      if ((state.trusted_play || state.already_playing) && video.currentTime >= (state.mode === "live" ? 3 : 1.25) && state.presented >= 3 &&
          !window.document.getElementById("movie_player")?.classList.contains("ad-showing")) break;
      await new Promise(resolve => window.setTimeout(resolve, 100));
    }
    if (observeSeconds) {
      const until = window.performance.now() + observeSeconds * 1000;
      samples.push(snapshot());
      while (window.performance.now() < until && !video.error) {
        await new Promise(resolve => window.setTimeout(resolve, 500));
        progress();
        samples.push(snapshot());
      }
    }
    const rect = video.getBoundingClientRect(), quality = video.getVideoPlaybackQuality();
    return { protocol: "zen_media_playback_v1", mode: state.mode, trusted_play: state.trusted_play, already_playing: state.already_playing,
      observation_ms: window.performance.now(), watched_at_ms: state.watched_at_ms, watched_media_time: state.watched_media_time,
      play_started_ms: state.play_started_ms ?? null, play_start_media_time: state.play_start_media_time ?? null,
      input_events: state.input_events || [],
      media_events: state.media_events || [],
      playback_samples: samples, playback_rate: video.playbackRate,
      current_time: video.currentTime, duration: Number.isFinite(video.duration) ? video.duration : null,
      width: video.videoWidth, height: video.videoHeight, ready_state: video.readyState, paused: video.paused,
      muted: video.muted, volume: video.volume, presented_callbacks: state.presented, frames: state.frames,
      total_video_frames: quality.totalVideoFrames, dropped_video_frames: quality.droppedVideoFrames,
      chunks_appended: state.chunks, media_source_state: state.source?.readyState || null,
      source_scheme: video.currentSrc.split(":", 1)[0], page_title: window.document.title,
      ad_showing: window.document.getElementById("movie_player")?.classList.contains("ad-showing") || false,
      error: video.error ? { code: video.error.code, message: video.error.message } : state.play_error,
      rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height, viewport_width: window.innerWidth },
      device_pixel_ratio: window.devicePixelRatio };
  }
  mediaCapabilities() {
    const window = this.contentWindow, video = window.document.createElement("video");
    const types = [
      'video/webm; codecs="vp8, vorbis"', 'video/webm; codecs="vp9, opus"',
      'video/webm; codecs="vp9"', 'video/webm; codecs="av01.0.04M.08"',
      'audio/webm; codecs="opus"', 'video/mp4; codecs="avc1.42E01E"',
      'video/mp4; codecs="avc1.42E01E, mp4a.40.2"', 'audio/mp4; codecs="mp4a.40.2"',
      'audio/mpeg', 'audio/ogg; codecs="vorbis"', 'audio/wav; codecs="1"',
    ];
    return { protocol: "zen_media_capabilities_v1", url: window.location.href,
      process_type: Services.appinfo.processType,
      gc_profile_environment: Services.env.get("JS_GC_PROFILE"),
      media_source_available: typeof window.MediaSource === "function",
      media_capabilities_available: !!window.navigator.mediaCapabilities,
      types: types.map(type => ({ type, can_play: video.canPlayType(type),
        media_source: typeof window.MediaSource === "function" && window.MediaSource.isTypeSupported(type) })),
      videos: [...window.document.querySelectorAll("video")].slice(0, 8).map(v => ({
        current_time: v.currentTime, duration: Number.isFinite(v.duration) ? v.duration : null,
        ready_state: v.readyState, network_state: v.networkState, paused: v.paused,
        width: v.videoWidth, height: v.videoHeight,
        error: v.error ? { code: v.error.code, message: v.error.message } : null,
      })),
    };
  }
  async clockSync({ url }) {
    const window = this.contentWindow, clock = window.performance, samples = [];
    for (let i = 0; i < 3; i++) {
      const sent = clock.now();
      let timer;
      try {
        const reply = await Promise.race([
          this.sendQuery("clock_sync", { url }),
          new Promise((_, reject) => { timer = window.setTimeout(() => reject(new Error("clock calibration timeout")), 15000); }),
        ]);
        const received = clock.now();
        if (!Number.isFinite(reply.host_monotonic_ms) || received < sent) throw new Error("invalid clock sample");
        samples.push({ guest_send_ms: sent, guest_receive_ms: received, host_monotonic_ms: reply.host_monotonic_ms });
      } finally {
        window.clearTimeout(timer);
      }
    }
    return { time_origin: clock.timeOrigin, samples };
  }
  async runDiagnostics({ samples }) {
    const window = this.contentWindow, document = window.document, clock = window.performance;
    const cases = [], longTasks = [];
    const summary = values => {
      const sorted = [...values].sort((a, b) => a - b);
      return { samples_ms: values, count: values.length, first_ms: values[0],
        p50_ms: sorted[Math.floor(sorted.length / 2)],
        p95_ms: sorted[Math.ceil(sorted.length * .95) - 1], max_ms: sorted.at(-1),
        below_clock_resolution: values.every(value => value === 0) };
    };
    const frame = () => new Promise((resolve, reject) => {
      const timeout = window.setTimeout(() => { window.cancelAnimationFrame(id); reject(new Error("animation frame timeout")); }, 15000);
      const id = window.requestAnimationFrame(() => { window.clearTimeout(timeout); resolve(); });
    });
    const measure = async (name, work, details = {}) => {
      const values = [];
      try {
        for (let i = 0; i < samples; i++) {
          const start = clock.now();
          await work(i);
          values.push(clock.now() - start);
        }
        cases.push({ name, status: "OK", ...details, ...summary(values) });
      } catch (error) {
        cases.push({ name, status: "FAIL", error: String(error), ...details, samples_ms: values });
      }
    };
    const supportsLongTasks = window.PerformanceObserver?.supportedEntryTypes?.includes("longtask") || false;
    const observer = supportsLongTasks ? new window.PerformanceObserver(list => {
      for (const entry of list.getEntries()) if (longTasks.length < 64)
        longTasks.push({ start_ms: entry.startTime, duration_ms: entry.duration });
    }) : null;
    if (observer) observer.observe({ type: "longtask" });
    const panel = document.createElement("div");
    panel.id = "alix-zen-diagnostic-panel";
    panel.style.cssText = "position:fixed;left:16px;top:120px;width:512px;height:240px;overflow:hidden;" +
      "contain:layout style paint;background:white;color:black;z-index:2147483646;font:14px sans-serif";
    document.documentElement.appendChild(panel);
    const started = clock.now();
    try {
      await measure("timer_zero_delay", () => new Promise(resolve => window.setTimeout(resolve, 0)));
      await measure("animation_frame_wait", frame);
      for (const bytes of [0, 4096, 65536]) {
        const payload = "z".repeat(bytes);
        await measure("actor_roundtrip_" + bytes, async id => {
          const reply = await this.sendQuery("diagnostic_ping", { id, payload });
          if (reply.id !== id || reply.payload !== payload) throw new Error("actor echo mismatch");
        }, { payload_bytes_each_direction: bytes });
      }
      const rows = [];
      for (let i = 0; i < 128; i++) {
        const row = document.createElement("div");
        row.style.cssText = "height:16px;width:200px";
        row.textContent = "Zen layout diagnostic " + i;
        panel.appendChild(row); rows.push(row);
      }
      await frame();
      await measure("dom_batched_layout_128", i => {
        for (const row of rows) row.style.width = (200 + i % 2) + "px";
        if (rows.at(-1).getBoundingClientRect().width !== 200 + i % 2) throw new Error("layout width mismatch");
      }, { nodes: 128, layout_flushes_per_sample: 1 });
      await measure("dom_interleaved_layout_128", i => {
        for (const row of rows) {
          row.style.width = (210 + i % 2) + "px";
          if (row.getBoundingClientRect().width !== 210 + i % 2) throw new Error("layout width mismatch");
        }
      }, { nodes: 128, layout_flushes_per_sample: 128 });
      panel.replaceChildren();
      const canvas = document.createElement("canvas"); canvas.width = 512; canvas.height = 128;
      panel.appendChild(canvas);
      const context = canvas.getContext("2d");
      await measure("canvas_fill_and_readback", () => {
        context.fillStyle = "rgb(17,34,51)"; context.fillRect(0, 0, 512, 128);
        const pixel = context.getImageData(511, 127, 1, 1).data;
        if (pixel[0] !== 17 || pixel[1] !== 34 || pixel[2] !== 51 || pixel[3] !== 255)
          throw new Error("canvas pixel mismatch");
      }, { pixels: 65536, readback_pixels: 1 });
      await measure("fonts_ready", () => document.fonts.ready,
                    { status_at_start: document.fonts.status });
      const widths = [];
      const fontPhases = { setup: [], shape: [], raster: [], readback: [] };
      await measure("font_shape_and_raster", () => {
        let mark = clock.now();
        context.fillStyle = "white"; context.fillRect(0, 0, 512, 128);
        context.fillStyle = "black"; context.font = "18px sans-serif";
        fontPhases.setup.push(clock.now() - mark); mark = clock.now();
        const text = "Zen 0123456789 Latin Greek Σ Cyrillic Ж 中文";
        const width = context.measureText(text).width; widths.push(width);
        fontPhases.shape.push(clock.now() - mark); mark = clock.now();
        if (!(width > 0)) throw new Error("text width missing");
        context.fillText(text, 2, 24);
        fontPhases.raster.push(clock.now() - mark); mark = clock.now();
        const pixels = context.getImageData(0, 0, 180, 32).data;
        fontPhases.readback.push(clock.now() - mark);
        let ink = 0;
        for (let i = 0; i < pixels.length; i += 4) if (pixels[i] < 240) ++ink;
        if (!ink) throw new Error("text raster is blank");
      }, { text_widths: widths, readback_pixels: 5760, phases_ms: fontPhases });
      const buffers = [];
      await measure("arraybuffer_allocate_touch_1m", i => {
        // Only this diagnostic-owned allocation is unwrapped. Xray wrappers
        // deliberately forbid direct indexed access to content typed arrays.
        const bytes = Components.utils.waiveXrays(new window.Uint8Array(new window.ArrayBuffer(1024 * 1024)));
        for (let page = 0; page < bytes.length; page += 4096) bytes[page] = i + 1;
        bytes[bytes.length - 1] = 73;
        if (bytes[0] !== i + 1 || bytes.at(-1) !== 73) throw new Error("array buffer data mismatch");
        buffers.push(bytes);
      }, { bytes_per_sample: 1048576, retained_bytes_limit: samples * 1048576 });
      buffers.length = 0;
      await frame();
    } catch (error) {
      cases.push({ name: "diagnostic_setup", status: "FAIL", error: String(error) });
    } finally {
      panel.remove();
      if (observer) {
        for (const entry of observer.takeRecords()) if (longTasks.length < 64)
          longTasks.push({ start_ms: entry.startTime, duration_ms: entry.duration });
        observer.disconnect();
      }
    }
    return { protocol: "zen_content_diagnostics_v2", url: window.location.href,
      visibility: document.visibilityState, samples, elapsed_ms: clock.now() - started,
      cases, long_tasks_supported: supportsLongTasks, long_tasks: longTasks };
  }
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
    if (message.name === "clock_sync") return this.clockSync(message.data);
    if (message.name === "diagnostics") return this.runDiagnostics(message.data);
    if (message.name === "media_capabilities") return this.mediaCapabilities();
    if (message.name === "media_prepare") return this.prepareMedia(message.data);
    if (message.name === "media_live_prepare") return this.prepareLiveMedia(message.data);
    if (message.name === "media_start_status") return new Promise(resolve => window.setTimeout(() => {
      const video = this._media?.video;
      resolve({ paused: video?.paused, current_time: video?.currentTime,
        frames: video?.getVideoPlaybackQuality().totalVideoFrames,
        input_events: this._media?.input_events || [] });
    }, 3000));
    if (message.name === "media_playback") return this.mediaPlayback(message.data);
    if (message.name === "media_debug") return this.mediaDebug();
    if (message.name === "input_prepare") {
      const document = window.document;
      const button = document.getElementById("addBtn");
      const a = document.getElementById("a");
      const result = document.getElementById("result");
      if (!button || !a || !result || document.title !== (message.data.title || "Add Two Numbers")) return { supported: false };
      const expected = "Result: " + (message.data.sample + 13);
      a.value = String(message.data.sample + 11);
      const cornerFixture = document.getElementById("alix-corner-fixture");
      let cornerMetadata;
      if (cornerFixture) {
        if (!window.CSS.supports("corner-shape", "superellipse(2)")) throw new Error("corner-shape unsupported");
        cornerFixture.style.setProperty("--bend", (message.data.sample * 4) + "px");
        const rect = cornerFixture.getBoundingClientRect();
        cornerMetadata = { x: rect.x, y: rect.y, width: rect.width, height: rect.height,
          viewport_width: window.innerWidth, response_bend: message.data.sample * 4 + 2,
          shapes: [...cornerFixture.children].map(tile => window.getComputedStyle(tile).getPropertyValue("corner-top-left-shape")) };
        if (cornerMetadata.shapes.some(shape => !shape)) throw new Error("missing computed corner shape");
      }
      let nativeMarker, nativeResponseMarker, drawNativeResponse;
      if (message.data.native_input) {
        let marker = document.getElementById("alix-native-input-marker");
        if (!marker) {
          marker = document.createElement(cornerFixture ? "div" : "canvas");
          marker.id = "alix-native-input-marker";
          marker.width = marker.height = 8;
          marker.setAttribute("aria-hidden", "true");
          marker.style.cssText = "all:initial;position:fixed;top:16px;right:16px;" +
            "width:8px;height:8px;display:block;z-index:2147483647;pointer-events:none;" +
            "user-select:none;contain:strict;image-rendering:pixelated";
          if (cornerFixture) for (let quadrant = 0; quadrant < 4; quadrant++) {
            const part = document.createElement("div");
            part.style.cssText = "all:initial;display:block;position:absolute;width:4px;height:4px;" +
              "left:" + (quadrant % 2) * 4 + "px;top:" + Math.floor(quadrant / 2) * 4 + "px";
            marker.appendChild(part);
          }
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
        const context = cornerFixture ? null : marker.getContext("2d");
        const draw = pattern => {
          for (let quadrant = 0; quadrant < 4; quadrant++) {
            const color = "rgb(" + pattern[quadrant].join(",") + ")";
            if (cornerFixture) marker.children[quadrant].style.backgroundColor = color;
            else {
              context.fillStyle = color;
              context.fillRect((quadrant % 2) * 4, Math.floor(quadrant / 2) * 4, 4, 4);
            }
          }
        };
        draw(colors);
        nativeMarker = { width: 8, height: 8, quadrant_rgb: colors,
          kind: cornerFixture ? "dom" : "canvas",
          device_pixel_ratio: window.devicePixelRatio, inset_css_pixels: 16 };
        nativeResponseMarker = { ...nativeMarker,
          quadrant_rgb: colors.map(color => color.map(channel => channel ^ 128)) };
        drawNativeResponse = () => draw(nativeResponseMarker.quadrant_rgb);
      }
      this._inputResult = null;
      this._inputPromise = new Promise(resolve => {
        let received = null;
        let lastKey = null;
        let timerId = null, frameId = null;
        const phases = { event_to_dom_observer_ms: null, event_to_microtask_ms: null,
          event_to_timer_ms: null, event_to_animation_frame_ms: null,
          event_time_ms: null, native_event_timestamp_ms: null, event_age_at_listener_ms: null, key_repeat: null };
        const mutation = new window.MutationObserver(() => {
          if (received !== null && phases.event_to_dom_observer_ms === null && result.textContent === expected) {
            phases.event_to_dom_observer_ms = performance.now() - received;
            if (cornerFixture) cornerFixture.style.setProperty("--bend", (message.data.sample * 4 + 2) + "px");
            if (drawNativeResponse) drawNativeResponse();
          }
        });
        mutation.observe(result, { childList: true, characterData: true, subtree: true });
        const keydown = event => {
          lastKey = { key: event.key, trusted: event.isTrusted };
          if (event.key === "Enter" && event.isTrusted && received === null) {
            received = performance.now();
            phases.event_time_ms = received;
            phases.native_event_timestamp_ms = event.timeStamp;
            phases.event_age_at_listener_ms = Number.isFinite(event.timeStamp) && event.timeStamp > 0 && event.timeStamp <= received
              ? received - event.timeStamp : null;
            phases.key_repeat = event.repeat;
            Promise.resolve().then(() => { phases.event_to_microtask_ms = performance.now() - received; });
            timerId = window.setTimeout(() => { phases.event_to_timer_ms = performance.now() - received; }, 0);
            frameId = window.requestAnimationFrame(() => { phases.event_to_animation_frame_ms = performance.now() - received; });
          }
        };
        const paint = () => {
          if (received === null || result.textContent !== expected) return;
          finish({ trusted: true, expected, actual: result.textContent,
                   event_to_paint_ms: performance.now() - received, ...phases,
                   ...(nativeResponseMarker ? { native_response_marker: nativeResponseMarker } : {}) });
        };
        const finish = data => {
          window.clearTimeout(timeout);
          button.removeEventListener("keydown", keydown, true);
          window.windowRoot.removeEventListener("MozAfterPaint", paint);
          mutation.disconnect();
          if (timerId !== null) window.clearTimeout(timerId);
          if (frameId !== null) window.cancelAnimationFrame(frameId);
          this._inputResult = { ...data, visibility: document.visibilityState,
            document_focused: document.hasFocus(), focused: document.activeElement?.id,
            input_time_origin: performance.timeOrigin };
          resolve(this._inputResult);
        };
        const timeout = window.setTimeout(() => finish({ error: "keyboard response timeout",
          last_key: lastKey, actual: result.textContent, expected,
          focused: document.activeElement?.id, document_focused: document.hasFocus() }),
          message.data.native_input ? 30000 : 15000);
        button.addEventListener("keydown", keydown, true);
        // Gecko directs privileged paint notifications to the parent target,
        // not the web content window (dom.send_after_paint_to_content=false).
        window.windowRoot.addEventListener("MozAfterPaint", paint);
      });
      button.focus();
      return { supported: true, expected, visibility: document.visibilityState,
        document_focused: document.hasFocus(), focused: document.activeElement?.id,
        ...(cornerMetadata ? { corner_fixture: cornerMetadata } : {}),
        ...(nativeMarker ? { native_marker: nativeMarker, native_response_marker: nativeResponseMarker } : {}) };
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
      document_id: String(this.manager.innerWindowId),
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
        dns_ms: entry.domainLookupEnd - entry.domainLookupStart,
        connect_ms: entry.connectEnd - entry.connectStart,
        request_to_response_ms: entry.responseStart - entry.requestStart,
        response_ms: entry.responseEnd - entry.responseStart,
      })),
      resources: performance.getEntriesByType("resource").length,
      slow_resources: performance.getEntriesByType("resource").sort((a, b) => b.duration - a.duration).slice(0, 16).map(entry => ({
        url: entry.name, kind: entry.initiatorType, duration_ms: entry.duration,
        dns_ms: entry.domainLookupEnd - entry.domainLookupStart,
        connect_ms: entry.connectEnd - entry.connectStart,
        request_to_response_ms: entry.responseStart - entry.requestStart,
        response_ms: entry.responseEnd - entry.responseStart, bytes: entry.transferSize,
      })),
    };
  }
}
