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
  receiveMessage() {
    const window = this.contentWindow;
    const performance = window.performance;
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
