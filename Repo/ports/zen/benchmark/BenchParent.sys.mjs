Components.utils.importGlobalProperties(["fetch"]);
export class AlixBenchParent extends JSWindowActorParent {
  receiveMessage(message) {
    if (message.name === "media_progress" || message.name === "media_debug") {
      Services.obs.notifyObservers(null, message.name === "media_progress" ? "alix-benchmark-media-progress" : "alix-benchmark-media-debug", JSON.stringify({
        context: this.browsingContext.id, ...message.data, document_id: String(this.manager.innerWindowId),
      }));
      return;
    }
    if (message.name === "diagnostic_ping") return message.data;
    if (message.name === "clock_sync") {
      return fetch(message.data.url, { credentials: "omit", cache: "no-store" }).then(response => {
        if (!response.ok) throw new Error("clock collector returned " + response.status);
        return response.json();
      });
    }
    Services.obs.notifyObservers(null, "alix-benchmark-paint", JSON.stringify({
      context: this.browsingContext.id, ...message.data, document_id: String(this.manager.innerWindowId),
    }));
  }
}
