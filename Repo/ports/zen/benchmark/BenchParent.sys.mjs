export class AlixBenchParent extends JSWindowActorParent {
  receiveMessage(message) {
    Services.obs.notifyObservers(null, "alix-benchmark-paint", JSON.stringify({
      context: this.browsingContext.id, ...message.data,
    }));
  }
}
