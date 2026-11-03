type Politeness = "polite" | "assertive";

type Listener = (message: string, politeness: Politeness) => void;

class LiveAnnouncerManager {
  private listeners: Listener[] = [];

  subscribe(listener: Listener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  announce(message: string, politeness: Politeness = "polite"): void {
    for (const listener of this.listeners) {
      listener(message, politeness);
    }
  }
}

export const liveAnnouncer = new LiveAnnouncerManager();

export function announce(message: string, politeness: Politeness = "polite"): void {
  liveAnnouncer.announce(message, politeness);
}
