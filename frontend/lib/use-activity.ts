"use client";

/**
 * Polls GET /api/v1/admin/activity for everything that wants to show what the system
 * does in the background (header icon, "Daten" tab).
 *
 * There is exactly ONE poller per browser tab, however many components use the hook.
 * Two components that polled on their own used up the request limit of the whole
 * address, and with it the login. The poller also
 *   - asks every 3 s while something runs (or shortly after a start) and every 30 s otherwise,
 *   - backs off when the server answers 429 ("too many requests") or does not answer.
 */

import { useCallback, useEffect, useState } from "react";
import { adminFetch, ApiError, type Activity, type ActivityResponse } from "./admin-api";

const FAST_MS = 3000;
const SLOW_MS = 30000;
const BOOST_MS = 15000;
const MAX_BACKOFF_MS = 60000;

export interface ActivitySnapshot {
  activities: Activity[];
  loaded: boolean;
  /** The server did not answer the last few requests */
  connectionLost: boolean;
  /** The server answered 429: this address asked too often */
  rateLimited: boolean;
  /** Timestamp (ms) of the last answer, so timers can keep counting in between */
  receivedAt: number;
}

const EMPTY: ActivitySnapshot = {
  activities: [],
  loaded: false,
  connectionLost: false,
  rateLimited: false,
  receivedAt: 0,
};

class Poller {
  snapshot: ActivitySnapshot = { ...EMPTY, receivedAt: Date.now() };
  listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private failures = 0;
  private retryAfterMs = 0;
  private boostUntil = 0;
  private active = false;
  private inflight: Promise<void> | null = null;

  constructor(readonly token: string) {}

  subscribe(listener: () => void) {
    this.listeners.add(listener);
    if (this.listeners.size === 1) this.start();
    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0) this.stop();
    };
  }

  private emit(next: Partial<ActivitySnapshot>) {
    this.snapshot = { ...this.snapshot, ...next };
    this.listeners.forEach((l) => l());
  }

  private start() {
    this.active = true;
    this.schedule(0);
  }

  private stop() {
    this.active = false;
    clearTimeout(this.timer);
  }

  /** Stop polling for good (the listeners moved to a newer poller). */
  dispose() {
    this.listeners.clear();
    this.stop();
  }

  private delay(): number {
    if (this.failures > 0) {
      const backoff = Math.min(MAX_BACKOFF_MS, FAST_MS * 2 ** this.failures);
      return Math.max(backoff, this.retryAfterMs);
    }
    const running = this.snapshot.activities.some((a) => a.state === "running");
    return running || Date.now() < this.boostUntil ? FAST_MS : SLOW_MS;
  }

  private schedule(ms: number) {
    clearTimeout(this.timer);
    if (!this.active) return;
    this.timer = setTimeout(async () => {
      await this.fetchOnce();
      this.schedule(this.delay());
    }, ms);
  }

  fetchOnce(): Promise<void> {
    if (this.inflight) return this.inflight;
    this.inflight = (async () => {
      try {
        const data = await adminFetch<ActivityResponse>(this.token, "/activity");
        this.failures = 0;
        this.retryAfterMs = 0;
        this.emit({
          activities: data.activities,
          loaded: true,
          connectionLost: false,
          rateLimited: false,
          receivedAt: Date.now(),
        });
      } catch (e) {
        this.failures += 1;
        const limited = e instanceof ApiError && e.status === 429;
        this.retryAfterMs = limited && e.retryAfter ? e.retryAfter * 1000 : 0;
        if (limited) this.emit({ rateLimited: true, connectionLost: false });
        else if (this.failures >= 3) this.emit({ connectionLost: true });
      } finally {
        this.inflight = null;
      }
    })();
    return this.inflight;
  }

  /** Ask now and keep asking quickly for a while (after "Import starten", when a window opens). */
  async boost() {
    this.boostUntil = Date.now() + BOOST_MS;
    await this.fetchOnce();
    this.schedule(this.delay());
  }
}

let poller: Poller | null = null;

function pollerFor(token: string): Poller {
  if (!poller || poller.token !== token) {
    const old = poller;
    poller = new Poller(token);
    // Components that still listen to an old poller (token changed) move over
    if (old) {
      const moving = [...old.listeners];
      old.dispose();
      moving.forEach((l) => poller!.subscribe(l));
    }
  }
  return poller;
}

export function useActivity(token: string | null, enabled: boolean) {
  const [snap, setSnap] = useState<ActivitySnapshot>(EMPTY);

  useEffect(() => {
    if (!enabled || !token) return;
    const p = pollerFor(token);
    setSnap(p.snapshot);
    return p.subscribe(() => setSnap(p.snapshot));
  }, [token, enabled]);

  const boost = useCallback(async () => {
    if (token && enabled) await pollerFor(token).boost();
  }, [token, enabled]);

  const importActivity = snap.activities.find((a) => a.id === "import") ?? null;
  const running = snap.activities.some((a) => a.state === "running");
  return {
    activities: snap.activities,
    importActivity,
    running,
    loaded: snap.loaded,
    connectionLost: snap.connectionLost,
    rateLimited: snap.rateLimited,
    receivedAt: snap.receivedAt || Date.now(),
    boost,
    /** Same as boost, kept as the name the components already use */
    refresh: boost,
  };
}
