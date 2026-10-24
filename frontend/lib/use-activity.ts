"use client";

/** Polls GET /api/v1/admin/activity: every 2 s while something runs, otherwise every 30 s. */

import { useCallback, useEffect, useRef, useState } from "react";
import { adminFetch, type Activity, type ActivityResponse } from "./admin-api";

const FAST_MS = 2000;
const SLOW_MS = 30000;

export function useActivity(token: string | null, enabled: boolean, fast = false) {
  const [activities, setActivities] = useState<Activity[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [connectionLost, setConnectionLost] = useState(false);
  const [receivedAt, setReceivedAt] = useState(() => Date.now());
  const failures = useRef(0);
  const running = activities.some((a) => a.state === "running");

  const refresh = useCallback(async () => {
    if (!token || !enabled) return;
    try {
      const data = await adminFetch<ActivityResponse>(token, "/activity");
      failures.current = 0;
      setConnectionLost(false);
      setActivities(data.activities);
      setReceivedAt(Date.now());
      setLoaded(true);
    } catch {
      failures.current += 1;
      if (failures.current >= 3) setConnectionLost(true);
    }
  }, [token, enabled]);

  useEffect(() => {
    if (!enabled || !token) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const loop = async () => {
      await refresh();
      if (!stopped) timer = setTimeout(loop, running || fast ? FAST_MS : SLOW_MS);
    };
    loop();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [refresh, enabled, token, running, fast]);

  const importActivity = activities.find((a) => a.id === "import") ?? null;
  return { activities, importActivity, running, loaded, connectionLost, receivedAt, refresh };
}
