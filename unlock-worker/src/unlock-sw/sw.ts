/// <reference lib="webworker" />
/**
 * Attest's unlock worker: the service worker that unlocks documents for a sender's new signers on an enrolled device
 * (design 3.2 C and D). It is small, versioned and built reproducibly (scripts/unlock/build-sw.mjs); each build's
 * SHA-256 is listed in src/lib/unlock/sw-builds.ts and anchored on Horizen, and scripts/unlock/sw-monitor.mjs compares
 * the worker Attest serves with them.
 *
 * It does three things: on a push (whose payload only says "check"), and on a page's "check" message, it runs the same
 * unlock as the pages (src/lib/unlock/device.ts), time-boxed to 15 seconds, then shows what happened. Every push ends
 * with a notification, as every platform requires. It has no fetch handler: it never sees or answers a page's requests.
 */
import { onAlarm } from "@/lib/key-directory-client";
import { deviceFetch, deviceState, runDeviceUnlock, type DeviceRunResult } from "@/lib/unlock/device";
import { noticesFor, type Notice } from "@/lib/unlock/notices";

declare const self: ServiceWorkerGlobalScope;

export const UNLOCK_WORKER_VERSION = "1.2.0";
const RUN_MS = 15_000;

self.addEventListener("install", () => {
  void self.skipWaiting();
});
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

// A directory alarm raised during a run is reported to DataHubz by the device itself (no page may be open).
onAlarm((a) => {
  if (a.reason !== "directory") return;
  void deviceState().then((s) => (s ? deviceFetch(s, "POST", "/api/unlock/alarm", { reason: a.reason, detail: a.detail }) : null)).catch(() => {});
});

const timeout = (ms: number) => new Promise<DeviceRunResult>((r) => setTimeout(() => r({ status: "error", message: "out of time" }), ms));

async function tellPages(result: DeviceRunResult) {
  const summary =
    result.status === "done"
      ? { status: "done", outcomes: result.outcomes.map((o) => ({ kind: o.kind, agreementId: o.agreementId })), recent: result.recent.map((r) => r.agreementId) }
      : { status: result.status };
  for (const c of await self.clients.matchAll({ type: "window", includeUncontrolled: true })) c.postMessage({ type: "unlock-result", version: UNLOCK_WORKER_VERSION, result: summary });
}

async function show(n: Notice) {
  await self.registration.showNotification(n.title, { body: n.body, tag: n.tag, data: { url: n.url }, icon: "/brand/attest-app-192.png", badge: "/brand/attest-app-192.png" });
}

async function run(trigger: "push" | "check") {
  const result = await Promise.race([runDeviceUnlock({ deadline: Date.now() + RUN_MS, wait: trigger === "push" }).catch((e): DeviceRunResult => ({ status: "error", message: e instanceof Error ? e.message : "error" })), timeout(RUN_MS + 3000)]);
  await tellPages(result).catch(() => {});
  let notices: Notice[] = [];
  if (result.status === "done") {
    notices = noticesFor(trigger === "push" ? result.outcomes : result.outcomes.filter((o) => o.kind === "unlocked" || o.kind === "held" || o.kind === "refused"), trigger === "push" ? result.recent : [], { hideTitles: result.hideTitles });
  } else if (result.status === "off" && trigger === "push") {
    notices = [{ title: "This device no longer unlocks documents", body: "It was turned off. You can turn it back on from your Security page.", tag: "unlock-device", url: "/dashboard/security" }];
  } else if (result.status === "error" && trigger === "push") {
    notices = [{ title: "Tap to finish unlocking", body: "A document is waiting to be unlocked for a new signer. Tap to open Attest, and it finishes there.", tag: "unlock-check", url: "/dashboard/agreements" }];
  }
  // Every push shows a notification (Chrome requires it, Safari drops the subscription otherwise).
  if (trigger === "push" && notices.length === 0) {
    notices = [{ title: "Nothing to unlock right now", body: "Attest asked this device to check, and nothing is waiting for a new signer.", tag: "unlock-check", url: "/dashboard/agreements" }];
  }
  for (const n of notices) await show(n).catch(() => {});
}

self.addEventListener("push", (e) => e.waitUntil(run("push")));

self.addEventListener("message", (e) => {
  const data = e.data as { type?: string } | null;
  if (data?.type === "check") e.waitUntil(run("check"));
  if (data?.type === "version") (e.source as Client | null)?.postMessage({ type: "unlock-version", version: UNLOCK_WORKER_VERSION });
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = new URL((e.notification.data as { url?: string } | null)?.url ?? "/dashboard/agreements", self.location.origin);
  if (url.origin !== self.location.origin) return;
  e.waitUntil(
    (async () => {
      const tabs = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      const tab = tabs.find((c) => new URL(c.url).origin === self.location.origin) as WindowClient | undefined;
      if (tab) {
        await tab.focus();
        await tab.navigate(url.href).catch(() => {});
        return;
      }
      await self.clients.openWindow(url.href);
    })()
  );
});

// The push service replaced the subscription: subscribe again with Attest's key, and tell Attest.
self.addEventListener("pushsubscriptionchange", (e) => {
  e.waitUntil(
    (async () => {
      const s = await deviceState();
      if (!s) return;
      const { vapidPublicKey } = (await (await fetch("/api/unlock/config", { cache: "no-store" })).json()) as { vapidPublicKey: string | null };
      if (!vapidPublicKey) return;
      const key = Uint8Array.from(atob(vapidPublicKey.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (vapidPublicKey.length % 4)) % 4)), (c) => c.charCodeAt(0));
      const sub = await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      const j = sub.toJSON() as { endpoint: string; keys: { p256dh: string; auth: string } };
      await deviceFetch(s, "PATCH", "/api/unlock/device", { push: { endpoint: j.endpoint, p256dh: j.keys.p256dh, auth: j.keys.auth } });
    })().catch(() => {})
  );
});
