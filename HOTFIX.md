# v7-hotfix branch

Built on `v7-production` (= upstream tag **v7.9.45**, the version live on relay.0xprivacy.online).

## Hotfix: `patches/0001-do-hibernation-idle-fix.patch`

Apply with: `git apply patches/0001-do-hibernation-idle-fix.patch`

**Problem (cost bug):** the RelayWebSocket Durable Object never truly hibernates:

1. `webSocketMessage` reset `lastActivityTime` on *every* message — REQ/EOSE/CLOSE
   protocol chatter kept the idle timer perpetually fresh.
2. The alarm handler rescheduled itself every 5 minutes as long as any WebSocket
   (even a fully hibernated one) was attached, so the DO billed wall-clock time
   around the clock.

**Fix:**

1. `lastActivityTime` is now only updated when an `EVENT` message arrives
   (after JSON parse), not on subscription chatter.
2. The alarm handler now checks `idleTime >= IDLE_TIMEOUT`: if the DO has been
   quiet it runs cleanup and does NOT reschedule the alarm. Subscriptions live in
   DO storage and `webSocketMessage` wakes the DO on demand, so this is safe.

The bundled `tsconfig.json` hunk (`moduleResolution: node` -> `bundler`) is only a
toolchain compatibility fix for current TypeScript versions (`tsc --noEmit`
otherwise errors with TS5108).

Verified: `tsc --noEmit` clean, `npm run build` produces a 209.6kb worker.js.
