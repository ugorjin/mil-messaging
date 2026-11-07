import { Authority, Client, enroll, RelayServer, type DeviceState, type Label } from '../src/index.ts';

export const PIN = '482913';

export function goodDevice(id: string, now: number): DeviceState {
  return {
    deviceId: id,
    mdmEnrolled: true,
    rooted: false,
    osPatchDate: new Date(now - 10 * 86_400_000).toISOString().slice(0, 10),
    screenCaptureBlocked: true,
  };
}

/** A small world with a controllable clock. */
export function world() {
  const clock = { t: Date.parse('2026-11-07T12:00:00Z') };
  const now = () => clock.t;
  const authority = new Authority({ now });
  const relay = new RelayServer();

  const user = (userId: string, clearance?: Label, validDays?: number) => {
    const client = new Client({ userId, relay, trust: authority, audit: authority.audit, device: goodDevice(`${userId}-phone`, now()), now });
    const token = enroll(authority, client, { pin: PIN, clearance, validDays });
    return { client, token };
  };

  return { clock, authority, relay, user };
}
