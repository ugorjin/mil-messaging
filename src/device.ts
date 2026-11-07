/**
 * Device posture check that must pass before a classified message is opened.
 *
 * PROTOTYPE NOTE: the state here is self-reported. In production it comes from
 * hardware-backed attestation (Apple App Attest / Google Play Integrity / Android
 * Key Attestation) checked by the server, plus the organisation's MDM.
 */
export interface DeviceState {
  deviceId: string;
  mdmEnrolled: boolean;
  rooted: boolean;
  /** Date of the OS security patch level, as an ISO date (YYYY-MM-DD). */
  osPatchDate: string;
  /** Screenshots and screen recording blocked (Android FLAG_SECURE / iOS capture detection). */
  screenCaptureBlocked: boolean;
}

export interface DevicePolicy {
  maxPatchAgeDays: number;
}

export const DEFAULT_DEVICE_POLICY: DevicePolicy = { maxPatchAgeDays: 90 };

/** Returns the list of problems; an empty list means the device is allowed. */
export function deviceViolations(d: DeviceState, now: number, policy = DEFAULT_DEVICE_POLICY): string[] {
  const v: string[] = [];
  if (!d.mdmEnrolled) v.push('device not enrolled in MDM');
  if (d.rooted) v.push('device is rooted/jailbroken');
  if (!d.screenCaptureBlocked) v.push('screen capture not blocked');
  const patch = Date.parse(d.osPatchDate);
  if (Number.isNaN(patch)) v.push('unknown OS patch level');
  else if ((now - patch) / 86_400_000 > policy.maxPatchAgeDays) v.push('OS security patch too old');
  return v;
}
