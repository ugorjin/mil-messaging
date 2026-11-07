/**
 * Enrollment: what a security officer does when issuing a user their device and token.
 *
 * The client generates its own Signal identity key and pre-keys; the token
 * generates the clearance key. Only public keys go to the authority, which signs them.
 */
import type { Authority } from './authority.ts';
import type { Label } from './classification.ts';
import { Client, type ClientOptions } from './client.ts';
import { HardwareToken } from './token.ts';

const DAY = 86_400_000;

export interface EnrollOptions {
  pin: string;
  /** Omit for a user with no clearance. */
  clearance?: Label;
  validDays?: number;
}

export async function enroll(authority: Authority, o: ClientOptions & EnrollOptions): Promise<{ client: Client; token: HardwareToken }> {
  const validMs = (o.validDays ?? 365) * DAY;
  const client = await Client.create(o);
  const token = new HardwareToken(client.userId, o.pin);
  const enrollment = authority.issueEnrollment(client.userId, client.aci, client.signalIdentityKey, validMs);
  const clearance = o.clearance
    ? authority.issueClearance(client.userId, o.clearance, token.generateClearanceKey(), validMs)
    : undefined;
  await client.installCertificates(enrollment, authority.issueSenderCertificate(enrollment), clearance);
  return { client, token };
}
