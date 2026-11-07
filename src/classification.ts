/** Classification levels, ordered from lowest to highest. */
export const LEVELS = ['UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'] as const;
export type Level = (typeof LEVELS)[number];

/** A security label: a level plus need-to-know compartments (e.g. "OPS", "SIGINT"). */
export interface Label {
  level: Level;
  compartments: string[];
}

export const rank = (l: Level): number => LEVELS.indexOf(l);

export function isLevel(v: unknown): v is Level {
  return typeof v === 'string' && (LEVELS as readonly string[]).includes(v);
}

/**
 * True when a clearance "dominates" a label: its level is at least the label's
 * level AND it holds every compartment on the label (Bell-LaPadula "no read up").
 */
export function dominates(clearance: Label, label: Label): boolean {
  return rank(clearance.level) >= rank(label.level) && label.compartments.every((c) => clearance.compartments.includes(c));
}

export const formatLabel = (l: Label): string =>
  l.compartments.length ? `${l.level}//${[...l.compartments].sort().join('/')}` : l.level;
