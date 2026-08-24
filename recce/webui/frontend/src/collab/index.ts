// Barrel — every existing `from "./collab"` import keeps working after the split.
// The folder replaces the old collab.tsx file 1:1.

export { CollabProvider, useCollab } from "./CollabContext";
export type { CollabCtx } from "./CollabContext";

export { PresenceBar } from "./presence";
export { OwnerProgress, MyQueue, TeamCoverage, ownerStats } from "./coverage";
export type { OwnerStat } from "./coverage";
export { ActivityButton } from "./activity";
export { ChatButton } from "./chat";
export { AssignControl, LabelChips, PortStatus } from "./assign";
export { AddMenu } from "./AddMenu";
