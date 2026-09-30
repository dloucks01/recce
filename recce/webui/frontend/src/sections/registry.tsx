// The workflow-phased section registry: order = engagement flow. The left nav
// rail + the section router both read this single source of truth.
import { ComponentType } from "react";
import { SectionId, SectionProps } from "../nav";
import { Overview } from "./Overview";
import { Hosts } from "./Hosts";
import { Findings } from "./Findings";
import { Scan } from "./Scan";
import { Exploit } from "./Exploit";
import { Sessions } from "./Sessions";
import { Oplog } from "./Oplog";
import { Creds } from "./Creds";
import { Report } from "./Report";

export type SectionDef = {
  id: SectionId;
  label: string;
  Component: ComponentType<SectionProps>;
};

export const SECTIONS: SectionDef[] = [
  { id: "overview", label: "Overview", Component: Overview },
  { id: "scan",     label: "Scan",     Component: Scan },
  { id: "hosts",    label: "Hosts",    Component: Hosts },
  { id: "findings", label: "Findings", Component: Findings },
  { id: "exploit",  label: "Exploit",  Component: Exploit },
  { id: "sessions", label: "Sessions", Component: Sessions },
  { id: "oplog",    label: "Op log",   Component: Oplog },
  { id: "creds",    label: "Creds",    Component: Creds },
  { id: "report",   label: "Report",   Component: Report },
];

export const SECTION_MAP: Record<SectionId, SectionDef> =
  Object.fromEntries(SECTIONS.map((s) => [s.id, s])) as Record<SectionId, SectionDef>;
