// P1-5 — Cloud pivot attack chain.
//
// Six-step story from "IMDS is reachable" all the way to "secrets manager
// was read". Consumes the shared ChainView from AttackChain.tsx — this
// module is a thin binding that hands ChainView the cloud-specific title
// + fetcher.
import { getAttackChainCloud } from "../api";
import { ChainView } from "./AttackChain";

interface Props {
  onOpenHost?: (ip: string) => void;
}
export function AttackChainCloud({ onOpenHost }: Props = {}) {
  return (
    <ChainView
      title="Cloud pivot"
      fetcher={getAttackChainCloud}
      loadingLabel="Loading cloud pivot chain…"
      allProvenMessage="Every step is proven — cloud pivot walk-through complete end-to-end."
      onOpenHost={onOpenHost}
    />
  );
}
