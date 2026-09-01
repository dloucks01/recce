// P1-6 — Web n-day attack chain.
//
// Six-step story from "we fingerprinted the surface" through KEV match and
// safe verify to "we have an authenticated session". Consumes the shared
// ChainView from AttackChain.tsx.
import { getAttackChainWeb } from "../api";
import { ChainView } from "./AttackChain";

interface Props {
  onOpenHost?: (ip: string) => void;
}
export function AttackChainWeb({ onOpenHost }: Props = {}) {
  return (
    <ChainView
      title="Web n-day"
      fetcher={getAttackChainWeb}
      loadingLabel="Loading web n-day chain…"
      allProvenMessage="Every step is proven — web n-day walk-through complete end-to-end."
      onOpenHost={onOpenHost}
    />
  );
}
