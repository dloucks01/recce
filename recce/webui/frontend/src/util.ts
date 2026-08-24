// Small, dependency-free helpers shared across the UI. Keep api.ts lean:
// API calls only, not encoding / scoring / formatting.

// Base64 for arbitrary bytes without blowing the argument stack. String.fromCharCode
// takes each byte as a separate argument, so spreading a large Uint8Array trips V8's
// "too many arguments" limit (~64-128k). Chunk it.
export function bytesToB64(bytes: Uint8Array): string {
  const CHUNK = 0x8000; // 32 KB — well under any engine's arg limit
  let bin = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + CHUNK)));
  }
  return btoa(bin);
}

export function strToB64(s: string): string {
  return bytesToB64(new TextEncoder().encode(s));
}

export function b64ToBytes(b64: string): Uint8Array {
  try {
    const raw = atob(b64);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf;
  } catch {
    return new Uint8Array(0);
  }
}
