let pendingBytes = 0

export const addObservedEgressBytes = (bytes: number) => {
  if (!Number.isFinite(bytes) || bytes <= 0) return
  pendingBytes += Math.max(0, Math.round(bytes))
}

export const takeObservedEgressBytes = () => {
  const bytes = pendingBytes
  pendingBytes = 0
  return bytes
}

export const restoreObservedEgressBytes = (bytes: number) => {
  addObservedEgressBytes(bytes)
}

export const peekObservedEgressBytes = () => pendingBytes
