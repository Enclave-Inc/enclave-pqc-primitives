export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

export function assertByteLength(
  value: Uint8Array,
  expectedBytes: number,
  label: string,
): void {
  if (value.length !== expectedBytes) {
    throw new Error(
      `${label} must be ${expectedBytes} bytes, got ${value.length}`,
    );
  }
}

export function assertNonEmpty(value: Uint8Array, label: string): void {
  if (value.length === 0) {
    throw new Error(`${label} must not be empty`);
  }
}
