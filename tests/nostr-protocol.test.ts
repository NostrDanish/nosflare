import test from "node:test";
import assert from "node:assert/strict";
import {
  isReplaceableKind,
  isParameterizedReplaceableKind,
  isIncomingReplaceableWinner,
  parseAddressableCoordinate,
} from "../src/nostr-protocol";

const author = "a".repeat(64);
const other = "b".repeat(64);

test("recognizes NIP-01 replaceable kind ranges", () => {
  assert.equal(isReplaceableKind(0), true);
  assert.equal(isReplaceableKind(3), true);
  assert.equal(isReplaceableKind(10000), true);
  assert.equal(isReplaceableKind(19999), true);
  assert.equal(isReplaceableKind(20000), false);
  assert.equal(isReplaceableKind(30000), false);
});

test("recognizes NIP-33 parameterized replaceable kinds", () => {
  assert.equal(isParameterizedReplaceableKind(30000), true);
  assert.equal(isParameterizedReplaceableKind(39999), true);
  assert.equal(isParameterizedReplaceableKind(40000), false);
});

test("replaceable event ordering prefers newer timestamp then lower id", () => {
  assert.equal(isIncomingReplaceableWinner(101, "f".repeat(64), 100, "0".repeat(64)), true);
  assert.equal(isIncomingReplaceableWinner(100, "0".repeat(64), 100, "1".repeat(64)), true);
  assert.equal(isIncomingReplaceableWinner(100, "1".repeat(64), 100, "0".repeat(64)), false);
  assert.equal(isIncomingReplaceableWinner(99, "0".repeat(64), 100, "f".repeat(64)), false);
});

test("parses own replaceable address coordinates", () => {
  assert.deepEqual(parseAddressableCoordinate(`10002:${author}:`, author), {
    kind: 10002, pubkey: author, dTag: "",
  });
  assert.deepEqual(parseAddressableCoordinate(`30023:${author}:article:part:1`, author), {
    kind: 30023, pubkey: author, dTag: "article:part:1",
  });
});

test("rejects malformed, foreign, and non-replaceable address coordinates", () => {
  assert.equal(parseAddressableCoordinate(`30023:${other}:slug`, author), null);
  assert.equal(parseAddressableCoordinate(`1:${author}:slug`, author), null);
  assert.equal(parseAddressableCoordinate(`10002:${author}:unexpected`, author), null);
  assert.equal(parseAddressableCoordinate(`30023:${author}`, author), null);
  assert.equal(parseAddressableCoordinate(`x:${author}:slug`, author), null);
});
