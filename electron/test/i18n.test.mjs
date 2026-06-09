// i18n.mjs의 순수 로직 단위 테스트(electron 비의존). 시작 화면의 실제 렌더는
// Windows/데스크톱 워크플로우에서 캡처로 확인한다.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mainMessages, pickLang, SUPPORTED } from "../lib/i18n.mjs";

test("pickLang maps Korean locales to ko", () => {
  assert.equal(pickLang("ko"), "ko");
  assert.equal(pickLang("ko-KR"), "ko");
  assert.equal(pickLang("KO-kr"), "ko");
});

test("pickLang falls back to English for everything else", () => {
  assert.equal(pickLang("en-US"), "en");
  assert.equal(pickLang("fr"), "en");
  assert.equal(pickLang(""), "en");
  assert.equal(pickLang(undefined), "en");
});

test("SUPPORTED lists English first as the fallback", () => {
  assert.deepEqual(SUPPORTED, ["en", "ko"]);
});

test("mainMessages returns the locale's strings with working interpolation", () => {
  const en = mainMessages("en-US");
  assert.equal(en.ready, "Ready. Opening the UI.");
  assert.equal(en.image("ghcr.io/x:1"), "Image: ghcr.io/x:1");
  assert.equal(en.startFailed("boom"), "Startup failed: boom");

  const ko = mainMessages("ko-KR");
  assert.equal(ko.ready, "준비 완료. UI를 엽니다.");
  assert.match(ko.image("ghcr.io/x:1"), /ghcr\.io\/x:1$/);
});

test("every main message key exists in both languages", () => {
  const en = mainMessages("en");
  const ko = mainMessages("ko");
  assert.deepEqual(Object.keys(en).sort(), Object.keys(ko).sort());
});
