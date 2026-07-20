// i18n.mjs의 순수 로직 단위 테스트(electron 비의존). 시작 화면의 실제 렌더는
// Windows/데스크톱 워크플로우에서 캡처로 확인한다.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mainMessages, pickLang, resolveLang, SUPPORTED } from "../lib/i18n.mjs";

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

test("resolveLang prefers SBOM_LANG over the system locale", () => {
  assert.equal(resolveLang("en", "ko-KR"), "en");
  assert.equal(resolveLang("ko", "en-US"), "ko");
});

test("resolveLang falls back to the system locale when no override is set", () => {
  assert.equal(resolveLang("", "ko-KR"), "ko");
  assert.equal(resolveLang(undefined, "en-US"), "en");
  assert.equal(resolveLang(undefined, undefined), "en");
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

// 영어 사전에 한글이 섞이면 일본어/영어 로캘 사용자가 한국어를 보게 된다. 함수형 문구는
// 소스를 문자열화해 내부 리터럴까지 훑는다 — container.mjs가 한국어를 그대로 던지던
// 회귀(영어 UI에 "docker run 실패: ...")를 CI 실패로 잡기 위한 가드.
test("English messages contain no Hangul", () => {
  const en = mainMessages("en");
  for (const [key, value] of Object.entries(en)) {
    assert.doesNotMatch(String(value), /[가-힣]/, `MAIN.en.${key} contains Hangul`);
  }
});

test("containerError translates each code without leaking the raw code", () => {
  const en = mainMessages("en");
  const ko = mainMessages("ko");
  for (const code of ["run-failed", "exited-early", "not-ready"]) {
    assert.notEqual(en.containerError(code, "90000"), code);
    assert.notEqual(ko.containerError(code, "90000"), code);
  }
  assert.match(en.containerError("run-failed", "port is already allocated"), /already allocated/);
  assert.match(en.containerError("not-ready", "90000"), /90 seconds/);
  // detail이 비었거나 숫자가 아니어도 문구가 깨지지 않는다.
  assert.doesNotMatch(en.containerError("not-ready", undefined), /NaN/);
  assert.doesNotMatch(en.containerError("run-failed", ""), /Details/);
  // 모르는 코드는 그대로 돌려준다(문구가 사라지는 것보다 낫다).
  assert.equal(en.containerError("who-knows", ""), "who-knows");
});
