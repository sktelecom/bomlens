// pullprogress.mjs의 순수 로직 단위 테스트. 집계 픽스처는 손으로 지어낸 것이 아니라
// 실제 non-TTY `docker pull alpine:3.19` 출력을 그대로 캡처한 것이다
// (test/fixtures/docker-pull-nontty.txt) — 형식을 추측하면 파서가 조용히 틀린다.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { classifyPullFailure, createPullProgress } from "../lib/pullprogress.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const transcript = fs
  .readFileSync(path.join(here, "fixtures", "docker-pull-nontty.txt"), "utf8")
  .split(/\r?\n/)
  .filter(Boolean);

test("aggregates the real docker pull transcript by layer", () => {
  const p = createPullProgress();
  for (const line of transcript) p.feed(line);
  // 등장한 레이어 ID 3개(17a39c…, ef1614…, fd18d7…). "Pulling from"/"Digest"/"Status" 줄과
  // 마지막 이미지 참조 줄은 레이어가 아니다.
  assert.deepEqual(p.snapshot(), { total: 3, complete: 1 });
});

test("counts a layer that never emitted 'Pulling fs layer'", () => {
  // 실제 출력에서 ef1614…는 Download complete로 처음 등장한다. "Pulling fs layer" 줄만
  // 세면 총계를 놓친다.
  const p = createPullProgress();
  p.feed("ef1614f30685: Download complete");
  assert.equal(p.snapshot().total, 1);
});

test("treats 'Already exists' as complete", () => {
  const p = createPullProgress();
  p.feed("17a39c0ba978: Already exists");
  p.feed("ef1614f30685: Pull complete");
  assert.deepEqual(p.snapshot(), { total: 2, complete: 2 });
});

test("feed returns a value only when the tally changes", () => {
  const p = createPullProgress();
  assert.deepEqual(p.feed("17a39c0ba978: Pulling fs layer"), { total: 1, complete: 0 });
  // 같은 레이어의 상태만 바뀌고 집계는 그대로 -> null.
  assert.equal(p.feed("17a39c0ba978: Downloading"), null);
  assert.deepEqual(p.feed("17a39c0ba978: Pull complete"), { total: 1, complete: 1 });
});

test("ignores non-layer lines", () => {
  const p = createPullProgress();
  for (const line of [
    "3.19: Pulling from library/alpine",
    "Digest: sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
    "Status: Downloaded newer image for alpine:3.19",
    "docker.io/library/alpine:3.19",
    "",
  ]) {
    assert.equal(p.feed(line), null);
  }
  assert.deepEqual(p.snapshot(), { total: 0, complete: 0 });
});

test("strips a TTY progress bar tail if one shows up", () => {
  const p = createPullProgress();
  p.feed("17a39c0ba978: Downloading [====>      ]  12.3MB/120.5MB");
  p.feed("17a39c0ba978: Pull complete");
  assert.deepEqual(p.snapshot(), { total: 1, complete: 1 });
});

test("classifyPullFailure recognises each failure mode", () => {
  assert.equal(classifyPullFailure("anything", "timeout"), "timeout");
  assert.equal(classifyPullFailure("write /var/lib/docker: no space left on device"), "disk");
  assert.equal(
    classifyPullFailure("dial tcp: lookup ghcr.io on 10.0.0.1:53: no such host"),
    "dns",
  );
  assert.equal(
    classifyPullFailure("x509: certificate signed by unknown authority"),
    "proxy",
  );
  assert.equal(classifyPullFailure("proxyconnect tcp: dial tcp 10.1.1.1:8080"), "proxy");
  assert.equal(classifyPullFailure("error parsing HTTP 403 response body"), "proxy");
  assert.equal(classifyPullFailure("pull access denied for foo, repository does not exist"), "auth");
  assert.equal(classifyPullFailure("unauthorized: authentication required"), "auth");
  assert.equal(classifyPullFailure("something we have never seen"), "unknown");
  assert.equal(classifyPullFailure(""), "unknown");
});

test("disk and dns win over the broader proxy pattern", () => {
  // 프록시 환경에서 디스크가 차면 두 신호가 같이 나올 수 있다. 실제 조치가 갈리므로
  // 더 특정적인 쪽을 골라야 한다.
  assert.equal(
    classifyPullFailure("403 Forbidden ... no space left on device"),
    "disk",
  );
  assert.equal(classifyPullFailure("403 Forbidden ... no such host"), "dns");
});
