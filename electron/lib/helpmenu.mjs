// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// 앱 메뉴의 "문제 신고" 항목(순수 로직 - electron 비의존, 단위 테스트 가능).
// 웹 UI의 도움말 메뉴와 같은 이슈 양식으로 연결한다. 이 항목은 아무것도 전송하지 않고
// 양식이 열리는 브라우저 탭만 띄운다. 스캔 결과 화면의 "문제 신고" 패널은 웹 UI가 그린다.

// .github/ISSUE_TEMPLATE/bug_report.yml. 웹 UI의 ISSUE_FORM_URL(src/lib/diagnostics.ts)과 같은 값이며,
// helpmenu.test.mjs가 양식 파일 존재와 두 값의 일치를 확인한다.
export const ISSUE_FORM_URL = "https://github.com/sktelecom/bomlens/issues/new?template=bug_report.yml";

// 앱 메뉴 전체 템플릿. Electron 기본 메뉴는 읽어 와서 덧붙일 수 없으므로(getApplicationMenu가
// 돌려준 인스턴스의 변경은 문서상 미지원) 같은 구성을 role로 새로 만든다. 기본 메뉴와 같은
// 항목(편집 단축키, 보기, 창)을 유지하고 Help에 문제 신고를 더한다. macOS는 앱 메뉴가 맨 앞에 온다.
export function buildMenuTemplate({ platform, reportLabel, helpLabel, onReport }) {
  const template = [];
  if (platform === "darwin") template.push({ role: "appMenu" });
  template.push({ role: "fileMenu" }, { role: "editMenu" }, { role: "viewMenu" }, { role: "windowMenu" });
  template.push({
    role: "help",
    label: helpLabel,
    submenu: [{ label: reportLabel, click: onReport }],
  });
  return template;
}
