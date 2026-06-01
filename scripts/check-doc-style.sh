#!/usr/bin/env bash
#
# check-doc-style.sh — 마크다운 문서의 AI 문체 장식을 검출하는 PostToolUse 훅.
#
# Claude Code가 .md 파일을 Write/Edit한 직후 실행된다. 코드블록과 표를 제외한
# 산문에서 과한 볼드·화살표 장식·가운뎃점 나열·장식 이모지·기계적 단계 라벨을
# 찾아, 발견 시 stderr로 경고하고 exit 2로 Claude에 피드백한다(차단은 아님).
#
# 기준 문서: docs/korean-style-guide.md
# 입력: stdin으로 Claude Code 훅 페이로드(JSON).
set -euo pipefail

payload=$(cat)
file=$(printf '%s' "$payload" | jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null || true)

# 마크다운이 아니거나, 의존성/메타 문서면 검사하지 않는다.
case "$file" in
  *.md) ;;
  *) exit 0 ;;
esac
case "$file" in
  *node_modules*) exit 0 ;;
  *korean-style-guide.md) exit 0 ;;  # 가이드 자체가 패턴을 예시로 포함
  *humanize.md) exit 0 ;;            # 슬래시 커맨드 정의도 동일
  *CLAUDE.md) exit 0 ;;              # 에이전트 지시문 — 패턴 이름을 본문에 설명
esac
[ -f "$file" ] || exit 0

# 코드블록(``` 토글)과 표 라인(| ...)을 제외한 산문만 추출하고,
# 인라인 코드(`...`)는 기술 표기 오탐을 막기 위해 비운다.
prose=$(awk '
  /^[[:space:]]*```/ { infence = !infence; next }
  infence            { next }
  /^[[:space:]]*\|/  { next }
  { line = $0; gsub(/`[^`]*`/, "", line); print line }
' "$file")

warns=""
add() { warns="${warns}  - $1"$'\n'; }

if printf '%s' "$prose" | grep -q '→'; then
  add "본문 산문에 화살표(→) 장식이 있습니다. 문장으로 푸세요(꼭 필요한 코드 흐름 표기는 백틱 안에 두면 예외)."
fi
if printf '%s' "$prose" | grep -qE '(·[^·]*){3,}'; then
  add "가운뎃점(·) 긴 나열이 있습니다. 쉼표나 문장으로 푸세요."
fi
if printf '%s' "$prose" | grep -qE '(\*\*[^*]+\*\*[^*]*){3,}'; then
  add "한 줄에 볼드가 과도합니다(3개 이상). 핵심 한두 곳만 남기세요."
fi
if printf '%s' "$prose" | grep -qE 'ℹ️|⚡|🚀|💡|✨|🔥|📌|🎯|🎉|👍'; then
  add "꾸밈용 장식 이모지가 있습니다. 제거하세요(표 안 상태표시 ✅/❌는 검사 대상이 아닙니다)."
fi
if printf '%s' "$prose" | grep -qE '\*\*[0-9]+단계 *[—-]|\*\*Step [0-9]'; then
  add "기계적 단계 라벨(**N단계 —)이 있습니다. 순서가 꼭 필요할 때만 번호 목록으로 두세요."
fi

if [ -n "$warns" ]; then
  {
    printf '문서 문체 가이드(docs/korean-style-guide.md) 위반 가능성: %s\n' "$file"
    printf '%s' "$warns"
    printf '산문 기준 검사이며 코드블록·표는 제외했습니다. 가이드대로 다듬어 주세요.\n'
  } >&2
  exit 2
fi
exit 0
