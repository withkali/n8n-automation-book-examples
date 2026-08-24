#!/usr/bin/env bash
# 워크플로 JSON에 시크릿이 남아 있는지 검사한다.
# n8n export는 credential '값'을 빼주지만, cURL import로 만든 HTTP Request 노드는
# Authorization 헤더에 토큰이 그대로 박힌 채 나온다. 공개 저장소에서는 이게 유출이다.
set -u
fail=0
pat='xox[baprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|ATATT[A-Za-z0-9_=-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer [A-Za-z0-9._-]{20,}'
while IFS= read -r -d '' f; do
  if grep -nEq "$pat" "$f"; then
    echo "시크릿 의심: $f"
    grep -nE "$pat" "$f" | sed 's/^/   /' | cut -c1-120
    fail=1
  fi
done < <(find . -name '*.json' -not -path './.git/*' -print0)
if [ "$fail" -eq 0 ]; then echo "OK — 시크릿 패턴 없음"; fi
exit $fail
