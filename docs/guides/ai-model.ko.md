---
description: BomLens로 HuggingFace AI 모델의 CycloneDX ML-BOM을 모델 id만으로 생성하고(G7 최소 요소 적합성 포함) 모델 카드와 데이터셋을 확인하는 방법. 소스 코드나 모델 다운로드가 필요 없습니다.
---

# AI 모델 SBOM 가이드

HuggingFace 모델의 CycloneDX ML-BOM(머신러닝 SBOM)을 생성하고 결과를 읽는 방법입니다. 모델 id만 주면 BomLens가 모델 카드 메타데이터를 네트워크로 가져옵니다. 소스 코드도, 모델 가중치 다운로드도 필요 없습니다.

설계 배경과 규제 맥락(EU AI Act, G7)은 메인테이너용 [AI SBOM 대응 준비](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/ai-sbom-readiness.md) 문서를 참고하세요.

## 동작 방식

AI 모델의 "구성요소 명세"는 모델 카드입니다. 식별자, 아키텍처, 태스크, 라이선스, 공급자, 데이터셋, 파일 무결성 등이 담깁니다. BomLens는 [OWASP AIBOM Generator](https://github.com/GenAI-Security-Project/aibom-generator)로 HuggingFace 모델 카드를 읽어 모델과 참조 데이터셋 중심의 **CycloneDX 1.7 ML-BOM**을 만들고, **G7 최소 요소 적합성** 검사(권고)를 더합니다. 모델에는 패키지 의존성이 없으므로 보안(CVE) 보고서는 생성하지 않습니다.

전체 도구 흐름은 [입력 형태별 파이프라인](../concepts/pipeline-by-input.ko.md)에 있습니다.

## 이미지 준비

AI 모델 SBOM 생성에는 OWASP AIBOM Generator가 들어 있는 별도 이미지가 필요합니다. opt-in이고 네트워크(HuggingFace)에 접근하므로 기본 이미지가 아니라 별도 이미지로 제공합니다.

```bash
docker pull ghcr.io/sktelecom/bomlens-aibom:latest
```

이 이미지가 AI 모델 스캔의 기본값이므로 `--model`만 붙여도 받습니다. 다른 태그를 쓰려면 환경변수 `SBOM_AIBOM_IMAGE`로 지정합니다.

## 실행하기

### 웹 UI에서

aibom 이미지로 UI를 실행하면 AI 모델 타일이 활성화됩니다. 그 뒤 모델 id를 입력하고 스캔합니다.

```bash
SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens-aibom:latest ./scripts/scan-sbom.sh --ui
#   Windows: sbom-ui.bat 더블클릭 전에 SBOM_SCANNER_IMAGE를 지정
```

새 스캔의 소스 타일에서 **AI 모델**을 고르고, HuggingFace 모델 id를 `org/model` 형식으로 입력한 뒤(예: `google-bert/bert-base-uncased`, `Qwen/Qwen2.5-0.5B` — 컬렉션 이름이나 전체 URL이 아닌) 스캔을 실행합니다.

### CLI에서

모델 id를 `--model`에 넘깁니다.

```bash
./scripts/scan-sbom.sh --project bert-base --version 1.0.0 \
  --model "google-bert/bert-base-uncased" --generate-only
```

`--model`은 `--target`, `--analyze`, `--git`, `--merge`와 함께 쓸 수 없습니다. `bomlens-aibom` 이미지를 자동으로 받고, 고지문과 위험 보고서를 만들며, 보안 보고서는 건너뜁니다(모델에는 패키지 CVE가 없음).

## 결과 읽기

웹 UI에서 AI/ML SBOM은 좌측 레일에 두 섹션을 추가합니다.

**모델·데이터셋** — 각 모델 카드의 식별자, 아키텍처, 태스크, 라이선스, 공급자, 무결성과 공개 4축 패널(가중치 / 아키텍처 / 학습 데이터 / 학습 과정 — 모델 카드에 문서화된 범위), 그리고 모델이 참조하는 데이터셋입니다.

![모델·데이터셋 — 모델 카드와 공개 4축](../images/web-ui-models.png)

**적합성** — AI 모델 SBOM에서는 이 섹션에 G7 최소 요소 검사(모두 권고)가 기본 형식 적합성 검사와 함께 더해집니다. G7 7개 클러스터(메타데이터, 시스템, 모델, 데이터셋, 인프라, 보안, KPI) 전체를 다루며, 각 항목에는 데이터 출처가 표시됩니다. 도구가 SBOM에서 직접 읽었는지, 신호로 도출했는지, 아니면 자동으로 확인할 수 없어 사람이 검토해야 하는지를 구분해, 도구가 자동으로 채운 범위와 사람이 채워야 할 부분을 함께 보여줍니다. 각 항목은 무엇인지와 어떻게 충족하는지를 안내합니다.

![적합성 — AI SBOM의 G7 권고 하위 블록](../images/web-ui-g7.png)

같은 데이터는 산출물에도 있습니다. ML-BOM(`_bom.json`, CycloneDX 1.7)과 적합성 보고서(`_conformance.*`)입니다.

## 한계

- 결과는 HuggingFace 모델 카드만큼만 충실합니다. 카드가 빈약하면 ML-BOM도 빈약하고, G7 검사도 카드에 문서화된 범위를 반영할 뿐 모델 자체를 감사하지는 않습니다.
- 메타데이터를 네트워크로 가져오므로, 비공개·게이트 모델은 접근 권한(환경의 HuggingFace 토큰)이 필요하며 오프라인 사용은 지원하지 않습니다.
- 모델 id는 `org/model` 형식이어야 합니다. 컬렉션 이름이나 전체 URL은 해석되지 않습니다.

---

> **관련 문서**: [입력 형태별 파이프라인](../concepts/pipeline-by-input.ko.md) | [웹 UI 레퍼런스](../reference/ui.ko.md) | [사용 가이드](../reference/cli.ko.md)
