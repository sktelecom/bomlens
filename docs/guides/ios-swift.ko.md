---
description: Swift Package Manager나 CocoaPods를 쓰는 iOS와 macOS 앱을 스캔합니다. 커밋해 둘 잠금 파일, Mac 없이 읽는 범위, Xcode가 관리하는 의존성에서 기대할 결과를 안내합니다.
---

# SwiftPM이나 CocoaPods를 쓰는 iOS 앱은 어떻게 스캔하나요?

BomLens는 프로젝트에 이미 있는 잠금 파일을 읽습니다. 그래서 스캔에 Mac, Xcode, CocoaPods 설치가 필요하지 않습니다. 준비할 것은 스캔하는 폴더에 잠금 파일이 들어 있는지 확인하는 일뿐입니다.

## 무엇을 읽나요?

| 의존성 관리자 | 파일 | 없으면 |
|---------------|------|--------|
| Swift Package Manager | `Package.swift` 옆의 `Package.resolved` | 스캔이 `swift package resolve`를 실행하며, 모든 의존성에 네트워크로 접근해야 합니다 |
| CocoaPods | `Podfile.lock` | `pod install`을 한 번 실행해 파일을 커밋하세요. BomLens가 직접 파싱합니다 |

최상위에 매니페스트가 없어도 세 단계 아래까지 Xcode 프로젝트, `Package.swift`, `Podfile`, `Package.resolved`가 있으면(예: `App/App.xcodeproj`) Swift 프로젝트로 스캔합니다.

## 어떻게 실행하나요?

데스크톱 앱이나 웹 UI에서는 프로젝트 폴더를 추가하고 스캔을 실행합니다. 명령줄에서는 다음과 같이 실행합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target ./my-ios-app --generate-only
```

스캔은 cdxgen 프로젝트의 Swift 이미지를 씁니다. 이 이미지의 크기는 BomLens에 기록되어 있지 않아 받기 전 크기 안내에 나오지 않습니다. 스캔 뒤 `scripts/check-setup.sh`를 실행하면 디스크에서 차지한 크기를 볼 수 있습니다.

## 비공개 의존성은 어떻게 하나요?

`Package.resolved`를 커밋하세요. 이 파일이 있으면 스캔이 네트워크 해석을 건너뛰고 파일에서 버전을 읽으므로, 비공개 Git 의존성을 클론하지 않아도 됩니다. 없으면 해석 단계가 `BOMLENS_PREP_TIMEOUT`초(기본 900초) 뒤에 멈춥니다. Git이 로그인을 요구하지 않도록 설정되어 있기 때문입니다. 비공개 CocoaPods 소스는 따로 할 일이 없습니다. `Podfile.lock`에 모든 Pod가 이미 적혀 있습니다.

## 결과에서 빠지는 것은 무엇인가요?

UIKit처럼 Xcode가 제공하는 플랫폼 프레임워크는 Linux 스캐너가 해석하지 않으며, 자체 라이선스도 없습니다. 그래서 앱의 SBOM에 라이선스가 없는 구성요소가 몇 개 있을 수 있습니다. `{Project}_{Version}_completeness.json`이나 개요 화면에서 완전성 등급을 확인하세요. partial이면 이유가 함께 나옵니다.

자세한 내용과 번들 예제는 [지원 생태계](../reference/ecosystems.ko.md#swift--ios)에 있습니다.
