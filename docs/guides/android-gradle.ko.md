---
description: Gradle로 빌드하는 안드로이드 앱을 스캔합니다. 준비할 것(Docker 메모리, Android SDK 이미지)과 첫 스캔에서 받는 것, 결과를 읽는 방법을 안내합니다.
---

# Gradle로 빌드하는 안드로이드 앱은 어떻게 스캔하나요?

안드로이드 프로젝트는 일반 자바 프로젝트와 달리 Android SDK 이미지가 하나 더 필요합니다. 이 이미지는 BomLens가 사용자의 컴퓨터에서 한 번 빌드합니다. 구글의 SDK 약관이 재배포를 허용하지 않아 BomLens가 이미지를 배포할 수 없으므로, 약관에 동의하면 로컬에서 만듭니다. 이미지가 생긴 뒤에는 다른 소스 스캔과 같은 방식으로 실행됩니다.

## 무엇을 준비하나요?

- 메모리 약 4GB를 할당한 Docker 엔진. 스캔 안에서 Gradle 빌드가 실행되는데, 메모리가 모자라면 빌드가 종료되고 결과가 직접 의존성만 담긴 얕은 결과로 바뀝니다. 늘리는 방법은 [요구 사항](../start/first-scan.ko.md#요구-사항)에 있습니다.
- Gradle 루트(`settings.gradle[.kts]` 또는 `build.gradle[.kts]`)가 있는 프로젝트 폴더. Gradle 래퍼가 있다면 `gradle/wrapper/gradle-wrapper.properties`가 Gradle 8.5 이상을 가리켜야 합니다. SDK 이미지가 Java 21에서 실행되기 때문입니다.
- 디스크 공간. SDK 이미지는 약 6.3GB이고 `compileSdk` 레벨마다 이미지가 따로 필요해서, 레벨이 다른 앱 두 개면 약 12.6GB입니다. 스캐너 이미지가 약 1.4GB 더해집니다. 전체 이미지 목록은 [디스크 사용량과 정리](../reference/docker-image.ko.md#이미지가-디스크를-얼마나-차지하나요)에 있습니다.

## 어떻게 스캔하나요?

데스크톱 앱이나 웹 UI에서는 프로젝트 폴더를 추가하고 스캔을 실행합니다. SDK 이미지가 없으면 이유를 설명하고 구글 약관 링크를 보여 주는 대화상자가 뜨며, 동의하면 이미지를 한 번 빌드합니다. 이후 새 스캔 화면에서 스캔을 다시 시작하세요.

명령줄에서는 SDK 이미지가 없으면 스캔이 시작되기 전에 멈추고, API 레벨이 채워진 `docker build` 명령을 출력합니다. 그 명령을 한 번 실행하고(이것이 [구글 SDK 약관](https://developer.android.com/studio/terms)에 동의하는 것입니다) 스캔을 다시 실행하세요.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target ./my-android-app --generate-only
```

빌드 레시피는 `docker/android/Dockerfile`이며, CLI 내려받기 파일과 저장소 클론에 모두 들어 있습니다.

## 사내 저장소도 되나요?

사내 저장소의 의존성은 본인의 Gradle 빌드가 쓰는 인증 정보가 있어야 받을 수 있습니다. BomLens는 `~/.gradle/gradle.properties`, `~/.gradle/init.gradle`, `~/.gradle/init.gradle.kts`, `~/.gradle/init.d` 폴더가 있으면 읽기 전용으로 스캔에 넘깁니다. 로컬 빌드에서 하듯 저장소 주소와 인증 정보를 그 파일에 적어 두세요. 도구별로 설정을 어디서 읽는지, 의존성이 해석되지 않을 때 무엇을 확인하는지는 [Maven으로 빌드하는 자바 프로젝트는 어떻게 스캔하나요?](java-maven.ko.md#사내-저장소도-되나요)에 있습니다.

## 결과에는 무엇이 담기나요?

SBOM에는 release 런타임 클래스패스가 해석한 라이브러리가 담기므로, 테스트에만 쓰는 라이브러리는 없습니다. Gradle 빌드를 아예 실행하지 못하면 BomLens는 버전 카탈로그가 선언한 라이브러리로 대신합니다. 이는 빌드가 실제로 쓰는 것이 아니라 선언일 뿐이어서 결과 등급이 partial이 됩니다. 완전성 등급은 `{Project}_{Version}_completeness.json`과 개요 화면에서 볼 수 있고, partial이면 이유가 함께 적힙니다.

감지 규칙과 Java 이미지는 [지원 생태계](../reference/ecosystems.ko.md#android)를 보세요.
