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

데스크톱 앱이나 웹 UI에서는 프로젝트 폴더를 추가하고 스캔을 실행합니다. SDK 이미지가 없으면 이유를 설명하고 구글 약관 링크를 보여 주는 대화상자가 뜹니다. 데스크톱 앱과 Windows 실행 파일 `sbom-ui.bat`에서는 동의하면 대화상자가 이미지를 한 번 빌드합니다. `scan-sbom.sh --ui`나 `docker run`으로 띄운 웹 UI는 이미지를 직접 빌드할 수 없어서, 대화상자가 직접 실행할 `docker build` 명령을 보여 줍니다. 저장소를 복제해 쓰고 있으면 그 복제본의 `docker/android` 폴더에서 빌드하고, 그렇지 않으면 GitHub에서 사용 중인 릴리스의 태그로 빌드 파일을 읽습니다. 릴리스 버전을 알 수 없으면 `main` 브랜치를 읽습니다. 이미지가 생기면 새 스캔 화면에서 스캔을 다시 시작하세요.

명령줄에서는 SDK 이미지가 없으면 스캔이 시작되기 전에 멈추고, API 레벨이 채워진 `docker build` 명령을 출력합니다. 그 명령을 한 번 실행하고(이것이 [구글 SDK 약관](https://developer.android.com/studio/terms)에 동의하는 것입니다) 스캔을 다시 실행하세요.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target ./my-android-app --generate-only
```

빌드 레시피는 `docker/android/Dockerfile`이며, CLI 내려받기 파일과 저장소 클론에 모두 들어 있습니다.

## 사내망이 HTTPS를 검사하면 어떻게 하나요?

SDK 이미지를 만들 때는 `dl.google.com`에서 안드로이드 명령줄 도구와 플랫폼을 내려받습니다. HTTPS를 검사하는 프록시는 이 통신을 회사 인증서(CA)로 다시 서명하는데, 이미지 빌드는 그 CA를 신뢰하지 않습니다. `SBOM_EXTRA_CA_CERTS`는 스캔 컨테이너에만 적용되고 `docker build`에는 적용되지 않으므로 여기서는 도움이 되지 않습니다. 빌드는 `curl: (60) SSL certificate problem`으로 멈추거나, `[build] ERROR: sdk-install: Android platform ... was not installed`와 함께 `sdkmanager`의 `PKIX path building failed` 줄을 출력하고 멈춥니다. 데스크톱 앱과 `sbom-ui.bat`의 대화상자도 같은 레시피를 실행하므로 똑같이 실패합니다. 이때는 CA를 넣어 이미지를 직접 빌드하세요.

1. 레시피 폴더를 복사하고, 회사 CA를 `company-ca.pem` 이름의 PEM 파일로 Dockerfile 옆에 둡니다.

   ```bash
   cp -R docker/android my-android-sdk && cp /path/to/company-ca.pem my-android-sdk/
   ```

2. `my-android-sdk/Dockerfile`에서 첫 번째 `RUN`(`unzip`과 `curl`이 있는지 확인하는 줄) 뒤, `RUN mkdir -p "$ANDROID_HOME/cmdline-tools"` 줄 앞에 아래 줄을 추가합니다. 기반 이미지가 Red Hat Enterprise Linux 9이므로 시스템 저장소는 `update-ca-trust`로, 자바 저장소는 `keytool`로 갱신합니다.

   ```dockerfile
   COPY company-ca.pem /tmp/company-ca.pem
   RUN cp /tmp/company-ca.pem /etc/pki/ca-trust/source/anchors/company-ca.pem \
       && update-ca-trust extract \
       && keytool -importcert -noprompt -trustcacerts -alias company-ca -file /tmp/company-ca.pem -cacerts -storepass changeit
   ```

3. 스캔이 출력한 `docker build` 명령을 `docker/android` 대신 `my-android-sdk` 폴더로 바꿔 실행합니다. 실행하면 [구글 SDK 약관](https://developer.android.com/studio/terms)에 동의하는 것입니다.

스캔 자체도 Gradle 빌드가 의존성을 내려받을 때 CA가 필요합니다. [사내 인증서는 어떻게 신뢰하게 하나요?](company-network.ko.md#사내-인증서는-어떻게-신뢰하게-하나요)에 따라 `SBOM_EXTRA_CA_CERTS`를 설정하세요.

## 사내 저장소도 되나요?

사내 저장소의 의존성은 본인의 Gradle 빌드가 쓰는 인증 정보가 있어야 받을 수 있습니다. BomLens는 `~/.gradle/gradle.properties`, `~/.gradle/init.gradle`, `~/.gradle/init.gradle.kts`, `~/.gradle/init.d` 폴더가 있으면 읽기 전용으로 스캔에 넘깁니다. 로컬 빌드에서 하듯 저장소 주소와 인증 정보를 그 파일에 적어 두세요. 도구별로 설정을 어디서 읽는지, 의존성이 해석되지 않을 때 무엇을 확인하는지는 [Maven으로 빌드하는 자바 프로젝트는 어떻게 스캔하나요?](java-maven.ko.md#사내-저장소도-되나요)에 있습니다.

## 결과에는 무엇이 담기나요?

SBOM에는 release 런타임 클래스패스가 해석한 라이브러리가 담기므로, 테스트에만 쓰는 라이브러리는 없습니다. Gradle 빌드를 아예 실행하지 못하면 BomLens는 버전 카탈로그가 선언한 라이브러리로 대신합니다. 이는 빌드가 실제로 쓰는 것이 아니라 선언일 뿐이어서 결과 등급이 partial이 됩니다. 완전성 등급은 `{Project}_{Version}_completeness.json`과 개요 화면에서 볼 수 있고, partial이면 이유가 함께 적힙니다.

## Gradle 빌드가 실패하면 어떻게 되나요?

Gradle이 release 런타임 클래스패스를 읽기 전에 멈추면 앱의 의존성을 알 수 없습니다. 이때 SBOM은 빌드의 다른 구성이 해석한 라이브러리를 넣지 않습니다. 그 라이브러리는 앱에 포함되는 것이 아니라 빌드 도구와 테스트 도구(Unified Test Platform, `ddmlib`, AndroidX 테스트 라이브러리)이기 때문입니다. 결과 등급은 unreliable이고, 사유에는 Gradle이 보고한 오류가 그대로 인용됩니다. 스캔 로그에도 Gradle의 `What went wrong` 내용이 마지막 몇 줄보다 먼저 나옵니다.

흔한 원인은 `android.useAndroidX=true`가 없는 프로젝트입니다. Android Studio는 새 프로젝트를 만들 때 이 줄을 `gradle.properties`에 적어 두므로, 이 파일 없이 복사한 프로젝트는 `contains AndroidX dependencies, but the android.useAndroidX property is not enabled` 오류로 실패합니다. 프로젝트 최상위 폴더의 `gradle.properties`에 이 줄을 추가한 뒤 다시 스캔하세요.

```properties
android.useAndroidX=true
```

감지 규칙과 Java 이미지는 [지원 생태계](../reference/ecosystems.ko.md#android)를 보세요.
