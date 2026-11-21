---
description: Maven으로 빌드하는 자바 프로젝트를 스캔합니다. Maven과 Gradle 선택, 사내 저장소와 settings.xml, 프록시와 사내 CA 인증서, 의존성 목록이 짧을 때 확인할 점을 안내합니다.
---

# Maven으로 빌드하는 자바 프로젝트는 어떻게 스캔하나요?

Maven 스캔은 컨테이너 안에서 Maven을 실행해 의존성 트리를 해석합니다. 그래서 본인의 빌드와 같은 네트워크 접근과 인증 정보가 필요합니다. 이것이 없으면 결과에는 `pom.xml`에 적힌 의존성만 담기고, 스캔은 그대로 정상 종료됩니다. 이 문서는 무엇을 설정하고 무엇을 확인할지 정리합니다.

## 어떻게 실행하나요?

데스크톱 앱이나 웹 UI에서는 프로젝트 폴더를 추가하고 스캔을 실행합니다. 명령줄에서는 다음과 같이 실행합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target ./my-maven-project --generate-only
```

처음 자바를 스캔하면 디스크에서 약 3.8~5.6GB인 Java 이미지를 받습니다([디스크 사용량과 정리](../reference/docker-image.ko.md#이미지가-디스크를-얼마나-차지하나요) 참고). 엔진의 여유 공간이 그 크기에 2GB를 더한 값보다 적으면 받기 전에 멈추며, `BOMLENS_SKIP_DISK_CHECK=1`을 지정하면 그대로 스캔합니다. Docker 엔진에 메모리 약 4GB를 할당하세요. 모자라면 빌드 단계가 종료되어 결과가 직접 의존성만 담긴 얕은 결과로 바뀝니다.

## pom.xml과 build.gradle이 함께 있으면 어떻게 되나요?

기본값은 Gradle 프로젝트로 읽는 것입니다. Maven으로 읽으려면 `--build-tool maven`(또는 `BOMLENS_BUILD_TOOL=maven`)을 쓰세요. 웹 UI와 데스크톱 앱에서는 두 파일이 모두 있는 폴더에서 새 스캔 화면에 빌드 도구 선택이 나타납니다. 스캔 로그에는 어떤 도구로 읽었는지가 적히고, SBOM에는 `bomlens:build-tool-choice`로 기록됩니다. 두 도구가 같은 프로젝트에서 서로 다른 의존성 집합을 해석할 수 있으니, 고르기 전에 구성요소 개수를 비교해 보세요.

## 사내 저장소도 되나요?

본인의 Maven 설정에 인증 정보가 있으면 됩니다. BomLens는 아래 파일 중 있는 것만 읽기 전용으로 스캔에 넘기고, 내용은 로그에 남기지 않습니다.

| 도구 | 홈 폴더에서 읽는 파일 |
|------|----------------------|
| Maven | `.m2/settings.xml`, `.m2/settings-security.xml` |
| Gradle | `.gradle/gradle.properties`, `.gradle/init.gradle`, `.gradle/init.gradle.kts`, `.gradle/init.d/` |

CLI, `--ui`, 데스크톱 앱은 모두 이렇게 합니다. 더블클릭하는 `sbom-ui.bat`은 넘기지 않으므로, 빌드에 이 파일이 필요한 Windows 사용자는 데스크톱 앱을 쓰세요. 미러 주소와 서버 인증 정보가 든 `settings.xml`은 그대로 사용됩니다. 비밀번호를 암호화했다면 `settings-security.xml`이 같은 폴더에 있어야 합니다. Maven 스캔은 파일을 찾으면 `maven: using the mounted settings.xml`을 로그에 남깁니다.

이 컴퓨터에서 빌드한 프로젝트는 스캔이 사내 저장소에 접속하지 못해도 해석됩니다. BomLens는 사용자의 Maven 로컬 저장소(`settings.xml`의 `<localRepository>`, 없으면 `~/.m2/repository`)도 읽기 전용으로 붙이고, Maven은 BomLens 자체 저장소 다음에 이 폴더를 읽되 여기에 쓰지는 않습니다. Maven이 내려받을 저장소가 응답하지 않으면 Maven을 오프라인(`-o`)으로 실행하고, 로그에 그 사실을 한 줄로 남깁니다. Maven 3.9 이상이 필요하며, 오프라인에서 프로젝트의 `mvnw`가 그보다 낮은 Maven을 실행하면 이미지의 Maven을 대신 씁니다. 저장소에 `maven-dependency-plugin`도 있어야 하므로, `mvn package`만 실행해 왔다면 먼저 `mvn dependency:tree`를 한 번 실행하세요. 붙이지 않으려면 `BOMLENS_MAVEN_USER_REPOSITORY=false`를 설정하세요. 자세한 동작은 [지원 생태계](../reference/ecosystems.ko.md#java-maven)에 있습니다.

사내 의존성이 여전히 빠질 때는 다음을 확인하세요.

- `settings.xml`의 미러 주소는 컨테이너 안에서 접속할 수 있어야 합니다. VPN 클라이언트를 거쳐야만 열리는 주소나 `localhost`는 안 됩니다.
- 받지 못한 의존성은 스캔 로그에 `Could not find artifact ...`로 나옵니다. 의존성 준비 단계가 실패하면 결과 옆에 `{Project}_{Version}_cdxgen.log` 파일이 남습니다.
- 본인 컴퓨터에서 `mvn dependency:tree`로 나오는 개수와 구성요소 개수를 비교하세요. 훨씬 적다면 해석이 실패한 것입니다.

## 프록시 뒤에서는 어떻게 하나요?

이미지는 Docker 엔진이 받으므로 프록시는 셸이 아니라 Docker Desktop이나 Rancher Desktop에서 설정합니다. 스캔 안에서는 환경의 `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`가 전달됩니다. 프록시가 HTTPS를 검사하고 사내 CA로 다시 서명한다면, 그 CA를 PEM 파일로 BomLens에 알려 주세요.

```bash
SBOM_EXTRA_CA_CERTS=/path/to/company-ca.pem ./scripts/scan-sbom.sh --target ./my-maven-project --generate-only
```

이 파일은 스캔 컨테이너의 시스템 인증서 저장소, Node.js, Java 신뢰 저장소에 추가됩니다. `PKIX path building failed`나 `certificate signed by unknown authority`로 실패하면 이 옵션을 알려 주는 `[WARN]` 줄이 출력됩니다. Windows에서 데스크톱 앱은 `SBOM_EXTRA_CA_CERTS`를 환경변수로 읽고, 배치 런처는 `bomlens.settings.txt`에서 읽습니다([설정 파일](../start/no-cli.ko.md#설정-파일-명령줄-불필요)). 이미지 다운로드 자체를 위해서는 Docker Desktop이나 Rancher Desktop에서도 그 CA를 신뢰해야 합니다.

테스트 스코프, 부모 POM 라이선스, Maven 3.10 같은 Maven 동작 전반은 [지원 생태계](../reference/ecosystems.ko.md#java-maven)를 보세요.
