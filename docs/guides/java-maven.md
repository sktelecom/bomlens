---
description: Scan a Java project that builds with Maven. Choosing between Maven and Gradle, using a private repository and settings.xml, proxies and company CA certificates, and what to check when the dependency list looks short.
---

# How do I scan a Java project that builds with Maven?

A Maven scan resolves the dependency tree by running Maven in a container, so it needs the same network access and credentials your own build has. Without them the result holds only what `pom.xml` writes down, and the scan still ends normally. This page covers what to set up and what to check.

## How do I run the scan?

In the desktop app or the web UI, add the project folder and run the scan. On the command line:

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target ./my-maven-project --generate-only
```

The first Java scan downloads a Java image of about 3.8 to 5.6 GB (see [Disk use and cleanup](../reference/docker-image.md#how-much-disk-do-the-images-take)). It stops before the download when the engine does not have that much free space plus 2 GB; `BOMLENS_SKIP_DISK_CHECK=1` scans anyway. Give the Docker engine about 4 GB of memory, or the build step can be killed and the result falls back to direct dependencies.

## What if the folder has both pom.xml and build.gradle?

By default such a folder is read as a Gradle project. To read it with Maven, use `--build-tool maven` (or `BOMLENS_BUILD_TOOL=maven`). In the web UI and the desktop app, a folder with both files shows a Build tool choice on the New scan form. The scan log names the tool it used, and the SBOM records it in `bomlens:build-tool-choice`. The two tools can resolve different sets of dependencies, so compare the component counts before you pick one.

## Does my private repository work?

Yes, if the credentials are in your Maven settings. BomLens passes these files into the scan read-only, only the ones that exist, and never logs their contents:

| Tool | Files read from your home folder |
|------|----------------------------------|
| Maven | `.m2/settings.xml`, `.m2/settings-security.xml` |
| Gradle | `.gradle/gradle.properties`, `.gradle/init.gradle`, `.gradle/init.gradle.kts`, `.gradle/init.d/` |

The CLI, `--ui` and the desktop app all do this. The double-click `sbom-ui.bat` does not, so use the desktop app on Windows when the build needs them. A `settings.xml` that holds your mirror address and server credentials is used as it is. If your passwords are encrypted, `settings-security.xml` must be next to it. A Maven scan logs `maven: using the mounted settings.xml` when it found one.

A project you have built on this machine resolves even when the scan cannot reach your repository. BomLens also mounts your Maven local repository read-only (the `<localRepository>` in `settings.xml`, else `~/.m2/repository`), and Maven reads it after BomLens's own repository without writing to it. When the repository Maven would download from does not answer, Maven runs offline (`-o`) and the log says so in one line. This needs Maven 3.9 or later; offline, a project's `mvnw` that runs an older Maven is replaced by the image's Maven. It also needs `maven-dependency-plugin` and Maven's plugin prefix data in your repository: if you have only run `mvn package`, or only used a Maven older than 3.9, run `mvn dependency:tree` once with Maven 3.9 or later first. Set `BOMLENS_MAVEN_USER_REPOSITORY=false` to leave it out. The details are in [Ecosystems](../reference/ecosystems.md#java-maven).

Three things to check when a private dependency is still missing:

- The mirror address in `settings.xml` must be reachable from inside a container. An address that only works through your VPN client or as `localhost` does not.
- A dependency that could not be downloaded appears in the scan log as `Could not find artifact ...`. When a dependency preparation step failed, the file `{Project}_{Version}_cdxgen.log` is kept next to the results.
- Compare the component count with what `mvn dependency:tree` shows on your machine. A far lower number means resolution failed.

## What if I am behind a proxy?

Image downloads are made by the Docker engine, so set the proxy in Docker Desktop or Rancher Desktop, not in your shell. Inside the scan, `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from your environment are passed on. When the proxy inspects HTTPS and re-signs it with a company CA, give BomLens that CA as a PEM file:

```bash
SBOM_EXTRA_CA_CERTS=/path/to/company-ca.pem ./scripts/scan-sbom.sh --target ./my-maven-project --generate-only
```

The file is added to the system store, Node.js and the Java trust store of the scan containers. A scan that fails with `PKIX path building failed` or `certificate signed by unknown authority` prints a `[WARN]` line that names this option. On Windows, the desktop app reads `SBOM_EXTRA_CA_CERTS` as an environment variable, and the batch launchers read it from `bomlens.settings.txt` ([Settings file](../start/no-cli.md#settings-file-no-command-line-needed)). The CA also has to be trusted by Docker Desktop or Rancher Desktop for the image download itself.

For the full Maven behavior, such as test scope, parent POM licenses and Maven 3.10, see [Ecosystems](../reference/ecosystems.md#java-maven).
