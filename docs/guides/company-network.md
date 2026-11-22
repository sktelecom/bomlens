---
description: Scan a project whose dependencies come from your company's package repository. Scan where the project already builds, read a lock file without a build, or analyze an SBOM your build made; the proxy and company CA settings are the fallback.
---

# How do I scan a project that needs my company's package repository?

A source scan resolves dependencies by running the package managers inside a container. The exact versions a project uses come from the environment that builds it: its login to the internal repository, its mirror, its VPN. A scan container does not have all of that. So for a project that needs the company's repository, scan where the project already builds, and treat the proxy and certificate settings below as a fallback.

## Where should I run the scan?

Pick the first of these that fits.

1. The project has a complete lock file. With `--detection static`, BomLens reads the lock file and runs no build, so it needs no access to your internal repository. `auto` does this by itself when one `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock` or `gradle.lockfile` covers the whole tree. Licenses the lock file lacks are filled from the public registry, so the license of an internal package may stay empty. A Node.js project installed on this machine with no lock file committed is read from the lock file npm or pnpm wrote under `node_modules`, so its full dependency graph resolves without the registry. That scan still builds, since such a lock records one machine's install ([Node.js](../reference/ecosystems.md#nodejs)).
2. Your build already produces an SBOM, or can. Make it on the machine that builds the project, for example with the CycloneDX plugin for Maven (`mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom`) or `npx @cyclonedx/cyclonedx-npm --output-file bom.json`, then check and analyze it with `--analyze bom.json`. The [supplier SBOM guide](supplier-sbom.md) describes the checks and the reports this gives. BomLens does not change the SBOM you hand it.
3. A CI runner or a build machine can run BomLens. Run the scan there, where the build already has its settings: see [CI/CD integration](ci-cd.md), including the case where the runner has no Docker.
4. None of these is possible. Scan from your own machine with the proxy and certificate settings below. Maven and Gradle settings files are passed into the scan ([Maven guide](java-maven.md#does-my-private-repository-work)). A Maven project you built on this machine resolves from your Maven local repository (`~/.m2/repository`, or the `<localRepository>` in `settings.xml`, read-only), even when the scan cannot reach your repository ([Java (Maven)](../reference/ecosystems.md#java-maven)). A Gradle project you built on this machine resolves from your Gradle cache (`~/.gradle/caches`, read-only), even when the scan cannot reach your repository ([Java (Gradle)](../reference/ecosystems.md#java-gradle)). A Python project whose dependencies you installed into a virtual environment on this machine (`.venv/`, `venv/`) is read from that environment, read-only, when the scan cannot use the package index ([Python](../reference/ecosystems.md#python)). npm and pip settings files and their mirror variables are not passed, so an npm project that needs a login to resolve, and a pip project with no virtual environment in its folder, usually come out short this way.

Compare the component count with what your own build reports. A far lower number means resolution failed. When the SBOM was written although the package registry refused the login for some downloads, the scan log has one `[WARN]` line, the SBOM records `bomlens:registry-refused`, and the web UI Overview shows the warning "Some dependencies may be missing" ([Artifacts](../reference/artifacts.md)).

A Node.js project with no lock file is resolved by an npm install against the registry its own `.npmrc` names. The scan asks that registry once first, without the login. When it does not answer, or its TLS certificate is not trusted, the scan does not wait for npm's retries: npm resolves from its cache alone, the scan ends within seconds, it lists only what `node_modules` or that cache holds, and it records the failed step `npm-registry:network` or `npm-registry:tls-trust`. The scan log names the registry and the cause ([Node.js](../reference/ecosystems.md#nodejs)). When the cache held every dependency, the failed step is removed and `npm-offline-cache` is recorded in `bomlens:prep-step-applied` instead. The CLI prints an `[INFO]` line and the web UI Overview shows a note, both saying the versions are the newest cached ones `package.json` allows and may not be the newest releases.

## What do I set for a proxy?

`HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` (the lower-case names too) from the shell that runs `scan-sbom.sh` are passed on to the scan containers by name. A proxy at your own machine's loopback address (`127.0.0.1`, `localhost`) is not passed, because inside a container that address is the container itself. Docker's own proxy setting applies then. `sbom-ui.bat` passes the same three variables to the web UI from the Windows environment. A double-clicked `.bat` does not see a variable typed in a command prompt, so set them with `setx` (for example `setx HTTPS_PROXY http://proxy.example:8080`) and double-click it again. The desktop app does not pass proxy variables, so set the proxy in the Docker engine there.

## How do I trust my company CA?

A proxy that inspects HTTPS re-signs it with a company CA, and the scan containers do not trust that CA. Some hosts may be inspected while others are not, so one registry can fail while another works. Give BomLens the CA as a PEM file:

```bash
SBOM_EXTRA_CA_CERTS=/path/to/company-ca.pem ./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --target ./my-project --generate-only
```

The file is added to the system store, Node.js and the Java trust store of the scan containers. A scan that fails on an untrusted certificate prints a `[WARN]` line that names this option. npm reports it as `SELF_SIGNED_CERT_IN_CHAIN` in the cdxgen log, and a dependency step that runs for minutes with no progress against such a registry points the same way.

How you set `SBOM_EXTRA_CA_CERTS` depends on how you start BomLens:

- `scan-sbom.sh` and `scan-sbom.bat` read it from the environment, as in the command above. They do not read a settings file.

  In PowerShell, set the variable first in the same line:

  ```powershell
  $env:SBOM_EXTRA_CA_CERTS="C:\path\to\company-ca.pem"; scripts\scan-sbom.bat --project MyApp --version 1.0.0 --target .\my-project --generate-only
  ```

- When you double-click `sbom-ui.bat`, it does not see a variable typed in a command prompt, so it also reads `SBOM_EXTRA_CA_CERTS=C:\path\to\company-ca.pem` from `bomlens.settings.txt` next to the scripts ([Settings file](../start/troubleshooting.md#settings-file-no-command-line-needed)). Use a path without `&`, `^`, `|`, `<`, `>`, `%` or `!`. A variable set in the environment wins over the file.
- The desktop app reads it from the environment only. On Windows, run `setx SBOM_EXTRA_CA_CERTS C:\path\to\company-ca.pem` once in a command prompt, then quit the app and start it again. On macOS, run `launchctl setenv SBOM_EXTRA_CA_CERTS /path/to/company-ca.pem` in Terminal, then start the app again; the setting is lost on restart. A path with a comma or a double quote is refused.

## What about the Docker engine's own proxy and CA?

Image downloads are made by the Docker engine, not by BomLens, so a proxy or CA you set in your shell has no effect on them. If the first scan stops at the image download, check these in order:

- `docker pull hello-world` in your terminal. If it fails the same way, the problem is the engine's setting, not BomLens.
- The proxy setting of your Docker product. Docker Desktop has it under `Settings > Resources > Proxies`, and Rancher Desktop under `Preferences > WSL > Proxy` on Windows. If the proxy also intercepts `localhost`, add `localhost` to its bypass list, or the browser shows an error even while the web UI runs.
- Whether the engine trusts your company CA. A proxy that inspects HTTPS shows up as `x509: certificate signed by unknown authority` in the pull error. How to add a CA depends on the product and the host system, so follow that product's documentation. `SBOM_EXTRA_CA_CERTS` does not cover image downloads.
- A host that cannot reach any registry can load the image from a file instead: see `SBOM_IMAGE_TAR` and `SBOM_PULL=never` in the [CLI reference](../reference/cli.md).

## What is written to logs and result files?

The console output of a scan, the web UI log and the cdxgen log kept as `{Project}_{Version}_cdxgen.log` have credentials masked: the user and password in a URL, the value after `Authorization`, `Bearer` and `Basic`, the value after a name such as `token`, `password`, `secret` or `api_key`, and the text of a `<password>` element. The SBOM carries no user or password from a URL. Masking works on patterns, so a credential written in a form none of them recognises, such as a bare token on a line with no name before it, is not masked. Read the cdxgen log before you send it to anyone.
