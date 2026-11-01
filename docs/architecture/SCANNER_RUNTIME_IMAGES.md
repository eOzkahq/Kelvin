# Scanner Runtime Images

Kelvin packages only OWASP ZAP Baseline and Nuclei as external scanner runtimes. The build definitions are under `deploy/scanners/`; no scanner image is published or enabled by the repository yet. `deploy/scanners/images.lock.json` deliberately has null release digests until a reviewed image build and promotion is completed.

## Reproducible build inputs

The `Scanner runtime images` GitHub Actions workflow is manually dispatched with exact scanner versions and upstream OCI references pinned by digest. It accepts only the official ZAP stable image, the official ProjectDiscovery Nuclei image, and the distroless static non-root image. Mutable tags are rejected by `scripts/scanners/build-images.sh`. The build runs for `linux/amd64`; changing platform requires a separately reviewed build and digest.

The ZAP image derives from the official stable runtime, sets UID/GID `10001`, and redirects transient home state to `/tmp`. The upstream `bare` image omits ZAP's packaged scan scripts, so stable is required for the Baseline integration; this carries extra upstream tooling and is a known size tradeoff pending a separately maintained minimal ZAP runtime. The Nuclei build copies only the executable from the pinned upstream image into the pinned distroless static runtime, then runs as UID/GID `10001`; it has no shell, package manager, or compiler. Both images are exercised read-only with a bounded `/tmp` tmpfs, and runtime version output must match the exact supplied version.

The workflow scans both images for HIGH and CRITICAL vulnerabilities, generates CycloneDX SBOMs, and archives the build metadata, image digests, inspected config, and exact build inputs. A reviewed release process must copy those values into `images.lock.json`, publish the immutable images to the controlled registry, sign them with Cosign, verify the signature at deployment, and update the corresponding registry `VersionPolicy`. The build workflow does not publish or sign images.

## Nuclei template catalog

The container packages the Nuclei executable only. The curated catalog `kelvin.safe.web.v1` must be reviewed, packaged, hashed, and mounted or included by the future Nuclei adapter before the scanner can be enabled. Kelvin must disable runtime template downloads and pass only that catalog to Nuclei. The catalog digest belongs in the version policy and image release record. A missing catalog digest keeps Nuclei unavailable.

## Vulnerability updates and rollback

On each upstream scanner or base-image update, review the release and license notices, resolve new immutable input digests, build both images, verify runtime versions and UID, inspect the SBOM, and triage Trivy findings. High or critical findings fail the build. A Product Security review approves exceptions or a patched image before promotion. Keep the previous signed image digests and policy as the rollback set; rollback changes the version policy to those previous immutable digests and never relies on moving a tag.

ZAP's official Baseline container scan uses a time-limited spider followed by passive scanning; it still sends requests and requires the worker's scope and request-budget enforcement. Nuclei's executable is not permission to use its built-in update mechanism or arbitrary templates. These image controls do not replace rootless OCI isolation, egress scope enforcement, or runtime resource limits.

References: [ZAP Docker Baseline](https://www.zaproxy.org/docs/docker/baseline-scan/), [ZAP Docker image guide](https://www.zaproxy.org/docs/docker/about/), [ProjectDiscovery Nuclei Dockerfile](https://github.com/projectdiscovery/nuclei/blob/dev/Dockerfile), [Docker image digest inspection](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/).
