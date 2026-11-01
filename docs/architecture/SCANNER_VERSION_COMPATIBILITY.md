# Scanner Version and Compatibility Policy

## Identity and pins

Registry entries carry an exact scanner version and an adapter semantic version (`MAJOR.MINOR.PATCH`). Ranges and mutable tags such as `latest` are not accepted. An external scanner must also provide an immutable OCI image reference ending in its declared `sha256` digest. Nuclei requires the curated catalog ID `kelvin.safe.web.v1` and its SHA-256 digest. Runtime identity is reported by the adapter and compared field-for-field with registry policy.

The repository currently has no production scanner image manifests or certified upstream release pins. Therefore this policy is implemented, but external scanners remain unavailable until P2-08 supplies reviewed image digests and catalog artifacts. No upstream scanner release is implicitly approved by this document.

## Verification and assessment records

The registry verifies runtime identity after adapter initialization and health checks. The worker repeats verification immediately before dispatch. A mismatch or verification error marks that scanner unavailable and rejects the job; it does not fall back to another version. `Registry.StampOutput` copies the verified scanner, adapter, image, and template catalog identities into the versioned output envelope. Adapter-provided identity fields that disagree with the verified registry snapshot are rejected.

## Upgrade and promotion

An upgrade changes the exact version policy and, for external tools, the image digest. Review the upstream release and license, rebuild from a controlled source, scan and test the image, run adapter contract and compatibility tests, review the safe template catalog changes, then promote the immutable image and catalog digests together. Deployments roll forward through an explicit configuration/image change; a worker never silently updates binaries or templates at startup. Rollback restores the previous reviewed version policy and immutable digests.

The worker runtime remains responsible for resource limits and isolation. Version verification does not replace scope enforcement, rootless execution, request pacing, or validation of untrusted scanner output.
