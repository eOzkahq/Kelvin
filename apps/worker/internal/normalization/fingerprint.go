package normalization

import (
	commonnorm "github.com/kelvin/kelvin/packages/common/normalization"
)

// Re-export common functions and types for unified canonical behavior
var (
	NormalizeCWE           = commonnorm.NormalizeCWE
	NormalizeCVEs          = commonnorm.NormalizeCVEs
	DeriveVulnerabilityKey = commonnorm.DeriveVulnerabilityKey
	SlugifyTitle           = commonnorm.SlugifyTitle
	NormalizeAsset         = commonnorm.NormalizeAsset
	NormalizeEndpoint      = commonnorm.NormalizeEndpoint
	NormalizeParameter     = commonnorm.NormalizeParameter
	GenerateFingerprint    = commonnorm.GenerateFingerprint
	ComputeFingerprint     = commonnorm.ComputeFingerprint
	ParseTaggedFingerprint = commonnorm.ParseTaggedFingerprint
	IsAmbiguousIdentity    = commonnorm.IsAmbiguousIdentity
)

type (
	FingerprintInput  = commonnorm.FingerprintInput
	FingerprintResult = commonnorm.FingerprintResult
)
