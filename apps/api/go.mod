module github.com/kelvin/kelvin/apps/api

go 1.22.0

require (
	github.com/kelvin/kelvin/packages/common v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.27.0
)

require go.uber.org/multierr v1.10.0 // indirect

replace github.com/kelvin/kelvin/packages/common => ../../packages/common
