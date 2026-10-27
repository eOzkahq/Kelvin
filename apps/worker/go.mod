module github.com/kelvin/kelvin/apps/worker

go 1.23.0

require (
	github.com/kelvin/kelvin/packages/common v0.0.0-00010101000000-000000000000
	github.com/kelvin/kelvin/packages/schemas v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.27.0
)

require (
	github.com/stretchr/testify v1.11.1 // indirect
	go.uber.org/multierr v1.10.0 // indirect
)

replace github.com/kelvin/kelvin/packages/common => ../../packages/common

replace github.com/kelvin/kelvin/packages/schemas => ../../packages/schemas
