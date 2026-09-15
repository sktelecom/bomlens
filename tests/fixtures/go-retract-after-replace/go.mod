module example.com/retractrepro

go 1.21

require (
	github.com/spf13/cobra v1.8.1
)

replace (
	github.com/spf13/cobra => github.com/spf13/cobra v1.8.1
)

retract (
	v0.0.1
)
