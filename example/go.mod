module example

go 1.24.3

require (
	example/cryptoinit v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.29.0
)

require golang.org/x/sys v0.27.0 // indirect

replace example/cryptoinit => ./cryptoinit
