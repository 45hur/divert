package main

import (
	_ "github.com/Elctro/divert/pkg"
)

func main() {
	WD, err := divert.NewWinDivertHandle("icmp")
	if err != nil {
		panic(err)
	}
	defer WD.Close()
}
