package main

import (
	_ "github.com/Elctro/divert/pkg"
	divert "github.com/Elctro/godivert2/pkg"
)

func main() {
	WD, err := divert.Open("true", 0, 0, 0)
	if err != nil {
		panic(err)
	}
	defer WD.Close()
}
