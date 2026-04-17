package main

import (
	"fmt"

	"wing/config"
)

func handleKeygen(genkey, genpsk bool) error {
	if genkey {
		priv, pub, err := config.GenerateKeypair()
		if err != nil {
			return err
		}
		fmt.Printf("private_key: %s\n", priv)
		fmt.Printf("public_key:  %s\n", pub)
	}
	if genpsk {
		psk, err := config.GeneratePSK()
		if err != nil {
			return err
		}
		fmt.Printf("preshared_key: %s\n", psk)
	}
	return nil
}
