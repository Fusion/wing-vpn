package cli

import (
	"fmt"
	"strings"

	"wing/config"
)

func HandleKeygen(genkey, genrootkey, issuepeerkey, genpsk bool, rootPrivateKey string) error {
	if genkey {
		priv, pub, err := config.GenerateKeypair()
		if err != nil {
			return err
		}
		fmt.Printf("private_key: %s\n", priv)
		fmt.Printf("public_key:  %s\n", pub)
	}
	if genrootkey {
		priv, pub, err := config.GenerateRootKeypair()
		if err != nil {
			return err
		}
		fmt.Printf("root_private_key: %s\n", priv)
		fmt.Printf("root_public_key:  %s\n", pub)
	}
	if issuepeerkey {
		issued, err := config.IssuePeerIdentity(strings.TrimSpace(rootPrivateKey))
		if err != nil {
			return err
		}
		fmt.Printf("\"private_key\": %q,\n", issued.PrivateKey)
		fmt.Printf("\"public_key\": %q,\n", issued.PublicKey)
		fmt.Printf("\"control_private_key\": %q,\n", issued.ControlPrivateKey)
		fmt.Printf("\"control_public_key\": %q,\n", issued.ControlPublicKey)
		fmt.Printf("\"root_public_key\": %q,\n", issued.RootPublicKey)
		fmt.Printf("\"identity_signature\": %q,\n", issued.IdentitySignature)
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
