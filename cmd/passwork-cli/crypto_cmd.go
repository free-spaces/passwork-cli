package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func runCrypto(args []string) error {
	if len(args) == 0 {
		printCryptoUsage()
		os.Exit(1)
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "enc", "encrypt":
		return runCryptoEnc(rest)
	case "dec", "decrypt":
		return runCryptoDec(rest)
	case "enc-file":
		return runCryptoEncFile(rest)
	case "dec-file":
		return runCryptoDecFile(rest)
	case "dec-mk":
		return runCryptoDecMK(rest)
	case "enc-mk":
		return runCryptoEncMK(rest)
	case "gen-rsa":
		return runCryptoGenRSA(rest)
	case "-h", "--help":
		printCryptoUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "crypto: unknown subcommand %q\n", sub)
		printCryptoUsage()
		os.Exit(1)
	}
	return nil
}

func printCryptoUsage() {
	fmt.Fprintf(os.Stderr, "Usage: passwork-cli crypto <subcommand> [options]\n\n")
	fmt.Fprintf(os.Stderr, "Subcommands:\n\n")
	fmt.Fprintf(os.Stderr, "  enc        Encrypt string (AES, custom base32). Key = vault/item/user master key.\n")
	fmt.Fprintf(os.Stderr, "             Options: -value <plaintext> (or stdin), -key <key>\n\n")
	fmt.Fprintf(os.Stderr, "  dec        Decrypt string (custom base32 -> plaintext).\n")
	fmt.Fprintf(os.Stderr, "             Options: -value <ciphertext> (or stdin), -key <key>\n\n")
	fmt.Fprintf(os.Stderr, "  enc-file   Encrypt file: file -> base64 -> AES -> custom base32. For attachments.\n")
	fmt.Fprintf(os.Stderr, "             Options: -input <path>, -key <key>\n\n")
	fmt.Fprintf(os.Stderr, "  dec-file   Decrypt file (custom base32 -> AES -> base64 decode -> stdout).\n")
	fmt.Fprintf(os.Stderr, "             Options: -value <ciphertext> (or stdin), -key <key>\n\n")
	fmt.Fprintf(os.Stderr, "  dec-mk     Decrypt vault master key (base64 ciphertext + RSA private key PEM).\n")
	fmt.Fprintf(os.Stderr, "             Options: -value <base64>, -key-file <private.pem>\n\n")
	fmt.Fprintf(os.Stderr, "  enc-mk     Encrypt vault master key with RSA public key PEM.\n")
	fmt.Fprintf(os.Stderr, "             Options: -value <plain master key>, -key-file <public.pem>\n\n")
	fmt.Fprintf(os.Stderr, "  gen-rsa    Generate RSA keypair; encrypt private key with user master key. Output JSON.\n")
	fmt.Fprintf(os.Stderr, "             Options: -key <userMasterKey>\n\n")
	fmt.Fprintf(os.Stderr, "Key/password: use -key or env PWK_CRYPTO_KEY where applicable.\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  passwork-cli crypto dec \"$userPrivateKeyEncrypted\" --key \"$userMasterKey\" > user_private.pem\n")
	fmt.Fprintf(os.Stderr, "  passwork-cli crypto dec-mk \"$vaultMasterKeyEncrypted\" -key-file user_private.pem\n")
	fmt.Fprintf(os.Stderr, "  passwork-cli crypto enc-mk \"$vaultMasterKey\" -key-file user_public.pem\n")
	fmt.Fprintf(os.Stderr, "  passwork-cli crypto enc-file -input ./file.txt -key \"$fileMasterKey\"\n")
	fmt.Fprintf(os.Stderr, "  passwork-cli crypto gen-rsa -key \"$userMasterKey\"\n")
}

func cryptoKeyAndValue(rest []string, needKey bool) (key []byte, value string, err error) {
	normalized := rest
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		normalized = append([]string{"-value", rest[0]}, rest[1:]...)
	}

	fs := flag.NewFlagSet("crypto", flag.ExitOnError)
	valueFlag := fs.String("value", "", "input value (else stdin)")
	keyFlag := fs.String("key", "", "key/password (else PWK_CRYPTO_KEY)")
	if err := fs.Parse(normalized); err != nil {
		return nil, "", err
	}
	keyStr := *keyFlag
	if keyStr == "" {
		keyStr = os.Getenv("PWK_CRYPTO_KEY")
	}
	if keyStr == "" && len(fs.Args()) >= 1 {
		keyStr = fs.Args()[0]
	}
	if needKey && keyStr == "" {
		return nil, "", fmt.Errorf("key required: use -key or PWK_CRYPTO_KEY")
	}
	value = *valueFlag
	if value == "" && len(fs.Args()) >= 1 {
		value = fs.Args()[0]
	}
	if value == "" {
		var b []byte
		b, err = io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			return nil, "", fmt.Errorf("stdin: %w", err)
		}
		value = strings.TrimSuffix(string(b), "\n")
	}
	return []byte(keyStr), value, nil
}

func runCryptoEnc(rest []string) error {
	key, plain, err := cryptoKeyAndValue(rest, true)
	if err != nil {
		return err
	}
	out, err := encryptWithAESMasterKey([]byte(plain), key)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func runCryptoDec(rest []string) error {
	key, cipher, err := cryptoKeyAndValue(rest, true)
	if err != nil {
		return err
	}
	plain, err := decryptWithAESMasterKey(cipher, key)
	if err != nil {
		return err
	}
	fmt.Print(string(plain))
	return nil
}

func runCryptoEncFile(rest []string) error {
	fs := flag.NewFlagSet("crypto enc-file", flag.ExitOnError)
	input := fs.String("input", "", "path to file to encrypt")
	keyFlag := fs.String("key", "", "key (else PWK_CRYPTO_KEY)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("enc-file: -input is required")
	}
	keyStr := *keyFlag
	if keyStr == "" {
		keyStr = os.Getenv("PWK_CRYPTO_KEY")
	}
	if keyStr == "" {
		return fmt.Errorf("enc-file: -key or PWK_CRYPTO_KEY required")
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	out, err := encryptWithAESMasterKey([]byte(b64), []byte(keyStr))
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func runCryptoDecFile(rest []string) error {
	key, cipher, err := cryptoKeyAndValue(rest, true)
	if err != nil {
		return err
	}
	plain, err := decryptWithAESMasterKey(cipher, key)
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(string(plain))
	if err != nil {
		return fmt.Errorf("dec-file: base64 decode: %w", err)
	}
	_, _ = os.Stdout.Write(decoded)
	return nil
}

func runCryptoDecMK(rest []string) error {
	fs := flag.NewFlagSet("crypto dec-mk", flag.ExitOnError)
	valueFlag := fs.String("value", "", "base64-encoded encrypted vault master key (else stdin or positional)")
	keyFile := fs.String("key-file", "", "path to RSA private key PEM (or positional arg)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	cipherBase64 := *valueFlag
	keyPath := *keyFile
	if len(fs.Args()) >= 2 {
		if cipherBase64 == "" {
			cipherBase64 = fs.Args()[0]
		}
		if keyPath == "" {
			keyPath = fs.Args()[1]
		}
	} else if len(fs.Args()) == 1 && keyPath == "" {
		keyPath = fs.Args()[0]
	}
	if keyPath == "" {
		return fmt.Errorf("dec-mk: -key-file or positional path to private PEM is required")
	}
	if cipherBase64 == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		cipherBase64 = strings.TrimSpace(string(b))
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	privKey, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		return err
	}
	plain, err := DecryptVaultMasterKey(cipherBase64, privKey)
	if err != nil {
		return err
	}
	_, _ = os.Stdout.Write(plain)
	return nil
}

func runCryptoEncMK(rest []string) error {
	fs := flag.NewFlagSet("crypto enc-mk", flag.ExitOnError)
	valueFlag := fs.String("value", "", "plain vault master key (else stdin or positional)")
	keyFile := fs.String("key-file", "", "path to RSA public key PEM (or positional arg)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	plain := *valueFlag
	keyPath := *keyFile
	if len(fs.Args()) >= 2 {
		if plain == "" {
			plain = fs.Args()[0]
		}
		if keyPath == "" {
			keyPath = fs.Args()[1]
		}
	} else if len(fs.Args()) == 1 && keyPath == "" {
		keyPath = fs.Args()[0]
	}
	if keyPath == "" {
		return fmt.Errorf("enc-mk: -key-file or positional path to public PEM is required")
	}
	if plain == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		plain = strings.TrimSuffix(string(b), "\n")
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	pubKey, err := ParsePublicKeyPEM(pemBytes)
	if err != nil {
		return err
	}
	cipher, err := EncryptVaultMasterKey([]byte(plain), pubKey)
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(cipher))
	return nil
}

func runCryptoGenRSA(rest []string) error {
	key, _, err := cryptoKeyAndValue(rest, true)
	if err != nil {
		return err
	}
	pubPEM, privateEncrypted, err := GenerateRSAKeypairAndEncryptPrivate(key)
	if err != nil {
		return err
	}
	out := map[string]string{
		"public":           string(pubPEM),
		"privateEncrypted": privateEncrypted,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
