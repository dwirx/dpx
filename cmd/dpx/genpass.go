package main

import (
	"flag"
	"fmt"
	"math"
)

type generatePasswordArgs struct {
	length    int
	count     int
	noSymbols bool
}

func parseGeneratePasswordArgs(args []string, opts runOptions) (generatePasswordArgs, error) {
	fs := flag.NewFlagSet("genpass", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	length := fs.Int("length", defaultGeneratedPasswordLength, "generated password length")
	count := fs.Int("count", 1, "number of generated passwords")
	noSymbols := fs.Bool("no-symbols", false, "exclude symbols for compatibility")
	if err := fs.Parse(args); err != nil {
		return generatePasswordArgs{}, err
	}
	if fs.NArg() > 0 {
		return generatePasswordArgs{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *length < minGeneratedPasswordLength || *length > maxGeneratedPasswordLength {
		return generatePasswordArgs{}, fmt.Errorf("password length must be between %d and %d", minGeneratedPasswordLength, maxGeneratedPasswordLength)
	}
	if *count < 1 || *count > 50 {
		return generatePasswordArgs{}, fmt.Errorf("count must be between 1 and 50")
	}
	return generatePasswordArgs{
		length:    *length,
		count:     *count,
		noSymbols: *noSymbols,
	}, nil
}

func runGeneratePassword(args []string, opts runOptions) error {
	parsed, err := parseGeneratePasswordArgs(args, opts)
	if err != nil {
		return err
	}

	includeSymbols := !parsed.noSymbols
	mode := "strong"
	if !includeSymbols {
		mode = "compatible"
	}

	var entropyBits float64
	for i := 0; i < parsed.count; i++ {
		generated, alphabetSize, err := generateStrongPasswordWithOptions(parsed.length, includeSymbols)
		if err != nil {
			return err
		}
		entropyBits = estimateEntropyBits(parsed.length, alphabetSize)
		if parsed.count == 1 {
			fmt.Fprintf(opts.stdout, "Generated password: %s\n", generated)
		} else {
			fmt.Fprintf(opts.stdout, "%d. %s\n", i+1, generated)
		}
	}
	fmt.Fprintf(opts.stdout, "Mode: %s | Length: %d | Count: %d | Estimated entropy: %.1f bits (%s)\n", mode, parsed.length, parsed.count, entropyBits, entropyLabel(entropyBits))
	return nil
}

func estimateEntropyBits(length, alphabetSize int) float64 {
	if length <= 0 || alphabetSize <= 1 {
		return 0
	}
	return float64(length) * math.Log2(float64(alphabetSize))
}

func entropyLabel(bits float64) string {
	switch {
	case bits >= 120:
		return "excellent"
	case bits >= 90:
		return "very strong"
	case bits >= 70:
		return "strong"
	case bits >= 50:
		return "moderate"
	default:
		return "low"
	}
}
