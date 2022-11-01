package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil/mssim"
	pb "github.com/schollz/progressbar/v3"
)

var (
	testName  = flag.String("test_name", "seal_unseal", "which test to run")
	testCount = flag.Int("test_count", 1000, "how many iterations of the test to run")
)

type test int

const (
	unspecified test = iota
	sealUnseal
	pcrExtend
	rsa2048CreateSignVerify
	eccp256CreateSignVerify
	firstTest = sealUnseal
	lastTest  = eccp256CreateSignVerify
)

func (t test) String() string {
	switch t {
	case sealUnseal:
		return "seal_unseal"
	case pcrExtend:
		return "pcr_extend"
	case rsa2048CreateSignVerify:
		return "rsa_2048_create_sign_verify"
	case eccp256CreateSignVerify:
		return "ecc_p256_create_sign_verify"
	default:
		return fmt.Sprintf("<invalid test selector %v>", int(t))
	}
}

func main() {
	if err := mainErr(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func mainErr() error {
	flag.Parse()

	test, err := selectTest(*testName)
	if err != nil {
		return err
	}

	// defaults ok
	cfg := mssim.Config{}
	sim, err := mssim.Open(cfg)
	if err != nil {
		return fmt.Errorf("could not connect to the simulator: %v", err)
	}
	defer sim.Close()

	tpm := transport.FromReadWriter(sim)
	return test.run(tpm, *testCount)
}

func allTestNames() []string {
	result := make([]string, 0, int(lastTest)-int(firstTest))
	for test := firstTest; test <= lastTest; test++ {
		result = append(result, test.String())
	}
	return result
}

func selectTest(testName string) (test, error) {
	switch strings.ToLower(testName) {
	case "seal", "seal_unseal":
		return sealUnseal, nil
	case "pcr", "pcr_extend":
		return pcrExtend, nil
	case "rsa", "rsa_2048_create_sign_verify":
		return rsa2048CreateSignVerify, nil
	case "ecc", "ecc_p256_create_sign_verify":
		return eccp256CreateSignVerify, nil
	default:
		return unspecified, fmt.Errorf("unrecognized test name: '%v'. supported tests: '%v'", testName, allTestNames())
	}
}

func (t test) run(tpm transport.TPM, count int) error {
	// Try to startup the TPM just in case we need to
	startup := tpm2.Startup_{
		StartupType: tpm2.TPMSUClear,
	}
	startup.Execute(tpm)

	bar := pb.Default(int64(count))
	start := time.Now()
	for i := 0; i < count; i++ {
		switch t {
		case sealUnseal:
			if err := runSealUnseal(tpm); err != nil {
				return err
			}
		case pcrExtend:
			if err := runPCRExtend(tpm); err != nil {
				return err
			}
		case rsa2048CreateSignVerify:
			if err := runRSA(tpm); err != nil {
				return err
			}
		case eccp256CreateSignVerify:
			if err := runECC(tpm); err != nil {
				return err
			}
		default:
			panic(fmt.Sprintf("invalid test specified: %v", t.String()))
		}
		bar.Add(1)
	}
	duration := time.Now().Sub(start)
	durationPerIteration := time.Duration(duration.Nanoseconds() / int64(count))
	fmt.Printf("Completed test '%v' in %v.\n(%v per iteration)\n", t, duration, durationPerIteration)
	return nil
}

func runSealUnseal(tpm transport.TPM) error {
	cp := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate(&tpm2.TPMSSensitiveCreate{
			UserAuth: tpm2.TPM2BAuth{
				Buffer: []byte("password"),
			},
			Data: tpm2.TPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
				Buffer: []byte("secrets"),
			}),
		}),
		InPublic: tpm2.TPM2BPublic(&tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: false,
				UserWithAuth:        true,
				NoDA:                true,
			},
		}),
	}
	cpRsp, err := cp.Execute(tpm)
	if err != nil {
		return err
	}
	defer func() {
		fc := tpm2.FlushContext{
			FlushHandle: cpRsp.ObjectHandle,
		}
		fc.Execute(tpm)
	}()

	unseal := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: cpRsp.ObjectHandle,
			Auth:   tpm2.PasswordAuth([]byte("password")),
			Name:   cpRsp.Name,
		},
	}
	unsealRsp, err := unseal.Execute(tpm)
	if err != nil {
		return err
	}

	if !bytes.Equal(unsealRsp.OutData.Buffer, []byte("secrets")) {
		return fmt.Errorf("incorrect data unsealed")
	}
	return nil
}

func runPCRExtend(tpm transport.TPM) error {
	event := tpm2.PCREvent{
		PCRHandle: tpm2.TPMHandle(0),
		EventData: tpm2.TPM2BEvent{
			Buffer: []byte("measurement"),
		},
	}
	return event.Execute(tpm)
}

func runRSA(tpm transport.TPM) error {
	rand := tpm2.GetRandom{
		BytesRequested: 4,
	}
	randRsp, err := rand.Execute(tpm)
	if err != nil {
		return err
	}

	cp := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.TPM2BPublic(&tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				SignEncrypt:         true,
				UserWithAuth:        true,
				NoDA:                true,
			},
			Parameters: tpm2.TPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.TPMUAsymScheme(tpm2.TPMAlgRSAPSS, &tpm2.TPMSSigSchemeRSAPSS{
						HashAlg: tpm2.TPMAlgSHA256,
					}),
				},
				KeyBits: 2048,
			}),
			Unique: tpm2.TPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{
				Buffer: randRsp.RandomBytes.Buffer,
			}),
		}),
	}
	cpRsp, err := cp.Execute(tpm)
	if err != nil {
		return err
	}
	defer func() {
		fc := tpm2.FlushContext{
			FlushHandle: cpRsp.ObjectHandle,
		}
		fc.Execute(tpm)
	}()

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: cpRsp.ObjectHandle,
			Name:   cpRsp.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: make([]byte, 32),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}
	signRsp, err := sign.Execute(tpm)
	if err != nil {
		return err
	}

	verify := tpm2.VerifySignature{
		KeyHandle: cpRsp.ObjectHandle,
		Digest:    sign.Digest,
		Signature: signRsp.Signature,
	}
	_, err = verify.Execute(tpm)
	return err
}

func runECC(tpm transport.TPM) error {
	rand := tpm2.GetRandom{
		BytesRequested: 4,
	}
	randRsp, err := rand.Execute(tpm)
	if err != nil {
		return err
	}

	cp := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.TPM2BPublic(&tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				SignEncrypt:         true,
				UserWithAuth:        true,
				NoDA:                true,
			},
			Parameters: tpm2.TPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.TPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
						HashAlg: tpm2.TPMAlgSHA256,
					}),
				},
				CurveID: tpm2.TPMECCNistP256,
			}),
			Unique: tpm2.TPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: randRsp.RandomBytes.Buffer,
				},
			}),
		}),
	}
	cpRsp, err := cp.Execute(tpm)
	if err != nil {
		return err
	}
	defer func() {
		fc := tpm2.FlushContext{
			FlushHandle: cpRsp.ObjectHandle,
		}
		fc.Execute(tpm)
	}()

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: cpRsp.ObjectHandle,
			Name:   cpRsp.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: make([]byte, 32),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}
	signRsp, err := sign.Execute(tpm)
	if err != nil {
		return err
	}

	verify := tpm2.VerifySignature{
		KeyHandle: cpRsp.ObjectHandle,
		Digest:    sign.Digest,
		Signature: signRsp.Signature,
	}
	_, err = verify.Execute(tpm)
	return err
}
