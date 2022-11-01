using System;
using System.CommandLine;
using System.Text;
using Tpm2Lib;
using ShellProgressBar;

class TSSBenchmarks
{
    public static void Main(String[] args)
    {
        var testNameOption = new Option<string>(
            name: "--test_name",
            description: "which test to run");
        testNameOption.SetDefaultValue("seal_unseal");
        var testCountOption = new Option<int>(
            name: "--test_count",
            description: "how many iterations of the test to run");
        testCountOption.SetDefaultValue(1000);

        var rootCommand = new RootCommand("Run TSS benchmarks");
        rootCommand.AddOption(testNameOption);
        rootCommand.AddOption(testCountOption);

        rootCommand.SetHandler((testName, testCount) =>
            {
                RunTest(testName, testCount);
            },
            testNameOption, testCountOption);

        rootCommand.Invoke(args);
    }

    static void RunTest(string testName, int testCount)
    {
        Func<Tpm2, bool> test;

        switch (testName.ToLower())
        {
            case "seal":
            case "seal_unseal":
                test = runSealUnseal;
                break;
            case "pcr":
            case "pcr_extend":
                test = runPCRExtend;
                break;
            case "rsa":
            case "rsa_2048_create_sign_verify":
                test = runRSA2048CreateSignVerify;
                break;
            case "ecc":
            case "ecc_p256_create_sign_verify":
                test = runECCP256CreateSignVerify;
                break;
            default:
                Console.Error.WriteLine($"unrecognized test name: '{testName}'. " +
                    "supported tests: seal_unseal, pcr_extend, rsa_2048_create_sign_verify, ecc_p256_create_sign_verify");
                Environment.ExitCode = -1;
                return;
        }

        var tcpDev = new TcpTpmDevice("127.0.0.1", 2321);
        tcpDev.SetSocketTimeout(2000);
        try
        {
            tcpDev.Connect();
        }
        catch (Exception e)
        {
            tcpDev.Dispose();
            Console.Error.WriteLine($"Error connecting to TPM: {e}");
            Environment.ExitCode = -1;
            return;
        }
        tcpDev.PowerCycle();
        Tpm2 tpm = new Tpm2(tcpDev);
        tpm._Behavior.Strict = true;
        tpm.Startup(Su.Clear);

        DateTime start = DateTime.Now;
        using (var progressBar = new ProgressBar(testCount, "Running tests..."))
        {
            for (int i = 0; i < testCount; i++)
            {
                if (!test(tpm))
                {
                    Console.Error.WriteLine("Error in the test; aborting");
                    Environment.ExitCode = -1;
                    break;
                }
                progressBar.Tick();
            }
        }

        TimeSpan elapsed = DateTime.Now.Subtract(start);
        TimeSpan elapsedEach = elapsed.Divide(testCount);

        string elapsedStr = prettyTimeSpan(elapsed);
        string elapsedEachStr = prettyTimeSpan(elapsedEach);
        Console.WriteLine($"Completed test '{testName}' in {elapsedStr}.\n({elapsedEachStr} per iteration)\n");

        tcpDev.Close();
    }

    static string prettyTimeSpan(TimeSpan span)
    {
        if (span.TotalSeconds >= 1)
        {
            return (span.TotalMilliseconds / 1000.0).ToString("0.###") + "s";
        }
        if (span.TotalMilliseconds >= 1)
        {
            return (span.TotalNanoseconds / 1000000.0).ToString("0.###") + "ms";
        }
        return (span.TotalNanoseconds / 1000.0).ToString("0.###") + "µs";
    }

    static bool runSealUnseal(Tpm2 tpm)
    {
        SensitiveCreate sensCreate = new SensitiveCreate(Encoding.ASCII.GetBytes("password"), Encoding.ASCII.GetBytes("secrets"));
        TpmPublic inPub = new TpmPublic(
            TpmAlgId.Sha256,
            ObjectAttr.FixedTPM | ObjectAttr.FixedParent | ObjectAttr.UserWithAuth | ObjectAttr.NoDA,
            null,
            new KeyedhashParms(),
            new Tpm2bDigestKeyedhash());
        TpmHandle blob = tpm[Auth.Default].CreatePrimary(TpmRh.Owner, sensCreate, inPub,
                                            null, null,
                                            out TpmPublic outPublic,
                                            out CreationData creationData,
                                            out byte[] creationHash,
                                            out TkCreation creationTicket);

        byte[] data = tpm[Auth.Pw].Unseal(blob);
        if (Encoding.ASCII.GetString(data) != "secrets")
        {
            Console.Error.WriteLine("Unsealed incorrect data");
            return false;
        }

        tpm.FlushContext(blob);
        return true;
    }
    static bool runPCRExtend(Tpm2 tpm)
    {
        tpm[Auth.Default].PcrEvent(TpmHandle.Pcr(0), Encoding.ASCII.GetBytes("measurement"));
        return true;
    }
    static bool runRSA2048CreateSignVerify(Tpm2 tpm)
    {
        byte[] rand = tpm.GetRandom(4);

        TpmPublic inPub = new TpmPublic(
            TpmAlgId.Sha256,
            ObjectAttr.FixedTPM | ObjectAttr.FixedParent | ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth | ObjectAttr.Sign | ObjectAttr.NoDA,
            null,
            new RsaParms(new SymDefObject(), new SchemeRsapss(TpmAlgId.Sha256), 2048, 0),
            new Tpm2bPublicKeyRsa(rand));
        TpmHandle key = tpm[Auth.Default].CreatePrimary(TpmRh.Owner, new SensitiveCreate(), inPub,
                                            null, null,
                                            out TpmPublic outPublic,
                                            out CreationData creationData,
                                            out byte[] creationHash,
                                            out TkCreation creationTicket);

        TpmHash digestToSign = new TpmHash(TpmAlgId.Sha256);
        var signature = tpm[Auth.Default].Sign(key,            // Handle of signing key
                                            digestToSign,         // Data to sign
                                            null,                 // Use key's scheme
                                            TpmHashCheck.Null());

        tpm.VerifySignature(key, digestToSign.digest, signature);

        tpm.FlushContext(key);
        return true;
    }
    static bool runECCP256CreateSignVerify(Tpm2 tpm)
    {
        byte[] rand = tpm.GetRandom(4);

        TpmPublic inPub = new TpmPublic(
            TpmAlgId.Sha256,
            ObjectAttr.FixedTPM | ObjectAttr.FixedParent | ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth | ObjectAttr.Sign | ObjectAttr.NoDA,
            null,
            new EccParms(new SymDefObject(), new SchemeEcdsa(TpmAlgId.Sha256), EccCurve.NistP256, new NullKdfScheme()),
            new EccPoint(rand, null));
        TpmHandle key = tpm[Auth.Default].CreatePrimary(TpmRh.Owner, new SensitiveCreate(), inPub,
                                            null, null,
                                            out TpmPublic outPublic,
                                            out CreationData creationData,
                                            out byte[] creationHash,
                                            out TkCreation creationTicket);

        TpmHash digestToSign = new TpmHash(TpmAlgId.Sha256);
        var signature = tpm[Auth.Default].Sign(key,
                                            digestToSign,
                                            null,
                                            TpmHashCheck.Null());

        tpm.VerifySignature(key, digestToSign.digest, signature);

        tpm.FlushContext(key);
        return true;
    }
}