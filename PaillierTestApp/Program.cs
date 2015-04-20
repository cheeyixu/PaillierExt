using PaillierExt;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Math;
using System.Diagnostics;

public class Test
{
    public static void Main()
    {
        //TestTextEncryption();
        //TestAddition_Batch();
        PerformanceTest();
    }

    public static String PrettifyXML(String XML)
    {
        String Result = "";

        MemoryStream mStream = new MemoryStream();
        XmlTextWriter writer = new XmlTextWriter(mStream, Encoding.Unicode);
        XmlDocument document = new XmlDocument();

        try
        {
            // Load the XmlDocument with the XML.
            document.LoadXml(XML);

            writer.Formatting = Formatting.Indented;

            // Write the XML into a formatting XmlTextWriter
            document.WriteContentTo(writer);
            writer.Flush();
            mStream.Flush();

            // Have to rewind the MemoryStream in order to read
            // its contents.
            mStream.Position = 0;

            // Read MemoryStream contents into a StreamReader.
            StreamReader sReader = new StreamReader(mStream);

            // Extract the text from the StreamReader.
            String FormattedXML = sReader.ReadToEnd();

            Result = FormattedXML;
        }
        catch (XmlException)
        {
        }

        mStream.Close();
        writer.Close();

        return Result;
    }

    public static void TestTextEncryption(string message = "This is to test Paillier encryption and hopefully this message contains more than 2 blocks please please please please please please please please please please please pleaseplease please please pleaseplease please please please          ", 
        int keySize = 384, PaillierPaddingMode padding = PaillierPaddingMode.Zeros)
    {
        Console.WriteLine();
        Console.WriteLine("-- Testing string encryption ---");

        byte[] plaintext = Encoding.Default.GetBytes(message);

        Paillier algorithm = new PaillierManaged();

        algorithm.KeySize = keySize;
        algorithm.Padding = padding;

        string parametersXML = algorithm.ToXmlString(true);
        Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        byte[] ciphertext = encryptAlgorithm.EncryptData(plaintext);

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        byte[] candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

        byte[] strip_zeros = StripTrailingZeros(candidatePlaintext, plaintext.Length);

        Console.WriteLine("Original string:  '{0}'", message);
        Console.WriteLine("Decrypted string: '{0}'", Encoding.Default.GetString(candidatePlaintext));
        //Console.WriteLine("Byte arrays equal: {0}", plaintext.SequenceEqual(candidatePlaintext));
        Console.WriteLine("Byte arrays equal: {0}", plaintext.SequenceEqual(strip_zeros));
        Console.WriteLine();
    }

    public static void TestAddition_Batch()
    {
        int error_counter = 0;
        int iteration = 40;
        Console.WriteLine("-- Testing Addition Homomorphic property in batch---");

        for (int i = 0; i < iteration; i++)
        {
            if (!TestAddition())
            {
                error_counter++;
            }
        }
        Console.WriteLine();
        Console.WriteLine("There are {0} / {1} errors.", error_counter, iteration);
    }

    public static Boolean TestAddition()
    {

        Paillier algorithm = new PaillierManaged();
        algorithm.KeySize = 384;
        algorithm.Padding = PaillierPaddingMode.LeadingZeros;

        string parametersXML = algorithm.ToXmlString(true);
        //Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        Random random = new Random();
        BigInteger A = new BigInteger(random.Next(32768).ToString());
        BigInteger B = new BigInteger(random.Next(32768).ToString());

        byte[] A_bytes = A.ToByteArrayUnsigned();
        byte[] B_bytes = B.ToByteArrayUnsigned();

        //encrypt A and B
        byte[] A_enc_bytes = encryptAlgorithm.EncryptData(A.ToByteArrayUnsigned());
        byte[] B_enc_bytes = encryptAlgorithm.EncryptData(B.ToByteArrayUnsigned());

        // decrypt A and B
        byte[] A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        byte[] B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        byte[] C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        byte[] C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        BigInteger A_dec = new BigInteger(1, A_dec_bytes);
        BigInteger B_dec = new BigInteger(1, B_dec_bytes);
        BigInteger C_dec = new BigInteger(1, C_dec_bytes);

        if (!C_dec.Equals(A.Add(B)))
        {
            Console.WriteLine();
            Console.WriteLine("***********Error Encountered!!***");
            Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));
            // printing out
            Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A.Add(B)).ToString());
            Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
            Console.WriteLine();

            Console.WriteLine("Re-run the numbers with different key..");
            Rerun_SameNumbers(A, B);
            Console.WriteLine();

            Console.WriteLine("Re-run the same key with different numbers..");
            Rerun_SameKey(encryptAlgorithm, decryptAlgorithm);
            Console.WriteLine();

            Console.WriteLine("Re-run with same key and same numbers..");
            Rerun_SamekeyNumber(encryptAlgorithm, decryptAlgorithm, A, B);
            Console.WriteLine();

            return false;
        }
        return true;
    }

    public static byte[] StripTrailingZeros(byte[] array, int arrayLength)
    {
        byte[] array_stripped = new byte[arrayLength];

        Array.Copy(array, 0, array_stripped, 0, arrayLength);

        return array_stripped;
    }

    public static void Rerun_SameNumbers(BigInteger A, BigInteger B)
    {
        Paillier algorithm = new PaillierManaged();
        algorithm.KeySize = 384;
        algorithm.Padding = PaillierPaddingMode.LeadingZeros;

        string parametersXML = algorithm.ToXmlString(true);
        //Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        byte[] A_bytes = A.ToByteArrayUnsigned();
        byte[] B_bytes = B.ToByteArrayUnsigned();

        //encrypt A and B
        byte[] A_enc_bytes = encryptAlgorithm.EncryptData(A.ToByteArrayUnsigned());
        byte[] B_enc_bytes = encryptAlgorithm.EncryptData(B.ToByteArrayUnsigned());

        // decrypt A and B
        byte[] A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        byte[] B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        //getting homomorphic addition result
        byte[] C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        byte[] C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        BigInteger A_dec = new BigInteger(1, A_dec_bytes);
        BigInteger B_dec = new BigInteger(1, B_dec_bytes);
        BigInteger C_dec = new BigInteger(1, C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A.Add(B)).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }

    public static void Rerun_SameKey(Paillier encryptAlgorithm, Paillier decryptAlgorithm)
    {
        Random random = new Random();
        BigInteger A = new BigInteger(random.Next(32768).ToString());
        BigInteger B = new BigInteger(random.Next(32768).ToString());

        byte[] A_bytes = A.ToByteArrayUnsigned();
        byte[] B_bytes = B.ToByteArrayUnsigned();

        //encrypt A and B
        byte[] A_enc_bytes = encryptAlgorithm.EncryptData(A.ToByteArrayUnsigned());
        byte[] B_enc_bytes = encryptAlgorithm.EncryptData(B.ToByteArrayUnsigned());

        // decrypt A and B
        byte[] A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        byte[] B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        byte[] C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        byte[] C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        BigInteger A_dec = new BigInteger(1, A_dec_bytes);
        BigInteger B_dec = new BigInteger(1, B_dec_bytes);
        BigInteger C_dec = new BigInteger(1, C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A.Add(B)).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }

    public static void Rerun_SamekeyNumber(Paillier encryptAlgorithm, Paillier decryptAlgorithm,
        BigInteger A, BigInteger B)
    {
        byte[] A_bytes = A.ToByteArrayUnsigned();
        byte[] B_bytes = B.ToByteArrayUnsigned();

        //encrypt A and B
        byte[] A_enc_bytes = encryptAlgorithm.EncryptData(A.ToByteArrayUnsigned());
        byte[] B_enc_bytes = encryptAlgorithm.EncryptData(B.ToByteArrayUnsigned());

        // decrypt A and B
        byte[] A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        byte[] B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        byte[] C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        byte[] C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        BigInteger A_dec = new BigInteger(1, A_dec_bytes);
        BigInteger B_dec = new BigInteger(1, B_dec_bytes);
        BigInteger C_dec = new BigInteger(1, C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A.Add(B)).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }

    public static void PerformanceTest()
    {
        Console.WriteLine();
        Console.WriteLine("-- Performance Test --");

        long total_time_plaintext = 0;
        long total_time_encrypted = 0;

        for (int i = 0; i < 10; i++)
        {
            Console.WriteLine("-- Performance test iteration {0} --", i);

            total_time_plaintext += ProfilePlaintextMUL(250000);
            total_time_encrypted += ProfileEncryptedMUL(250000);
        }

        Console.WriteLine("Total time for plaintext addition  = {0} ticks", total_time_plaintext);
        Console.WriteLine("Total time for ciphertext addition = {0} ticks", total_time_encrypted);
        Console.WriteLine();
    }

    private static long ProfilePlaintextMUL(int iterations)
    {
        // clean up
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var rnd = new Random();

        // prepare and warm up 
        var a = rnd.Next(32768);
        var b = rnd.Next(32768);
        var c = a * b;

        var watch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            c = a * b;
        }
        watch.Stop();

        return watch.Elapsed.Ticks;
    }

    private static long ProfileEncryptedMUL(int iterations)
    {
        // clean up
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var rnd = new Random();

        // prepare and warm up 
        Paillier algorithm = new PaillierManaged();
        algorithm.KeySize = 384;
        algorithm.Padding = PaillierPaddingMode.LeadingZeros;
        string parametersXML = algorithm.ToXmlString(true);

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        var a = new BigInteger(rnd.Next(32768).ToString());
        var a_bytes = encryptAlgorithm.EncryptData(a.ToByteArrayUnsigned());

        var b = new BigInteger(rnd.Next(32768).ToString());
        var b_bytes = encryptAlgorithm.EncryptData(b.ToByteArrayUnsigned());

        var c_bytes = encryptAlgorithm.Addition(a_bytes, b_bytes);

        var watch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            c_bytes = encryptAlgorithm.Addition(a_bytes, b_bytes);
        }
        watch.Stop();

        return watch.Elapsed.Ticks;
    }
}

