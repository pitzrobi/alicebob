using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;


namespace alicebob
{
    class Program
    {
        static void Main(string[] args)
        {
            string SourceData;
            byte[] tmpSource;
            byte[] tmpHash;


            Console.WriteLine("Add meg a szöveget");
            SourceData = Console.ReadLine();
            

            tmpSource = ASCIIEncoding.ASCII.GetBytes(SourceData);
            Console.WriteLine("kerlek varj...");

            RsaKeyPairGenerator rsaKeyPairGen = new RsaKeyPairGenerator();
            rsaKeyPairGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = rsaKeyPairGen.GenerateKeyPair();


            RsaKeyParameters PrivateKey = (RsaKeyParameters)keyPair.Private;
            RsaKeyParameters PublicKey = (RsaKeyParameters)keyPair.Public;

            TextWriter tw1 = new StringWriter();
            PemWriter pw1 = new PemWriter(tw1);
            pw1.WriteObject(PublicKey);
            pw1.Writer.Flush();
            string publicwrite = tw1.ToString();
            Console.WriteLine("A Public key: {0}", publicwrite);
            Console.WriteLine();



            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine());
            cipher.Init(true, PublicKey);
            byte[] cipheretext = cipher.ProcessBlock(tmpSource, 0, tmpSource.Length);
            string resoult = Encoding.UTF8.GetString(cipheretext);
            Console.WriteLine("Kodolt szoveg: ");
            Console.WriteLine(resoult);


            Console.WriteLine("Nyomj meg egy gombot a dekodolashoz");
            Console.ReadKey();
            Decryption(cipheretext, PrivateKey);
        }

        static void Decryption(byte[] ct, RsaKeyParameters PvtKey)
        {
            IAsymmetricBlockCipher cipher1 = new OaepEncoding(new RsaEngine());
            cipher1.Init(false, PvtKey);
            byte[] deciphered = cipher1.ProcessBlock(ct, 0, ct.Length);
            string dekodolt = Encoding.UTF8.GetString(deciphered);
            Console.WriteLine();
            Console.WriteLine("Dekodolt szoveg:{0}", dekodolt);
            Console.WriteLine();
        }

    }
}
