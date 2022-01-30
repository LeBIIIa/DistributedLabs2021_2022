using CryptoAlgorithmLibrary.Helpers;

using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace CryptoAlgorithmLibrary.RSA
{
    public class RSA_Algo
    {
        private const int BITSIZE = 512;
        private BigInteger prime1, prime2;
        private BigInteger modulus, phi, privateExp;
        private readonly BigInteger publicExp;
        readonly RandomNumberGenerator rbg = RandomNumberGenerator.Create();

        public RSA_Algo()
        {
            prime1 = GeneratePrime();
            prime2 = GeneratePrime();
            if (prime2 > prime1)
            {
                BigInteger test = prime1;
                prime1 = prime2;
                prime2 = test;
            }
            publicExp = new BigInteger(65537);
            CalculatePrivateKey();
        }

        private static BigInteger GeneratePrime()
        {
            RandomNumberGenerator rbg = RandomNumberGenerator.Create();
            int wlen = (BITSIZE / 8) + 1;

            byte[] bytes = new byte[wlen];
            BigInteger testPrime;
            rbg.GetBytes(bytes);
            bytes[wlen - 1] = 0x00;
            bytes[0] |= 0x01;
            testPrime = new BigInteger(bytes);

            bool IsProbablePrime = false;
            int count = 0;
            while (!IsProbablePrime && count <= 2e3)
            {
                count++;
                testPrime = testPrime + 2;
                IsProbablePrime = testPrime.IsProbablePrime(5);
            }
            return testPrime;
        }

        private void CalculatePrivateKey()
        {
            ushort prime1BitSize = prime1.GetBitsize();
            ushort prime2BitSize = prime2.GetBitsize();
            if (prime1BitSize < 126 || prime2BitSize < 126)
            {
                ThrowHelper.ArgumentException("Please insert numbers with at least 126 bits");
            }

            modulus = BigInteger.Multiply(prime1, prime2);

            phi = modulus - prime1 - prime2 + 1;
            privateExp = publicExp.ModInverse(ref phi);
        }

        public string Encrypt(string text)
        {
            //Pegar tamanho dos blocos
            int blocklen = (modulus.GetBitsize() / 8) - 4;
            if (blocklen < 5)
            {
                return ThrowHelper.ArgumentException<string>("Key too small", nameof(modulus));
            }

            //Dividir plaintext em blocos
            byte[] plaintextArr = Encoding.UTF8.GetBytes(text);
            ushort blockCnt = 0;
            StringBuilder finalString = new();
            foreach (byte[] plainBlock in plaintextArr.Slices(blocklen))
            {
                //Add padding
                byte[] withPadArr = new byte[plainBlock.Length + 4]; //4 bytes random
                byte[] padArr = new byte[4];
                rbg.GetBytes(padArr);
                padArr[0] &= 0x7F; //make sure the first bit is always zero. No negative numbers for us :D
                Array.Copy(padArr, withPadArr, 4);
                Array.Copy(plainBlock, 0, withPadArr, 4, plainBlock.Length);


                Array.Reverse(withPadArr);
                BigInteger toCrypt = new(withPadArr);

                BigInteger crypt = BigInteger.ModPow(toCrypt, publicExp, modulus);
                byte[] cryptArr = crypt.ToByteArray();
                string b58Enc = Base58CheckEncoding.Encode(cryptArr).ToString();
                finalString.Append(b58Enc);
                finalString.Append('_');

                blockCnt++;
            }
            return finalString.ToString().TrimEnd('_');
        }

        public string Decrypt(string encText)
        {
            string startString = encText;

            ushort blockCnt = 0;
            StringBuilder finalString = new();
            foreach (string cryptBlock in startString.Split('_'))
            {
                //CryptText inicial
                byte[] cryptArr;
                cryptArr = Base58CheckEncoding.Decode(cryptBlock);

                BigInteger crypt = new(cryptArr);
                BigInteger decrypt = BigInteger.ModPow(crypt, privateExp, modulus);

                //Remove padding
                byte[] decryptWithPadArr = decrypt.ToByteArray();
                byte[] decryptArr = new byte[decryptWithPadArr.Length - 4];
                Array.Copy(decryptWithPadArr, decryptArr, decryptArr.Length);
                Array.Reverse(decryptArr);

                string rsaDec = Encoding.UTF8.GetString(decryptArr);
                finalString.Append(rsaDec);

                blockCnt++;
            }

            return finalString.ToString();
        }

        public void UpdatePrime1(BigInteger newPrime1)
        {
            prime1 = newPrime1;
            if (prime2 > prime1)
            {
                BigInteger test = prime1;
                prime1 = prime2;
                prime2 = test;
            }
            CalculatePrivateKey();
        }
    }
}
