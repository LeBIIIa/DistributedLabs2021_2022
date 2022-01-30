using CryptoAlgorithmLibrary.RSA;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Tests
{
    [TestClass]
    public class RSA_Tests
    {
        public readonly BigInteger newBigInteger = BigInteger.Parse("4340300884495571525792093478418444707275458804511673094179149063976798729236901037364745603809622136195437491529337266716613598203894984433311722694335279");
        RSA_Algo Checksum { get; set; }

        [TestInitialize]
        public void SHA1_TestsInit()
        {
            Checksum = new RSA_Algo();
        }

        [TestMethod]
        [DataRow("test")]
        [DataRow("qwerty")]
        [DataRow("tset")]
        [DataRow("hesoyam")]
        [DataRow("DistributedLabs")]
        [DataRow("C#_is_the_best")]
        public void TestForCorrectess(string input)
        {
            string encrypt = Checksum.Encrypt(input);
            string decrypt = Checksum.Decrypt(encrypt);
            Assert.AreEqual(input, decrypt);
        }

        [TestMethod]
        [DataRow("test")]
        [DataRow("qwerty")]
        [DataRow("tset")]
        [DataRow("hesoyam")]
        [DataRow("DistributedLabs")]
        [DataRow("C#_is_the_best")]
        public void TestWithModification(string input)
        {
            string encrypt = Checksum.Encrypt(input);
            Checksum.UpdatePrime1(newBigInteger);
            string decrypt = Checksum.Decrypt(encrypt);
            Assert.AreNotEqual(input, decrypt);
        }
    }
}
