using CryptoAlgorithmLibrary.SHA1;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests
{
    [TestClass]
    public class SHA1_Tests
    {
        SHA1_Algo Checksum { get; set; }

        [TestInitialize]
        public void SHA1_TestsInit()
        {
            Checksum = new SHA1_Algo();
        }

        [TestMethod]
        ///http://www.sha1-online.com/
        [DataRow("test", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")]
        [DataRow("qwerty", "b1b3773a05c0ed0176787a4f1574ff0075f7521e")]
        [DataRow(
            "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest",
            "0e34a1b06b62e92a370b5a85b8b616d6aa5becc0")]
        [DataRow("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn", "c01fbfbc822046b03c598e28d43d56a4906e22ad")]
        [DataRow("hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "3ae8a7e1648678734ba5f3f57070b1b3a51f9b42")]
        [DataRow("tset", "6e45a996ca8c1c3bb0a7807c039dfffb02c0cad2")]
        public void TestForCorrectess(string input, string correctOutput)
        {
            Checksum.Update(input);
            string hash = Checksum.Final();
            Assert.AreEqual(correctOutput, hash);
        }

        [TestMethod]
        [DataRow("test", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd1")]
        [DataRow("test", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd2")]
        [DataRow("test", "a94a8fe5ccb19ba61c4c0873d391e987982fdbd1")]
        [DataRow(
            "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest",
            "0e34a1b06b62e92a350b5a85b8b616d6aa5becc0")]
        [DataRow("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn", "c02fbfbc822046b03c598e28d43d56a4906e22ad")]
        [DataRow("hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "3ae8a7e1648678134ba5f3f57070b1b3a51f9b42")]
        public void TestWithModification(string input, string modifiedOutput)
        {
            Checksum.Update(input);
            string hash = Checksum.Final();
            Assert.AreNotEqual(modifiedOutput, hash);
        }
    }
}
