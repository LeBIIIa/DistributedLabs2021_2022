using System;
using System.IO;
using System.Text;

namespace CryptoAlgorithmLibrary.SHA1
{
    public class SHA1_Algo
    {
        const int BLOCK_INTS = 16;  /* number of 32bit integers per SHA1 block */
        const int BLOCK_BYTES = BLOCK_INTS * 4;

        private readonly uint[] digest;
        private StringBuilder buffer;
        private ulong transforms;

        public SHA1_Algo()
        {
            digest = new uint[5];
            Reset();

        }

        private void Reset()
        {
            /* SHA1 initialization constants */
            digest[0] = 0x67452301;
            digest[1] = 0xefcdab89;
            digest[2] = 0x98badcfe;
            digest[3] = 0x10325476;
            digest[4] = 0xc3d2e1f0;

            /* Reset counters */
            buffer = new StringBuilder();
            transforms = 0;
        }
        private static uint Rol(uint value, int bits)
        {
            return (value << bits) | (value >> (32 - bits));
        }
        private static uint BLK(uint[] block, int i) //BLOCK_INTS
        {
            return Rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i], 1);
        }

        private static void R0(uint[] block, uint v, ref uint w, uint x, uint y, ref uint z, int i) //BLOCK_INTS
        {
            z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + Rol(v, 5);
            w = Rol(w, 30);
        }
        private static void R1(uint[] block, uint v, ref uint w, uint x, uint y, ref uint z, int i) //BLOCK_INTS
        {
            block[i] = BLK(block, i);
            z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + Rol(v, 5);
            w = Rol(w, 30);
        }
        private static void R2(uint[] block, uint v, ref uint w, uint x, uint y, ref uint z, int i) //BLOCK_INTS
        {
            block[i] = BLK(block, i);
            z += (w ^ x ^ y) + block[i] + 0x6ed9eba1 + Rol(v, 5);
            w = Rol(w, 30);
        }
        private static void R3(uint[] block, uint v, ref uint w, uint x, uint y, ref uint z, int i) //BLOCK_INTS
        {
            block[i] = BLK(block, i);
            z += (((w | x) & y) | (w & x)) + block[i] + 0x8f1bbcdc + Rol(v, 5);
            w = Rol(w, 30);
        }
        private static void R4(uint[] block, uint v, ref uint w, uint x, uint y, ref uint z, int i) //BLOCK_INTS
        {
            block[i] = BLK(block, i);
            z += (w ^ x ^ y) + block[i] + 0xca62c1d6 + Rol(v, 5);
            w = Rol(w, 30);
        }

        private void Transform(uint[] block)//[BLOCK_INTS]
        {
            uint a = digest[0];
            uint b = digest[1];
            uint c = digest[2];
            uint d = digest[3];
            uint e = digest[4];

            R0(block, a, ref b, c, d, ref e, 0);
            R0(block, e, ref a, b, c, ref d, 1);
            R0(block, d, ref e, a, b, ref c, 2);
            R0(block, c, ref d, e, a, ref b, 3);
            R0(block, b, ref c, d, e, ref a, 4);
            R0(block, a, ref b, c, d, ref e, 5);
            R0(block, e, ref a, b, c, ref d, 6);
            R0(block, d, ref e, a, b, ref c, 7);
            R0(block, c, ref d, e, a, ref b, 8);
            R0(block, b, ref c, d, e, ref a, 9);
            R0(block, a, ref b, c, d, ref e, 10);
            R0(block, e, ref a, b, c, ref d, 11);
            R0(block, d, ref e, a, b, ref c, 12);
            R0(block, c, ref d, e, a, ref b, 13);
            R0(block, b, ref c, d, e, ref a, 14);
            R0(block, a, ref b, c, d, ref e, 15);
            R1(block, e, ref a, b, c, ref d, 0);
            R1(block, d, ref e, a, b, ref c, 1);
            R1(block, c, ref d, e, a, ref b, 2);
            R1(block, b, ref c, d, e, ref a, 3);
            R2(block, a, ref b, c, d, ref e, 4);
            R2(block, e, ref a, b, c, ref d, 5);
            R2(block, d, ref e, a, b, ref c, 6);
            R2(block, c, ref d, e, a, ref b, 7);
            R2(block, b, ref c, d, e, ref a, 8);
            R2(block, a, ref b, c, d, ref e, 9);
            R2(block, e, ref a, b, c, ref d, 10);
            R2(block, d, ref e, a, b, ref c, 11);
            R2(block, c, ref d, e, a, ref b, 12);
            R2(block, b, ref c, d, e, ref a, 13);
            R2(block, a, ref b, c, d, ref e, 14);
            R2(block, e, ref a, b, c, ref d, 15);
            R2(block, d, ref e, a, b, ref c, 0);
            R2(block, c, ref d, e, a, ref b, 1);
            R2(block, b, ref c, d, e, ref a, 2);
            R2(block, a, ref b, c, d, ref e, 3);
            R2(block, e, ref a, b, c, ref d, 4);
            R2(block, d, ref e, a, b, ref c, 5);
            R2(block, c, ref d, e, a, ref b, 6);
            R2(block, b, ref c, d, e, ref a, 7);
            R3(block, a, ref b, c, d, ref e, 8);
            R3(block, e, ref a, b, c, ref d, 9);
            R3(block, d, ref e, a, b, ref c, 10);
            R3(block, c, ref d, e, a, ref b, 11);
            R3(block, b, ref c, d, e, ref a, 12);
            R3(block, a, ref b, c, d, ref e, 13);
            R3(block, e, ref a, b, c, ref d, 14);
            R3(block, d, ref e, a, b, ref c, 15);
            R3(block, c, ref d, e, a, ref b, 0);
            R3(block, b, ref c, d, e, ref a, 1);
            R3(block, a, ref b, c, d, ref e, 2);
            R3(block, e, ref a, b, c, ref d, 3);
            R3(block, d, ref e, a, b, ref c, 4);
            R3(block, c, ref d, e, a, ref b, 5);
            R3(block, b, ref c, d, e, ref a, 6);
            R3(block, a, ref b, c, d, ref e, 7);
            R3(block, e, ref a, b, c, ref d, 8);
            R3(block, d, ref e, a, b, ref c, 9);
            R3(block, c, ref d, e, a, ref b, 10);
            R3(block, b, ref c, d, e, ref a, 11);
            R4(block, a, ref b, c, d, ref e, 12);
            R4(block, e, ref a, b, c, ref d, 13);
            R4(block, d, ref e, a, b, ref c, 14);
            R4(block, c, ref d, e, a, ref b, 15);
            R4(block, b, ref c, d, e, ref a, 0);
            R4(block, a, ref b, c, d, ref e, 1);
            R4(block, e, ref a, b, c, ref d, 2);
            R4(block, d, ref e, a, b, ref c, 3);
            R4(block, c, ref d, e, a, ref b, 4);
            R4(block, b, ref c, d, e, ref a, 5);
            R4(block, a, ref b, c, d, ref e, 6);
            R4(block, e, ref a, b, c, ref d, 7);
            R4(block, d, ref e, a, b, ref c, 8);
            R4(block, c, ref d, e, a, ref b, 9);
            R4(block, b, ref c, d, e, ref a, 10);
            R4(block, a, ref b, c, d, ref e, 11);
            R4(block, e, ref a, b, c, ref d, 12);
            R4(block, d, ref e, a, b, ref c, 13);
            R4(block, c, ref d, e, a, ref b, 14);
            R4(block, b, ref c, d, e, ref a, 15);

            digest[0] = digest[0] + a;
            digest[1] = digest[1] + b;
            digest[2] = digest[2] + c;
            digest[3] = digest[3] + d;
            digest[4] = digest[4] + e;


            transforms++;
        }
        private void BufferToBlock(ref uint[] block) //BLOCK_INTS
        {
            for (int i = 0; i < BLOCK_INTS; i++)
            {
                block[i] = (uint)((buffer[4 * i + 3] & 0xff)
                    | (buffer[4 * i + 2] & 0xff) << 8
                    | (buffer[4 * i + 1] & 0xff) << 16
                    | (buffer[4 * i + 0] & 0xff) << 24);
            }
        }
        private void Update(Stream reader)
        {
            int offset = 0;
            while (offset < reader.Length)
            {
                byte[] sBufReader = new byte[BLOCK_BYTES];
                int gCount = reader.Read(sBufReader, 0, BLOCK_BYTES - buffer.Length);
                offset = offset + gCount;
                byte[] sBuf = new byte[gCount];
                Array.Copy(sBufReader, sBuf, gCount);
                buffer.Append(Encoding.ASCII.GetString(sBuf));
                if (buffer.Length != BLOCK_BYTES)
                {
                    return;
                }
                uint[] block = new uint[BLOCK_INTS];
                BufferToBlock(ref block);
                Transform(block);
                buffer.Clear();
            }
        }


        public void Update(string message)
        {
            using MemoryStream ms = new();
            using StreamWriter writer = new(ms);
            writer.Write(message);
            writer.Flush();
            ms.Position = 0;
            Update(ms);
        }
        public string Final()
        {
            /* Total number of hashed bits */
            ulong total_bits = (transforms * BLOCK_BYTES + (uint)buffer.Length) * 8;
            buffer.Append((char)0x80);
            int orig_size = buffer.Length;
            if (buffer.Length < BLOCK_BYTES)
                buffer.Append(new string((char)0x00, BLOCK_BYTES - buffer.Length));

            uint[] block = new uint[BLOCK_INTS];
            BufferToBlock(ref block);

            if (orig_size > BLOCK_BYTES - 8)
            {
                Transform(block);
                for (int i = 0; i < BLOCK_INTS - 2; i++)
                {
                    block[i] = 0;
                }
            }

            block[BLOCK_INTS - 1] = (uint)total_bits;
            block[BLOCK_INTS - 2] = (uint)(total_bits >> 32);
            Transform(block);

            StringBuilder sb = new();
            for (int i = 0; i < digest.Length; i++)
            {
                sb.Append(digest[i].ToString("x8"));
            }

            Reset();

            return sb.ToString();
        }
    }
}
