using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;

namespace CryptoAlgorithmLibrary.RSA
{
    public static class RSA_Helper
    {
        public static T[] CopySlice<T>(this T[] source, int index, int length, bool padToLength = false)
        {
            int n = length;
            T[] slice = null;

            if (source.Length < index + length)
            {
                n = source.Length - index;
                if (padToLength)
                {
                    slice = new T[length];
                }
            }

            if (slice == null) slice = new T[n];
            Array.Copy(source, index, slice, 0, n);
            return slice;
        }

        public static IEnumerable<T[]> Slices<T>(this T[] source, int count, bool padToLength = false)
        {
            for (var i = 0; i < source.Length; i += count)
                yield return source.CopySlice(i, count, padToLength);
        }

        public static ushort GetBitsize(this BigInteger num)
        {
            ushort bitSize = 0;
            while (num != 0)
            {
                num /= 2;
                bitSize++;
            }
            return bitSize;
        }

        //stackoverflow.com/questions/7483706/c-sharp-modinverse-function
        public static BigInteger ModInverse(this BigInteger e, ref BigInteger phi)
        {
            BigInteger i = phi, v = 0, d = 1;
            while (e > 0)
            {
                BigInteger t = i / e, x = e;
                e = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= phi;
            if (v < 0) v = (v + phi) % phi;
            return v;
        }

        //Miller-Rabin
        public static bool IsProbablePrime(this BigInteger w, int iterations)
        {
            if (w == 2 || w == 3)
                return true;
            if (w < 2 || w % 2 == 0)
                return false;


            //1. Let a be the largest integer such that 2^a divides w−1
            BigInteger m = w - 1;
            ushort a = 0;
            while (m % 2 == 0)
            {
                m /= 2;
                a += 1;
            }

            //3. wlen = len (w).
            ushort bitsize = w.GetBitsize();
            int wlen = bitsize / 8;
            if (bitsize % 8 == 0)
                wlen++;
            if (wlen == 0)
                wlen++;

            RandomNumberGenerator rbg = RandomNumberGenerator.Create();
            byte[] bytes = new byte[wlen];
            BigInteger b;


            //4. For i = 1 to iterations do
            for (int i = 1; i <= iterations; i++)
            {
                //4.1 Obtain a string b of wlen bits from an RBG.
                ushort cycles = 0;
                do
                {
                    cycles++;
                    if (cycles == 2e6)
                        return false;

                    rbg.GetBytes(bytes);

                    bytes[wlen - 1] = unchecked((byte)((0xFF >> 1 + (7 - (bitsize % 8))) & bytes[wlen - 1]));
                    b = new BigInteger(bytes);
                } while (b <= 1 || b >= w - 1);

                //4.3 z = b^m mod w
                BigInteger z = BigInteger.ModPow(b, m, w);

                //4.4 If ((z = 1) or (z = w − 1)), then go to step 4.7.
                if (z == 1 || z == w - 1)
                    continue;

                //4.5 For j = 1 to a − 1 do
                for (int j = 1; j < a; j++)
                {
                    z = BigInteger.ModPow(z, 2, w);     //4.5.1 z = z^2 mod w.
                    if (z == w - 1)                     //4.5.2 If (z = w−1), then go to step 4.7
                        break;
                    if (z == 1)                         //4.5.3 If (z = 1), then go to step 4.6.
                        return false;                   //4.6 ret composite
                }

                if (z != w - 1)
                    return false;
            }


            return true;
        }
    }
}
