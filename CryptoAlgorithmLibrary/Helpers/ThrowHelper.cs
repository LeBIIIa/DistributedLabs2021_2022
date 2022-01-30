using System;
using System.Runtime.CompilerServices;

namespace CryptoAlgorithmLibrary.Helpers
{
    public class ThrowHelper
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static T ArgumentException<T>(string message = default, string paramName = default)
        {
            throw new ArgumentException(message, paramName);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ArgumentException(string message = default, string paramName = default)
        {
            throw new ArgumentException(message, paramName);
        }
    }
}
