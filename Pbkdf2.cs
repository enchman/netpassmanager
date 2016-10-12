using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TestConsole
{
    public enum KeyDerivationPrf
    {
        HMACSHA1,
        HMACSHA256,
        HMACSHA512
    }

    public static class KeyDerivation
    {
        public static byte[] Pbkdf2(string password, byte[] salt, KeyDerivationPrf method, int iterations, int requestBytes)
        {
            Pbkdf2Managed rfc = new Pbkdf2Managed(password, salt, iterations, method);
            return rfc.GetBytes(requestBytes);
        }
        public static byte[] Pbkdf2(byte[] password, byte[] salt, KeyDerivationPrf method, int iterations, int requestBytes)
        {
            Pbkdf2Managed rfc = new Pbkdf2Managed(password, salt, iterations, method);
            return rfc.GetBytes(requestBytes);
        }
        
    }

    public class Pbkdf2Managed : Pbkdf2Base
    {
        public Pbkdf2Managed(byte[] password, byte[] salt, int iterations, KeyDerivationPrf hashMethod):
            base (password, salt, iterations, getMethod(hashMethod))
        { }
        public Pbkdf2Managed(string password, byte[] salt, int iterations, KeyDerivationPrf hashMethod) :
            base(password, salt, iterations, getMethod(hashMethod))
        { }

        private static HMAC getMethod(KeyDerivationPrf method)
        {
            HMAC hash = new HMACSHA1();
            switch (method)
            {
                case KeyDerivationPrf.HMACSHA256:
                    hash = new HMACSHA256();
                    break;
                case KeyDerivationPrf.HMACSHA512:
                    hash = new HMACSHA512();
                    break;
            }

            return hash;
        }
    }

    public abstract class Pbkdf2Base
    {
        private uint blockIndex = 1;
        private readonly int blockSize;

        private byte[] buffer;
        private int bufferStartIndex = 0;
        private int bufferEndIndex = 0;

        protected HMAC hashAlgorithm;
        protected byte[] salt;
        protected int iterations;

        public Pbkdf2Base(string password, byte[] salt, HMAC algorithm) :
            this(Encoding.UTF8.GetBytes(password), salt, 1000, algorithm) { }
        public Pbkdf2Base(byte[] password, byte[] salt, HMAC algorithm) :
            this(password, salt, 1000, algorithm) { }
        public Pbkdf2Base(string password, byte[] salt, int iterations, HMAC algorithm):
            this(Encoding.UTF8.GetBytes(password), salt, iterations, algorithm) { }

        public Pbkdf2Base(byte[] password, byte[] salt, int iterations, HMAC algorithm)
        {
            algorithm.Key = password;
            blockSize = algorithm.HashSize / 8;
            buffer = new byte[blockSize];

            this.hashAlgorithm = algorithm;
            this.salt = salt;
            this.iterations = iterations;
        }

        public byte[] GetBytes(int count)
        {
            byte[] result = new byte[count];

            int resultOffset = 0;
            int bufferCount = bufferEndIndex - bufferStartIndex;

            if (bufferCount > 0)
            {
                if (count < bufferCount)
                {
                    Buffer.BlockCopy(buffer, bufferStartIndex, result, 0, count);
                    bufferStartIndex += count;
                    return result;
                }
                Buffer.BlockCopy(buffer, bufferStartIndex, result, 0, bufferCount);
                bufferStartIndex = bufferEndIndex = 0;
                resultOffset += bufferCount;
            }

            while (resultOffset < count)
            {
                int needCount = count - resultOffset;
                buffer = function();
                if (needCount > blockSize)
                {
                    Buffer.BlockCopy(buffer, 0, result, resultOffset, blockSize);
                    resultOffset += blockSize;
                }
                else
                {
                    Buffer.BlockCopy(buffer, 0, result, resultOffset, needCount);
                    bufferStartIndex = needCount;
                    bufferEndIndex = blockSize;
                    return result;
                }
            }

            return result;
        }

        public byte[] function()
        {
            if (blockIndex == uint.MaxValue)
                throw new Exception("Derived key exceed limitation");

            byte[] salted = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, salted, 0, salt.Length);
            Buffer.BlockCopy(blockIndex.ToBytes(), 0, salted, salt.Length, 4);
            byte[] hashed = hashAlgorithm.ComputeHash(salted);

            byte[] result = hashed;

            for (int i = 2; i <= iterations; i++)
            {
                hashed = hashAlgorithm.ComputeHash(hashed, 0, hashed.Length);
                for (int j = 0; j < blockSize; j++)
                {
                    result[j] = (byte)(result[j] ^ hashed[j]);
                }
            }

            blockIndex++;

            return result;
        }
    }

    static class Helper
    {
        public static byte[] ToBytes(this uint source)
        {
            byte[] num = BitConverter.GetBytes(source);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(num);

            return num;
        }

        public static string ToHex(this byte[] source, bool lowercase = false)
        {
            string hex = BitConverter.ToString(source).Replace("-", string.Empty);

            if (lowercase)
                return hex.ToLower();
            else
                return hex;
        }
    }
}
