using System;
using Org.BouncyCastle.Math;

namespace PaillierExt
{
    public class PaillierEncryptor : PaillierAbstractCipher
    {
        Random o_random;

        public PaillierEncryptor(PaillierKeyStruct p_struct)
            : base(p_struct)    // this base keyword means the constructor will use the base's constructor -TA
        {
            o_random = new Random();
        }

        // TODO: check again for encryption
        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            // *********** SPECIAL ************ //

            // generate random R
            //BigInteger R = new BigInteger();
            //R.genRandomBits(o_key_struct.N.BitLength() - 1, o_random); //R's BitLength is n-1 so that r is within Zn
            BigInteger R = new BigInteger(o_key_struct.N.BitLength - 1, o_random);

            // ciphertext c = g^m * r^n mod n^2
            BigInteger Nsquare = o_key_struct.N.Multiply(o_key_struct.N);
            BigInteger C = (o_key_struct.G.ModPow(new BigInteger(1, p_block), Nsquare).Multiply(
                           R.ModPow(o_key_struct.N, Nsquare))).Mod(Nsquare);

            // create an array to contain the ciphertext
            byte[] x_result = new byte[o_ciphertext_blocksize];
            //byte[] c_bytes = C.getBytes();
            byte[] c_bytes = C.ToByteArrayUnsigned();

            // copy c_bytes into x_result
            Array.Copy(c_bytes, 0, x_result, o_ciphertext_blocksize - c_bytes.Length, c_bytes.Length);

            // return result array
            return x_result;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            if (!(p_final_block.Length > 0))
                return new byte[0];     //return empty block

            // ***************** SPECIAL ******************* //
            return ProcessDataBlock(PadPlaintextBlock(p_final_block));
        }

        // ****** also special ******* //
        protected byte[] PadPlaintextBlock(byte[] p_block)
        {
            if (p_block.Length < o_block_size)
            {
                byte[] x_padded = new byte[o_block_size];

                switch (o_key_struct.Padding)
                {
                    // trailing zeros
                    case PaillierPaddingMode.Zeros:
                        Array.Copy(p_block, 0, x_padded, 0, p_block.Length);
                        break;

                    case PaillierPaddingMode.LeadingZeros:
                        Array.Copy(p_block, 0, x_padded, o_block_size - p_block.Length, p_block.Length);
                        break;

                    case PaillierPaddingMode.ANSIX923:
                        throw new System.NotImplementedException();
                        break;
                }

                return x_padded;
            }

            return p_block;
        }
    }
}
