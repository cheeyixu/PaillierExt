using Org.BouncyCastle.Math;

namespace PaillierExt
{
    public struct PaillierKeyStruct
    {
        public BigInteger N;
        public BigInteger G;
        public BigInteger Lambda;
        public BigInteger Miu;
        public PaillierPaddingMode Padding; // this parameter should be considered part of the public key

        // ******************** SPECIAL ************* //
        public int getPlaintextBlocksize()
        {
            return (N.BitLength - 1) / 8;
        }

        // TODO: check again ciphertext and plaintext block size
        public int getCiphertextBlocksize()
        {
            //return ((N.BitLength + 7) / 8) * 2;
            return ((N.BitLength + 7) / 8) * 2;     // +1 to acommodate signed bit for 2's complement
        }
    }
}
