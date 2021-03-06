﻿/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.
 
 This library is provided as-is and is covered by the MIT License [1].
  
 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;

namespace PaillierExt
{
    [Serializable]
    public struct PaillierParameters
    {
        public byte[] N;
        public byte[] G;

        public PaillierPaddingMode Padding;
        [NonSerialized]
        public byte[] Lambda;
        [NonSerialized]
        public byte[] Miu;
    }
}
