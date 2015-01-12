//------------------------------------------------------------------------------
//
// Copyright © Microsoft Corporation, All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Microsoft.KeyVault.Client.Cryptography
{
    public static class NativeMethods
    {
        public const int Success = 0x00000000;                              // ERROR_SUCCESS
        public const int BadSignature = unchecked((int)0x80090006);        // NTE_BAD_SIGNATURE
        public const int InvalidParameter = unchecked((int)0x80090027);    // NTE_INVALID_PARAMETER

        [StructLayout(LayoutKind.Sequential)]
        public struct NCRYPT_PKCS1_PADDING_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
        }

        /// <summary>
        ///     Padding modes 
        /// </summary>
        public enum AsymmetricPaddingMode
        {
            None = 1,                       // BCRYPT_PAD_NONE
            Pkcs1 = 2,                      // BCRYPT_PAD_PKCS1
            Oaep = 4,                       // BCRYPT_PAD_OAEP
            Pss = 8                         // BCRYPT_PAD_PSS
        }

        [DllImport("ncrypt.dll")]
        public static extern int NCryptOpenStorageProvider([Out] out SafeNCryptProviderHandle phProvider,
                                                           [MarshalAs(UnmanagedType.LPWStr)] string pszProviderName,
                                                           int dwFlags);

        [DllImport("ncrypt.dll")]
        public static extern int NCryptImportKey(SafeNCryptProviderHandle hProvider,
                                                            IntPtr hImportKey,
                                                            [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
                                                            [In, MarshalAs(UnmanagedType.LPArray)] byte[] pParameterList,
                                                            out SafeNCryptKeyHandle phKey,
                                                            [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbData,
                                                            int cbData,
                                                            int dwFlags);

        [DllImport("ncrypt.dll")]
        public static extern int NCryptVerifySignature(SafeNCryptKeyHandle hKey,
                                                               [In] ref NCRYPT_PKCS1_PADDING_INFO pPaddingInfo,
                                                               [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbHashValue,
                                                               int cbHashValue,
                                                               [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbSignature,
                                                               int cbSignature,
                                                               AsymmetricPaddingMode dwFlags);

        public static byte[] NewNCryptPublicBlob(RSAParameters rsaParams)
        {
            // Builds a BCRYPT_RSAKEY_BLOB strucutre ( http://msdn.microsoft.com/en-us/library/windows/desktop/aa375531(v=vs.85).aspx ).
            var size = 6 * 4 + rsaParams.Exponent.Length + rsaParams.Modulus.Length;
            var data = new byte[size];
            var stream = new MemoryStream(data);
            var writer = new BinaryWriter(stream);
            writer.Write((int)0x31415352);
            writer.Write((int)rsaParams.Modulus.Length * 8);
            writer.Write((int)rsaParams.Exponent.Length);
            writer.Write((int)rsaParams.Modulus.Length);
            writer.Write((int)0);
            writer.Write((int)0);
            writer.Write(rsaParams.Exponent);
            writer.Write(rsaParams.Modulus);
            return data;
        }
    }
}
