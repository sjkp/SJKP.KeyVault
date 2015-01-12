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
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.KeyVault.Client.Cryptography;
using Microsoft.KeyVault.WebKey;
using Microsoft.Win32.SafeHandles;

namespace Microsoft.KeyVault.Client
{
    public static class KeyVaultClientExtensions
    {
        /// <summary>
        /// Decrypts a single block of encrypted data
        /// </summary>
        /// <param name="keyBundle">The key to use for decryption</param>
        /// <param name="algorithm">The encryption algorithm</param>
        /// <param name="cipherText">The encrypted data</param>
        /// <returns></returns>
        public static async Task<KeyOperationResult> DecryptDataAsync( this KeyVaultClient client, KeyBundle keyBundle, string algorithm, byte[] cipherText )
        {
            if ( keyBundle == null )
                throw new ArgumentNullException( "keyBundle" );

            return await client.DecryptDataAsync( keyBundle.Key, algorithm, cipherText ).ConfigureAwait( false );
        }

        /// <summary>
        /// Decrypts a single block of encrypted data
        /// </summary>
        /// <param name="key">The web key to use for decryption</param>
        /// <param name="algorithm">The encryption algorithm</param>
        /// <param name="cipherText">The encrypted data</param>
        /// <returns></returns>
        public static async Task<KeyOperationResult> DecryptDataAsync( this KeyVaultClient client, JsonWebKey key, string algorithm, byte[] cipherText )
        {
            if ( key == null )
                throw new ArgumentNullException( "key" );

            return await client.DecryptDataAsync( key.Kid, algorithm, cipherText ).ConfigureAwait( false );
        }

        /// <summary>
        /// Encrypts a single block of data. The amount of data that may be encrypted is determined
        /// by the target key type and the encryption algorithm, e.g. RSA, RSA_OAEP
        /// </summary>
        /// <param name="keyBundle">The key bundle</param>
        /// <param name="algorithm">The encryption algorithm</param>
        /// <param name="digest">The plain text to encrypt</param>
        /// <returns></returns>
        public static async Task<KeyOperationResult> EncryptDataAsync( this KeyVaultClient client, KeyBundle keyBundle, string algorithm, byte[] plaintext )
        {
            if ( keyBundle == null )
                throw new ArgumentNullException( "keyBundle" );

            return await client.EncryptDataAsync( keyBundle.Key, algorithm, plaintext ).ConfigureAwait( false );
        }

        /// <summary>
        /// Encrypts a single block of data. The amount of data that may be encrypted is determined
        /// by the target key type and the encryption algorithm, e.g. RSA, RSA_OAEP
        /// </summary>
        /// <param name="key">The web key</param>
        /// <param name="algorithm">The encryption algorithm</param>
        /// <param name="digest">The plain text to encrypt</param>
        /// <returns></returns>
        public static async Task<KeyOperationResult> EncryptDataAsync( this KeyVaultClient client, JsonWebKey key, string algorithm, byte[] plaintext )
        {
            KeyOperationResult result = null;

            if ( key == null )
                throw new ArgumentNullException( "key" );

            if ( string.IsNullOrEmpty( algorithm ) )
                throw new ArgumentNullException( "algorithm" );

            if ( plaintext == null )
                throw new ArgumentNullException( "plaintext" );

            switch ( key.Kty )
            {
                case JsonWebKeyType.Rsa:
                case JsonWebKeyType.RsaHsm:
                    var provider = key.ToRSA();

                    if ( provider == null || !typeof( RSACryptoServiceProvider ).IsInstanceOfType( provider ) )
                        throw new InvalidOperationException( "JsonWebKey RSA provider type is not supported" );

                    if ( algorithm != JsonWebKeyEncryptionAlgorithm.RSA15 && algorithm != JsonWebKeyEncryptionAlgorithm.RSAOAEP )
                        throw new ArgumentException( "algorithm" );

                    var cipher_text = await client.EncryptDataAsync( (RSACryptoServiceProvider)provider, plaintext, algorithm == JsonWebKeyEncryptionAlgorithm.RSAOAEP ).ConfigureAwait( false );

                    result = new KeyOperationResult( key.Kid, cipher_text );
                    break;

                default:
                    result = await client.EncryptDataAsync( key.Kid, algorithm, plaintext ).ConfigureAwait( false );
                    break;
            }

            return result;
        }
        
#pragma warning disable 1998
        /// <summary>
        /// Encrypts a single block of data. The amount of data that may be encrypted is determined
        /// by the target key type and the encryption algorithm, e.g. RSA, RSA_OAEP
        /// </summary>
        /// <param name="encryptionKey">The encryption key</param>
        /// <param name="data">The data to encrypt</param>
        /// <param name="useOAEP">false for RSA1_5, true for RSA_OAEP</param>
        /// <returns>The encrypted data</returns>
        private static async Task<byte[]> EncryptDataAsync( this KeyVaultClient client, RSACryptoServiceProvider encryptionKey, byte[] data, bool useOAEP = true )
        {
            if ( encryptionKey == null )
                throw new ArgumentNullException( "encryptionKey" );

            if ( data == null )
                throw new ArgumentNullException( "data" );

            return encryptionKey.Encrypt( data, useOAEP );
        }
#pragma warning restore 1998

        /// <summary>
        /// Imports an X509 Certificate, including private key, to the specified vault.
        /// </summary>
        /// <param name="client">The KmsClient</param>
        /// <param name="vaultAddress">The vault address to import the key</param>
        /// <param name="certificate">The certificate to import</param>
        /// <returns></returns>
        public static async Task<KeyBundle> ImportKeyAsync( this KeyVaultClient client, string vaultAddress, X509Certificate2 certificate, bool? importToHardware = null )
        {
            if ( certificate == null )
                throw new ArgumentNullException( "certificate" );

            return await ImportKeyAsync( client, vaultAddress, certificate.GetCertHashString(), certificate, importToHardware ).ConfigureAwait( false );
        }

        /// <summary>
        /// Imports an X509 Certificate, including private key, to the specified vault.
        /// </summary>
        /// <param name="client">The KmsClient</param>
        /// <param name="vaultAddress">The vault address to import the key</param>
        /// <param name="certificate">The certificate to import</param>
        /// <returns></returns>
        public static async Task<KeyBundle> ImportKeyAsync( this KeyVaultClient client, string vaultAddress, string keyName, X509Certificate2 certificate, bool? importToHardware = null )
        {
            if ( string.IsNullOrEmpty( vaultAddress ) )
                throw new ArgumentNullException( "vaultAddress" );

            if ( certificate == null )
                throw new ArgumentNullException( "certificate" );

            if ( !certificate.HasPrivateKey )
                throw new ArgumentException( "Certificate does not have a private key" );

            var key = certificate.PrivateKey as RSA;

            if ( key == null )
                throw new ArgumentException( string.Format( CultureInfo.CurrentCulture, "Certificate key uses unsupported algorithm {0}", certificate.GetKeyAlgorithm() ) );

            var keyBundle = new KeyBundle
            {
                Key        = new JsonWebKey( key, true ),
                Attributes = new KeyAttributes
                {
                    Enabled   = true,
                    Expires   = certificate.NotAfter.ToUniversalTime().ToUnixTime(),
                    NotBefore = certificate.NotBefore.ToUniversalTime().ToUnixTime(),
                },
            };

            return await client.ImportKeyAsync( vaultAddress, keyName, keyBundle, importToHardware ).ConfigureAwait( false );
        }

        /// <summary>
        /// Creates a signature from a digest using the specified key in the vault 
        /// </summary>
        /// <param name="keyBundle"> The key bundle of the signing key </param>
        /// <param name="algorithm"> the signing algorithm </param>
        /// <param name="digest"> the signing digest hash value </param>
        /// <returns> signature </returns>
        public static async Task<KeyOperationResult> SignAsync( this KeyVaultClient client, KeyBundle keyBundle, string algorithm, byte[] digest )
        {
            if ( keyBundle == null )
                throw new ArgumentNullException( "keyBundle" );

            return await client.SignAsync( keyBundle.Key, algorithm, digest ).ConfigureAwait( false );
        }

        /// <summary>
        /// Creates a signature from a digest using the specified key in the vault 
        /// </summary>
        /// <param name="key"> The web key of the signing key </param>
        /// <param name="algorithm"> the signing algorithm </param>
        /// <param name="digest"> the signing digest hash value </param>
        /// <returns> signature </returns>
        public static async Task<KeyOperationResult> SignAsync( this KeyVaultClient client, JsonWebKey key, string algorithm, byte[] digest )
        {
            if ( key == null )
                throw new ArgumentNullException( "key" );

            return await client.SignAsync( key.Kid, algorithm, digest ).ConfigureAwait( false );
        }

        public static async Task<KeyOperationResult> UnwrapKeyAsync( this KeyVaultClient client, KeyBundle wrappingKey, byte[] wrappedKey, string algorithm )
        {
            if ( wrappingKey == null )
                throw new ArgumentNullException( "wrappingKey" );

            return await client.UnwrapKeyAsync( wrappingKey.Key, wrappedKey, algorithm ).ConfigureAwait( false );
        }

        public static async Task<KeyOperationResult> UnwrapKeyAsync( this KeyVaultClient client, JsonWebKey wrappingKey, byte[] wrappedKey, string algorithm )
        {
            if ( wrappingKey == null )
                throw new ArgumentNullException( "wrappingKey" );

            if ( wrappedKey == null )
                throw new ArgumentNullException( "wrappedKey" );

            return await client.UnwrapKeyAsync( wrappingKey.Kid, algorithm, wrappedKey ).ConfigureAwait( false );
        }

        
        /// <summary>
        /// Wraps a symmetric key using the specified wrapping key and algorithm.
        /// </summary>
        /// <param name="client">The KMSClient instance</param>
        /// <param name="wrappingKey">The wrapping key</param>
        /// <param name="key">The key to wrap</param>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The wrapped key</returns>
        public static async Task<bool> VerifyAsync( this KeyVaultClient client, KeyBundle verifyKey, string algorithm, byte[] digest, byte[] signature )
        {
            return await client.VerifyAsync( verifyKey.Key, algorithm, digest, signature ).ConfigureAwait( false );
        }

        /// <summary>
        /// Wraps a symmetric key using the specified wrapping key and algorithm.
        /// </summary>
        /// <param name="client">The KMSClient instance</param>
        /// <param name="wrappingKey">The wrapping key</param>
        /// <param name="key">The key to wrap</param>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The wrapped key</returns>
        public static async Task<bool> VerifyAsync( this KeyVaultClient client, JsonWebKey verifyKey, string algorithm, byte[] digest, byte[] signature )
        {
            bool result = false;

            if ( verifyKey == null )
                throw new ArgumentNullException( "verifyKey" );

            if ( digest == null )
                throw new ArgumentNullException( "digest" );

            if ( signature == null )
                throw new ArgumentNullException( "signature" );

            switch ( verifyKey.Kty )
            {
                case JsonWebKeyType.Rsa:
                case JsonWebKeyType.RsaHsm:
                    var rsaParameters = verifyKey.ToRSAParameters();

                    result = await client.VerifyAsync( rsaParameters, algorithm, digest, signature ).ConfigureAwait( false );
                    break;

                default:
                    result = await client.VerifyAsync( verifyKey.Kid, algorithm, digest, signature ).ConfigureAwait( false );
                    break;
            }

            return result;
        }

        public static async Task<bool> VerifyAsync( this KeyVaultClient client, RSAParameters rsaParameters, string algorithm, byte[] digest, byte[] signature )
        {
            if ( string.IsNullOrWhiteSpace( algorithm ) )
                throw new ArgumentNullException( "algorithm" );

            if ( digest == null )
                throw new ArgumentNullException( "digest" );

            if ( signature == null )
                throw new ArgumentNullException( "signature" );

            var task = new Task<bool>( () =>
            {
                switch ( algorithm )
                {
                    case "RS256":
                    case "RS384":
                    case "RS512":
                        using ( var localKey = new RSACryptoServiceProvider() )
                        {
                            localKey.ImportParameters( rsaParameters );
                            return localKey.VerifyHash( digest, CryptoConfig.MapNameToOID( MapAlgToHashAlgorithm( algorithm ) ), signature );
                        }

                    case "RSSP1":
                    case "RSNULL":
                        {
                            SafeNCryptProviderHandle hProvider;
                            var errorCode = NativeMethods.NCryptOpenStorageProvider( out hProvider, "Microsoft Software Key Storage Provider", 0 );
                            if ( errorCode != NativeMethods.Success )
                                throw new CryptographicException( errorCode );

                            var blob = NativeMethods.NewNCryptPublicBlob( rsaParameters );
                            SafeNCryptKeyHandle hKey;
                            errorCode = NativeMethods.NCryptImportKey( hProvider, IntPtr.Zero, "RSAPUBLICBLOB", null, out hKey, blob, blob.Length, 0 );
                            if ( errorCode != NativeMethods.Success )
                                throw new CryptographicException( errorCode );

                            var pkcs1Info = new NativeMethods.NCRYPT_PKCS1_PADDING_INFO();
                            pkcs1Info.pszAlgId = null;

                            errorCode = NativeMethods.NCryptVerifySignature( hKey, ref pkcs1Info, digest, digest.Length, signature, signature.Length, NativeMethods.AsymmetricPaddingMode.Pkcs1 );
                            if ( errorCode != NativeMethods.Success && errorCode != NativeMethods.BadSignature && errorCode != NativeMethods.InvalidParameter )
                                throw new CryptographicException( errorCode );

                            return ( errorCode == NativeMethods.Success );
                        }

                    default:
                        throw new ArgumentException( "Invalid algorithm: " + algorithm );
                }
            } );

            task.Start();
            
            return await task.ConfigureAwait( false );
        }

        private static string MapAlgToHashAlgorithm(string alg)
        {
            switch (alg)
            {
                case "RS256":
                    return "SHA256";

                case "RS384":
                    return "SHA384";

                case "RS512":
                    return "SHA512";

                default:
                    throw new ArgumentException("Invalid algorithm: " + alg);
            }
        }

        /// <summary>
        /// Wraps a symmetric key using the specified wrapping key and algorithm.
        /// </summary>
        /// <param name="client">The KMSClient instance</param>
        /// <param name="wrappingKey">The wrapping key</param>
        /// <param name="key">The key to wrap</param>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The wrapped key</returns>
        public static async Task<KeyOperationResult> WrapKeyAsync( this KeyVaultClient client, KeyBundle wrappingKey, byte[] key, string algorithm )
        {
            if ( wrappingKey == null )
                throw new ArgumentNullException( "keyBundle" );

            return await client.WrapKeyAsync( wrappingKey.Key, key, algorithm ).ConfigureAwait( false );
        }

        /// <summary>
        /// Wraps a symmetric key using the specified wrapping key and algorithm.
        /// </summary>
        /// <param name="client">The KMSClient instance</param>
        /// <param name="wrappingKey">The wrapping key</param>
        /// <param name="key">The key to wrap</param>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The wrapped key</returns>
        public static async Task<KeyOperationResult> WrapKeyAsync( this KeyVaultClient client, JsonWebKey wrappingKey, byte[] key, string algorithm )
        {
            KeyOperationResult result = null;

            if ( wrappingKey == null )
                throw new ArgumentNullException( "wrappingKey" );

            if ( key == null )
                throw new ArgumentNullException( "key" );

            switch ( wrappingKey.Kty )
            {
                case JsonWebKeyType.Rsa:
                case JsonWebKeyType.RsaHsm:
                    var provider = wrappingKey.ToRSA();

                    if ( provider == null || !typeof( RSACryptoServiceProvider ).IsInstanceOfType( provider ) )
                        throw new InvalidOperationException( "JsonWebKey RSA provider type is not supported" );

                    if ( algorithm != JsonWebKeyEncryptionAlgorithm.RSA15 && algorithm != JsonWebKeyEncryptionAlgorithm.RSAOAEP )
                        throw new ArgumentException( "algorithm" );

                    var encrypted_key = await client.WrapKeyAsync( (RSACryptoServiceProvider)provider, key, algorithm == JsonWebKeyEncryptionAlgorithm.RSAOAEP ).ConfigureAwait( false );

                    result = new KeyOperationResult( wrappingKey.Kid, encrypted_key );
                    break;

                default:
                    result = await client.WrapKeyAsync( wrappingKey.Kid, algorithm, key ).ConfigureAwait( false );
                    break;
            }

            return result;
        }

#pragma warning disable 1998
        /// <summary>
        /// Wraps a symmetric key using the specified wrapping key and algorithm.
        /// </summary>
        /// <param name="client">The KMSClient instance</param>
        /// <param name="wrappingKey">The wrapping key</param>
        /// <param name="key">The key to wrap</param>
        /// <param name="algorithm">The algorithm to use</param>
        /// <returns>The wrapped key</returns>
        private static async Task<byte[]> WrapKeyAsync( this KeyVaultClient client, RSACryptoServiceProvider wrappingKey, byte[] key, bool useOAEP = true )
        {
            if ( wrappingKey == null )
                throw new ArgumentNullException( "wrappingKey" );

            if ( key == null )
                throw new ArgumentNullException( "key" );

            return wrappingKey.Encrypt( key, useOAEP );
        }
#pragma warning restore 1998
    }
}
