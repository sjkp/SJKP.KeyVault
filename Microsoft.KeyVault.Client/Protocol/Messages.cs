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

using System.Collections.Generic;
using System.Runtime.Serialization;
using Microsoft.KeyVault.WebKey;
using Microsoft.KeyVault.WebKey.Json;
using Newtonsoft.Json;
using System.Security;

namespace Microsoft.KeyVault.Client.Protocol
{
    public static class MessagePropertyNames
    {
        public const string Algorithm    = "alg";
        public const string Attributes   = "attributes";
        public const string Digest       = "digest";
        public const string Hsm          = "hsm";
        public const string Key          = "key";
        public const string KeySize      = "key_size";
        public const string KeyOps       = "key_ops";
        public const string Kid          = "kid";
        public const string Kty          = "kty";
        public const string Value        = "value";
        public const string Id           = "id";
    }

    #region Error Response Messages

    [JsonObject]
    public class Error
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "code", Required = Required.Default )]
        public string Code { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "message", Required = Required.Default )]
        public string Message { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class ErrorResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "error", Required = Required.Default )]
        public Error Error { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    #endregion

    #region Key Management Messages
    [JsonObject]
    public class GetKeyResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Key, Required = Required.Always )]
        public JsonWebKey Key { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Always )]
        public KeyAttributes Attributes { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class BackupKeyResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter( typeof( Base64UrlConverter ) )]
        public byte[] Value { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class CreateKeyRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Kty, Required = Required.Always )]
        public string Kty { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.KeySize, Required = Required.Default )]
        public int? KeySize { get; set; }

        /// <summary>
        /// Supported Key Operations
        /// </summary>
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.KeyOps, Required = Required.Default )]
        public string[] KeyOps { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Default )]
        public KeyAttributes Attributes { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class ImportKeyRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Key, Required = Required.Always )]
        public JsonWebKey Key { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Always )]
        public KeyAttributes Attributes { get; set; }

        /// <summary>
        /// Is this key protected by an HSM?
        /// </summary>
        /// <remarks>This attribute is only meaningul at IMPORT requests. In future versions, it may be removed from this structure.</remarks>
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Hsm, Required = Required.Default )]
        public bool? Hsm { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class RestoreKeyRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter( typeof( Base64UrlConverter ) )]
        public byte[] Value { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class UpdateKeyRequestMessage
    {
        /// <summary>
        /// Supported Key Operations
        /// </summary>
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.KeyOps, Required = Required.Default )]
        public string[] KeyOps { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Always )]
        public KeyAttributes Attributes { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class DeleteKeyRequestMessage
    {
        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    #endregion

    #region Key Operation Messages

    [JsonObject]
    public class KeyOpRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Algorithm, Required = Required.Always )]
        public string Alg { get; set; }

        // Data to be encrypted.
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter( typeof( Base64UrlConverter ) )]
        public byte[] Value { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class KeyOpResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Kid, Required = Required.Always )]
        public string Kid { get; set; }

        // Encrypted data.
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter( typeof( Base64UrlConverter ) )]
        public byte[] Value { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class VerifyRequestMessage : KeyOpRequestMessage
    {
        // Digest to be verified, in Base64URL.
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Digest, Required = Required.Always )]
        [JsonConverter( typeof( Base64UrlConverter ) )]
        public byte[] Digest;
    }

    [JsonObject]
    public class VerifyResponseMessage
    {
        // true if signature was verified, false otherwise.
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        public bool Value;

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    #endregion

    [JsonObject]
    public class SecretRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter(typeof(SecureStringConverter))]
        public SecureString Value { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }

    [JsonObject]
    public class SecretResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter(typeof(SecureStringConverter))]
        public SecureString Value { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Id, Required = Required.Default )]
        public string Id { get; set; }

        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }
}