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

using System.Runtime.Serialization;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace Microsoft.KeyVault.Client
{
    /// <summary>
    /// The attributes of a key managed by the KeyVault service
    /// </summary>
    [JsonObject]
    public class KeyAttributes
    {
        /// <summary>
        /// Determines whether the key is enabled
        /// </summary>
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "enabled", Required = Required.Default )]
        public bool? Enabled { get; set; }

        /// <summary>
        /// Expiry date as the number of seconds since the Unix Epoch (1/1/1970)
        /// </summary>
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "exp", Required = Required.Default )]
        public int? Expires { get; set; }

        /// <summary>
        /// NotBefore date as the number of seconds since the Unix Epoch (1/1/1970)
        /// </summary>
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "nbf", Required = Required.Default )]
        public int? NotBefore { get; set; }

        /// <summary>
        /// Additional data 
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo  { get; set; }

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <remarks>
        /// The defauts for the properties are:
        /// Enabled   = null
        /// NotBefore = null
        /// Expires   = null
        /// Hsm       = null
        /// </remarks>
        public KeyAttributes()
        {
            Enabled   = null;
            NotBefore = null;
            Expires   = null;
        }

        public override string ToString()
        {
            return JsonConvert.SerializeObject( this );
        }
    }
}
