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

using Microsoft.KeyVault.Client.Protocol;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace Microsoft.KeyVault.Client
{
    [JsonObject]
    public class SecretItem
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Id, Required = Required.Always )]
        public string Id { get; set; }        
        
        /// <summary>
        /// Additional data 
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, object> AdditionalInfo { get; set; }
    }
}
