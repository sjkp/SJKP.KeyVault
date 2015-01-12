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
using System.Security;
using System;

namespace Microsoft.KeyVault.Client
{
    /// <summary>
    /// A Secret consisting of a value and id.
    /// </summary>
    [DataContract()]
    public class Secret
    {
        internal const string Property_Value = "value";
        internal const string Property_Id = "id";

        /// <summary>
        /// The secret value 
        /// </summary>
        public SecureString SecureValue { get; set; }

        /// <summary>
        /// The secret value in plain text 
        /// </summary>
        [DataMember(Name = Property_Value, IsRequired = false)]
        public string Value
        {
            get
            {
                return SecureValue.ConvertToString();
            }
            set
            {
                SecureValue = value.ConvertToSecureString();
            }
        }

        /// <summary>
        /// The secret id
        /// </summary>
        [DataMember(Name = Property_Id, IsRequired = false, EmitDefaultValue = false)]
        public string Id { get; set; }

        /// <summary>
        /// Default constructor
        /// </summary>
        public Secret()
        {
        }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
