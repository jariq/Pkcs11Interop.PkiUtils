/*
 *  Pkcs11Interop.PkiUtils - PKI extensions for Pkcs11Interop library
 *  Copyright (c) 2013 JWC s.r.o.
 *  Author: Jaroslav Imrich
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License version 3
 *  as published by the Free Software Foundation.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *  
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 *  You can be released from the requirements of the license by purchasing
 *  a commercial license. Buying such a license is mandatory as soon as you
 *  develop commercial activities involving the Pkcs11Interop.PkiUtils software 
 *  without disclosing the source code of your own applications.
 *  
 *  For more information, please contact JWC s.r.o. at info@pkcs11interop.net
 */

using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Net.Pkcs11Interop.PkiUtils.Tests
{
	/// <summary>
	/// Helper methods for Pkcs11Interop.PkiUtils.Tests
	/// </summary>
	public class Helpers 
	{
		/// <summary>
		/// Finds slot containing the token that matches specified criteria
		/// </summary>
		/// <param name="pkcs11">High level PKCS#11 wrapper</param>
		/// <param name="tokenSerial">Serial number of token that should be found</param>
		/// <param name="tokenLabel">Label of token that should be found</param>
		/// <returns>Slot containing the token that matches specified criteria</returns>urns>
		public static Slot FindSlot(Pkcs11 pkcs11, string tokenSerial, string tokenLabel)
		{
			if (string.IsNullOrEmpty(tokenSerial) && string.IsNullOrEmpty(tokenLabel))
				throw new ArgumentException("Token serial and/or label has to be specified");

			List<Slot> slots = pkcs11.GetSlotList(true);
			foreach (Slot slot in slots)
			{
				TokenInfo tokenInfo = slot.GetTokenInfo();

				if (!string.IsNullOrEmpty(tokenSerial))
					if (0 != String.Compare(tokenSerial, tokenInfo.SerialNumber, StringComparison.InvariantCultureIgnoreCase))
						continue;

				if (!string.IsNullOrEmpty(tokenLabel))
					if (0 != String.Compare(tokenLabel, tokenInfo.Label, StringComparison.InvariantCultureIgnoreCase))
						continue;

				return slot;
			}

			return null;
        }

		/// <summary>
		/// Generates asymetric key pair
		/// </summary>
		/// <param name='session'>Read-write session with user logged in</param>
		/// <param name='ckaLabel'>Value of CKA_LABEL attribute for generated keys</param>
		/// <param name='ckaId'>Value of CKA_ID attribute for generated keys</param>
		/// <param name='publicKeyHandle'>Output parameter for public key object handle</param>
		/// <param name='privateKeyHandle'>Output parameter for private key object handle</param>
		public static void GenerateKeyPair(Session session, string ckaLabel, byte[] ckaId, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle)
		{
			// Prepare attribute template of new public key
			List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>();
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaLabel));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS_BITS, 1024));
			publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

			// Prepare attribute template of new private key
			List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>();
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaLabel));
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN_RECOVER, true));
			privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));

			// Specify key generation mechanism
			Mechanism mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

			// Generate key pair
			session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
        }
    }
}
