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
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;

namespace Net.Pkcs11Interop.PkiUtils
{
	/// <summary>
	/// Certificate request utilities
	/// </summary>
	public static class CertificateRequest
	{
		/// <summary>
		/// Generates certificate request in PKCS#10 format defined by RFC 2986
		/// </summary>
		/// <param name="session">Session with user logged in</param>
		/// <param name="publicKeyHandle">Handle of public key that should be contained in generated request</param>
		/// <param name="privateKeyHandle">Handle of private key that should be used for the creation of request signature</param>
		/// <param name="subjectDistinguishedName">Subject entity's distinguished name</param>
		/// <param name="hashAlgorithm">Hash algorihtm used for the creation of request signature</param>
		/// <returns>Certificate request in PKCS#10 format</returns>
		public static byte[] GeneratePkcs10(Session session, ObjectHandle publicKeyHandle, ObjectHandle privateKeyHandle, string subjectDistinguishedName, HashAlgorithm hashAlgorithm)
		{
			List<CKA> pubKeyAttrsToRead = new List<CKA>();
			pubKeyAttrsToRead.Add(CKA.CKA_KEY_TYPE);
			pubKeyAttrsToRead.Add(CKA.CKA_MODULUS);
			pubKeyAttrsToRead.Add(CKA.CKA_PUBLIC_EXPONENT);

			// Read public key attributes
			List<ObjectAttribute> publicKeyAttributes = session.GetAttributeValue(publicKeyHandle, pubKeyAttrsToRead);
			if ((uint)CKK.CKK_RSA != publicKeyAttributes[0].GetValueAsUint())
				throw new NotSupportedException("Currently only RSA keys are supported");

			// Create instance of RsaKeyParameters class usable for BouncyCastle
			BigInteger modulus = new BigInteger(1, publicKeyAttributes[1].GetValueAsByteArray());
			BigInteger publicExponent = new BigInteger(1, publicKeyAttributes[2].GetValueAsByteArray());
			RsaKeyParameters publicKeyParameters = new RsaKeyParameters(false, modulus, publicExponent);

			// Determine algorithms
			Mechanism mechanism = null;
			string signatureAlgorihtm = null;
			switch (hashAlgorithm)
			{
				case HashAlgorithm.SHA1:
					mechanism = new Mechanism(CKM.CKM_SHA1_RSA_PKCS);
					signatureAlgorihtm = PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id;
					break;
				case HashAlgorithm.SHA256:
					mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);
					signatureAlgorihtm = PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id;
					break;
				case HashAlgorithm.SHA384:
					mechanism = new Mechanism(CKM.CKM_SHA384_RSA_PKCS);
					signatureAlgorihtm = PkcsObjectIdentifiers.Sha384WithRsaEncryption.Id;
					break;
				case HashAlgorithm.SHA512:
					mechanism = new Mechanism(CKM.CKM_SHA512_RSA_PKCS);
					signatureAlgorihtm = PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id;
					break;
			}

			// Generate and sign PKCS#10 request
			Pkcs10CertificationRequestDelaySigned pkcs10 = new Pkcs10CertificationRequestDelaySigned(signatureAlgorihtm, new X509Name(subjectDistinguishedName), publicKeyParameters, null);
			byte[] signature = session.Sign(mechanism, privateKeyHandle, pkcs10.GetDataToSign());
			pkcs10.SignRequest(new DerBitString(signature));

			return pkcs10.GetDerEncoded();
		}
	}
}
