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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace Net.Pkcs11Interop.PkiUtils
{
    /// <summary>
    /// Utilities for object importing
    /// </summary>/summary>
	public static class ObjectImporter
	{
        /// <summary>
        /// Imports the certificate into the PKCS#11 compatible device and pairs it with the corresponding private key
        /// </summary>
        /// <param name="session">Session with user logged in</param>
        /// <param name="certificate">Certificate that should be imported</param>
        /// <returns>Handle of created certificate object</returns>
		public static ObjectHandle ImportCertificate(Session session, byte[] certificate)
        {
            // Parse certificate
            X509CertificateParser x509CertificateParser = new X509CertificateParser();
            X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(certificate);

            // Get public key from certificate
            AsymmetricKeyParameter pubKeyParams = x509Certificate.GetPublicKey();
            if (!(pubKeyParams is RsaKeyParameters))
                throw new NotSupportedException("Currently only RSA keys are supported");
            RsaKeyParameters rsaPubKeyParams = (RsaKeyParameters)pubKeyParams;

            // Find corresponding private key
            List<ObjectAttribute> privKeySearchTemplate = new List<ObjectAttribute>();
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, (uint)CKO.CKO_PRIVATE_KEY));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)CKK.CKK_RSA));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_MODULUS, rsaPubKeyParams.Modulus.ToByteArrayUnsigned()));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, rsaPubKeyParams.Exponent.ToByteArrayUnsigned()));

            List<ObjectHandle> foundObjects = session.FindAllObjects(privKeySearchTemplate);
            if (foundObjects.Count != 1)
                throw new ObjectNotFoundException("Corresponding RSA private key not found");

            ObjectHandle privKeyObjectHandle = foundObjects[0];

            // Read CKA_LABEL and CKA_ID attributes of private key
            List<CKA> privKeyAttrsToRead = new List<CKA>();
            privKeyAttrsToRead.Add(CKA.CKA_LABEL);
            privKeyAttrsToRead.Add(CKA.CKA_ID);

            List<ObjectAttribute> privKeyAttributes = session.GetAttributeValue(privKeyObjectHandle, privKeyAttrsToRead);

            // Define attributes of new certificate object
            List<ObjectAttribute> certificateAttributes = new List<ObjectAttribute>();
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, (uint)CKO.CKO_CERTIFICATE));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, privKeyAttributes[0].GetValueAsString()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, (uint)CKC.CKC_X_509));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TRUSTED, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ID, privKeyAttributes[1].GetValueAsByteArray()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SERIAL_NUMBER, x509Certificate.SerialNumber.ToByteArrayUnsigned()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, x509Certificate.GetEncoded()));

            // Create certificate object
            return session.CreateObject(certificateAttributes);
        }
	}
}
