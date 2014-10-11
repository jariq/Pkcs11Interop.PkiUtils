/*
 *  Pkcs11Interop.PkiUtils - PKI extensions for Pkcs11Interop library
 *  Copyright (c) 2013-2014 JWC s.r.o. <http://www.jwc.sk>
 *  Author: Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  Licensing for open source projects:
 *  Pkcs11Interop.PkiUtils is available under the terms of the GNU Affero General 
 *  Public License version 3 as published by the Free Software Foundation.
 *  Please see <http://www.gnu.org/licenses/agpl-3.0.html> for more details.
 *
 *  Licensing for other types of projects:
 *  Pkcs11Interop.PkiUtils is available under the terms of flexible commercial license.
 *  Please contact JWC s.r.o. at <info@pkcs11interop.net> for more details.
 */

using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Net.Pkcs11Interop.PkiUtils
{
    /// <summary>
    /// Certificate request utilities
    /// </summary>
    public static class CertificateRequest
    {
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
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
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
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, privKeyAttributes[0].GetValueAsString()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TRUSTED, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ID, privKeyAttributes[1].GetValueAsByteArray()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SERIAL_NUMBER, x509Certificate.SerialNumber.ToByteArrayUnsigned()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, x509Certificate.GetEncoded()));

            // Create certificate object
            return session.CreateObject(certificateAttributes);
        }

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
            if (CKK.CKK_RSA != (CKK)publicKeyAttributes[0].GetValueAsUlong())
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
