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

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using NUnit.Framework;

namespace Net.Pkcs11Interop.PkiUtils.Tests
{
    /// <summary>
    /// Tests for Net.Pkcs11Interop.PkiUtils.ObjectImporter class
    /// </summary>
    [TestFixture()]
    public class ObjectImporterTest
    {
        /// <summary>
        /// Certificate import test
        /// </summary>
        [Test()]
        public void ImportCertificateTest()
        {
            byte[] certificate = System.IO.File.ReadAllBytes(@"c:\Pkcs11Interop.PkiUtils.Tests\certificate.cer");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Find usable slot
                Slot slot = Helpers.FindSlot(pkcs11, Settings.TokenSerial, Settings.TokenLabel);
                Assert.IsNotNull(slot);

                // Open RW session
                using (Session session = slot.OpenSession(false))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Import certificate
                    ObjectHandle certObjectHandle = ObjectImporter.ImportCertificate(session, certificate);

                    // Do something interesting with certificate

                    // Destroy certificate
                    session.DestroyObject(certObjectHandle);

                    session.Logout();
                }
            }
        }

        /// <summary>
        /// Trusted certificate import test
        /// </summary>
        [Test()]
        public void ImportTrustedCertificateTest()
        {
            byte[] certificate = System.IO.File.ReadAllBytes(@"c:\Pkcs11Interop.PkiUtils.Tests\CA.cer");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Find usable slot
                Slot slot = Helpers.FindSlot(pkcs11, Settings.TokenSerial, Settings.TokenLabel);
                Assert.IsNotNull(slot);

                // Open RW session
                using (Session session = slot.OpenSession(false))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Import trusted certificate
                    ObjectHandle certObjectHandle = ObjectImporter.ImportTrustedCertificate(session, certificate);

                    // Do something interesting with trusted certificate

                    // Destroy certificate
                    session.DestroyObject(certObjectHandle);

                    session.Logout();
                }
            }
        }
    }
}

