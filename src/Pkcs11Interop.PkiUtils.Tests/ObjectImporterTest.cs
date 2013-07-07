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
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

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
    }
}

