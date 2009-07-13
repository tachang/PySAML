import sys, os, time
import unittest

# In order to import PySAML without installing it I need to modify the sys.path variable
sys.path.append(os.path.normpath("../"))

import SAML
import SAMLMessages

# This class tests the SAML Subject class
class subjectTests(unittest.TestCase):

  def testSubjectCreatedWithCorrectAttributes(self):
    subject = SAML.Subject("JohnDoe@example.com","urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

    self.assertEqual(subject.name,"JohnDoe@example.com")
    self.assertEqual(subject.nameidformat,"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

  # Should still be able to set the nameid-format even if it is not a standard format
  def testAcceptsAnyNameIDFormat(self):
    subject = SAML.Subject("JohnDoe@example.com","InvalidNameIDFormatEMail")
    self.assertEqual(subject.nameidformat,"InvalidNameIDFormatEMail")

  # Test setting multiple confirmation methods
  def testInternallySetsConfirmationMethods(self):
    confirmationMethods = ["urn:oasis:names:tc:SAML:1.0:cm:bearer"]
    subject = SAML.Subject("JohnDoe@example.com",
                           "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                           confirmationMethods)
    self.assertEqual(confirmationMethods, subject.confirmationMethods)

    xml = subject.getXML()
    self.assertEqual(xml.count("urn:oasis:names:tc:SAML:1.0:cm:bearer"),1,"Expecting to see one instance of bearer string")

    subject.confirmationMethods = []
    xml = subject.getXML()
    self.assertEqual(xml.count("urn:oasis:names:tc:SAML:1.0:cm:bearer"),0,"There should be no bearer string since it has been set to None")

  def testCreateAssertion(self):

    # The subject of the assertion. Usually an e-mail address or username.
    subject = SAML.Subject("JohnDoe@example.com","urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

    # The authentication statement which is how the person is proving he really is that person. Usually a password.
    authStatement = SAML.AuthenticationStatement(subject,"urn:oasis:names:tc:SAML:1.0:am:password",None)

    # Create a conditions timeframe of 60 minutes (period in which assertion is valid)
    notBefore = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
    notOnOrAfter = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time() + 60))
    conditions = SAML.Conditions(notBefore, notOnOrAfter)

    # Create the actual assertion
    assertion = SAML.Assertion(authStatement, "PySAML Issuer", conditions)

    # Put the assertion into a signed SAML response

    privateKeyFile = open("JeffreyTchangPrivateKey.pem","r")
    privatekey = privateKeyFile.read()

    certificateFile = open("JeffreyTchangPublicCertificate.pem","r")
    certificate = certificateFile.read()

    response = SAML.Response(assertion, privatekey, certificate)

    print response

"""
  def test_prettyXML(self):
    subject = SAML.Subject("JohnDoe@example.com","urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    self.assertEqual( subject.__str__(),subject.prettyXML())

    xml = subject.prettyXML()
    self.assertEqual(xml.count("urn:oasis:names:tc:SAML:1.0:cm:bearer"),0,"No bearer string should be present since default is None")

    print subject.prettyXML()

class SAMLTests(unittest.TestCase):

  def test_CreateAssertion(self):

    # Who am I making this assertion about
    subject = SAML.Subject("scarter","urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified")

    # Create an assertion
    simpleAssertion = SAML.Assertion("ExampleIssuer", subject)

    simpleAssertion.sign(privateKey="PrivateKey.pem")

    # Suppose I changed something about the assertion now.

    print simpleAssertion

"""

if __name__ == '__main__':
  suite = unittest.TestLoader().loadTestsFromTestCase(subjectTests)
  unittest.TextTestRunner().run(suite)
