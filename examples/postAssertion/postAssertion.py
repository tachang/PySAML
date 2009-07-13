# Import the PySAML library
import SAML

# Native modules
import time
import logging
import os
import sys
import StringIO
import base64
import urllib
import urllib2


# Enable SAML logging if needed for debugging
# SAML.log(logging.DEBUG, "PySAML.log")

# The subject of the assertion. Usually an e-mail address or username.
subject = SAML.Subject("JohnDoe@example.com","urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

# The authentication statement which is how the person is proving he really is that person. Usually a password.
authStatement = SAML.AuthenticationStatement(subject,"urn:oasis:names:tc:SAML:1.0:am:password",None)

# Create a conditions timeframe of 5 minutes (period in which assertion is valid)
notBefore = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
notOnOrAfter = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time() + 5))
conditions = SAML.Conditions(notBefore, notOnOrAfter)

# Create the actual assertion
assertion = SAML.Assertion(authStatement, "PySAML Issuer", conditions)


# At this point I have an assertion. To sign the assertion I need to put it into a SAML response
# object. I need to specify a private key to sign. In addition I should include a certificate
# that binds the corresponding public key to a name.

# Open up my private key file
privateKeyFile = open("../sharedfiles/JohnDoePrivateKey.pem","r")
privatekey = privateKeyFile.read()

# Open up the certificate
certificateFile = open("../sharedfiles/JohnDoeCertificate.pem","r")
certificate = certificateFile.read()

# Sign with the private key but also include the certificate in the SAML response    
response = SAML.Response(assertion, privatekey, certificate)








 
values = {"TARGET" : "http://www.example.com/secure/",
        "SAMLResponse" : base64.b64encode(response.getXML())}


proxy_url = 'http://localhost:8888'
proxy_support = urllib2.ProxyHandler({'http': proxy_url})
opener = urllib2.build_opener(proxy_support, urllib2.HTTPHandler)
urllib2.install_opener(opener)


        
data = urllib.urlencode(values)
req = urllib2.Request("http://www.sp.demo/affwebservices/public/samlcc", data)

print urllib2.urlopen(req).read()

