
# Import the PySAML library
import SAML
import time, logging

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

# Print the assertion
print assertion

