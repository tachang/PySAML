import xml.dom.minidom

class SAMLMessages():

  def getSubjectXML(self, subject):  

    doc = xml.dom.minidom.Document()
    subjectElement = doc.createElement("Subject")
    
    # <NameIdentifier>
    nameIDElement = doc.createElement("NameIdentifier")
    nameIDElement.setAttribute("Format",subject.nameidformat)
    nameIDText = doc.createTextNode(subject.name)
    nameIDElement.appendChild(nameIDText)
    
    subjectConfirmationElement = doc.createElement("SubjectConfirmation")
    
    # Go through the list of confirmation methods
    for confirmationMethod in subject.confirmationMethods:
      confirmationMethodElement = doc.createElement("ConfirmationMethod")
      confirmationMethod = doc.createTextNode(confirmationMethod)
      confirmationMethodElement.appendChild(confirmationMethod)
      subjectConfirmationElement.appendChild(confirmationMethodElement)
  
    subjectElement.appendChild(nameIDElement)
    subjectElement.appendChild(subjectConfirmationElement)
  
    return subjectElement.toxml()

    
  def getAuthenticationStatementXML(self, authStatement):
    doc = xml.dom.minidom.Document()  
    authenticationStatementElement = doc.createElement("AuthenticationStatement")
    authenticationStatementElement.setAttribute("AuthenticationMethod", authStatement.authMethod)
    authenticationStatementElement.setAttribute("AuthenticationInstant", authStatement.authInstant)   

    # Turn the subject object into an XML node
    subject = xml.dom.minidom.parseString(authStatement.subject.getXML())    
    authenticationStatementElement.appendChild(subject)
    
    return authenticationStatementElement.toxml()
    

