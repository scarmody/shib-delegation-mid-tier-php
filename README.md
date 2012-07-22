shib-delegation-mid-tier-php
============================

This is a php implementation of the mid-tier described in https://spaces.internet2.edu/display/ShibuPortal/Solution+Proposal 

1. installed the delegation extension into your IDP?

http://svn.shibboleth.net/view/extensions/java-idp-delegation/?sortdir=down

It adds an additional element to the original SAML assertion (a url value at the issuing IDP that can be contacted to obtain a delegated assertion); $epr value (ie that url) is extracted from the original assertion by the code... 

2. Configure the SP at the mid tier (see notes at top of shibboleth2.xml)

3. COnfigure security at backend (tellShib to accept delegated assertion)