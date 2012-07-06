<?php

## https://spaces.internet2.edu/display/ShibuPortal/Solution+Proposal
## this code assumes that it is protected by Shibboleth
##
## This code executes all of the steps described in section 2 of the Solution Proposal
##

## To-DOs
##
## 1.	erase TMP files on exit
##
## 2. use of --insecure by curl
##
## 3. what to do when curl errors occur
## 
## 4. label various curl commands in trace output
##
## 5. find places that exit
##
## 6. clean up namespace references in style sheets

 function print_r_html ($arr) {
        ?><pre><?
        print_r($arr);
        ?></pre><?
}

function maketemp ($s) {
	global $temp_file_names ;
	$t = `mktemp` ;
	##  output ("(inside) $s = $t") ;
	$t = substr($t,0,-1) ;
	## remember filename, so can erase on exit 
	$temp_file_names[] = $t ;
	return $t ;
}

function doXSLT ($u) {
	global $style_sheet_file ;
	global $style_sheet ;
	$ret = file_put_contents ($style_sheet_file , $style_sheet ) ;
	$k = `xsltproc $style_sheet_file $u ` ;
	return $k ;
}

function output ($string, $type ) {
	global $MODE ;
	## echo "(inside-output) MODE = $MODE\n" ;
	if ( $MODE == "CONSOLE" ) {
		echo "$string \n" ;
	} else {		// otherwise, console mode
		$num = func_num_args ( ) ;
		if ( $num == 1 ) {
			echo "$string <BR> " ;
		} else {
			if ( $type == "XML" ) {
				## echo "<br>got XML string<BR>" ;
				## mixed str_replace ( mixed $search , mixed $replace , mixed $subject 
				$temp = $string ;
				$string = str_replace ( "<", "&lt;", $temp ) ;
				$temp = $string ;
				$string = str_replace ( ">", "&gt;", $temp ) ;
				echo "$string <P> " ;
			} else {
				echo "$string <BR> " ;
			}
		}
	}
}

function contactBackendService ($dummy) {

	global $MODE ;		// either CONSOLE or WEB -- controls how outputing is done, and how 
						// context assertionis obtained
	global $style_sheet_file ;
	global $style_sheet ;
	global $temp_file_names ;

$MODE = $dummy;
## echo "MODE = $MODE\n" ;

$FALSE = 0 ;
$TRUE = 1;

$DEBUG = $TRUE ;	// TRUE = running on the command line
$DEBUG = $FALSE ;	// running on the web
$TRACE = $FALSE ;	
$TRACE = $TRUE;		// run in verbose mode, dumping out a lot of info

	if ( $TRACE ) {
		$curl_mode = " --verbose " ;
	} else {
		$curl_mode = " --silent " ;
	}

$TARGET = "http://stc-test3.cis.brown.edu/secure/info.php" ;	// target url for the backend service
$SENDER = "https://stc-test6.cis.brown.edu/shibboleth" ;		// providerID of the mmid-tier portal

# headers needed for ECP
$header_accept = "Accept:text/html; application/vnd.paos+xml" ;
$header_paos = "PAOS:ver=\"urn:liberty:paos:2003-08\";\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"" ;
$header_post_soap = 'Content-Type: application/vnd.paos+xml' ;
$header_soap_accept = "Accept:text/html" ;

$cookie_file = maketemp ("cookie file" ) ;

$style_sheet_file = maketemp ("style sheet file") ;

	## step 2.1 -- Portlet Issues HTTP Request to Web Service Provider
	##
	## 2.2. Web Service Provider issues <samlp:AuthnRequest> to Identity Provider via Portlet
	## (reponse from backend service is in $ecp_response_file )

	## this file will hold the response from the SP
	$ecp_response_file = maketemp( "ecp_response_file" ) ;

	# issue a request to the target and include headers signalling ECP
	$curl_command = "curl " . $curl_mode . " --insecure -o $ecp_response_file -c $cookie_file -b $cookie_file -H \"$header_accept\" -H \"$header_paos\" $TARGET" ;
	if ( $TRACE ) {
		output ("curl_command = $curl_command") ;
	}
	$sp_resp = passthru ( "$curl_command", $ret ) ;
	## output of curl command is stored in $ecp_response_file

	if ( $ret ) {
		output  ("error from first curl to backend service") ;
	}
	
	if ( $TRACE ) {
		output ("ecp_response_file contents:") ;
    	$tmp =  file_get_contents($ecp_response_file) ;
    	output ($tmp, "XML") ;
	}
	
	# parse the SP response using xsltproc 
	# and a stylesheet to remove the SOAP header
	# but leave everything else

	## use xsltproc to remove the SOAP header from the SP response
	$style_sheet = '<xsl:stylesheet version="1.0"
 		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 		xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
                xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" 
                xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" >

 		<xsl:output omit-xml-declaration="yes"/>

            <xsl:template match="/">
                <xsl:copy-of select="//samlp:AuthnRequest" />
            </xsl:template>

    	<xsl:template match="S:Envelope" />

	</xsl:stylesheet> ' ;

	$idp_request = doXSLT( $ecp_response_file) ;
	
	if ( $TRACE ) {
		output ("idp_request = $idp_request", "XML") ;
	}
	
	if ( strlen($idp_request) == 0 ) {
		output ("ERROR -- did not find idp_response in XML form the SP");
	}

	# pick out the relay state element from the SP response
	# so that it can later be included in the package to the SP
	$style_sheet = '<xsl:stylesheet version="1.0"
 		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 		xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 		xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" >

 		<xsl:output omit-xml-declaration="yes"/>

 		<xsl:template match="/">
     		<xsl:copy-of select="//ecp:RelayState" />
 		</xsl:template>

		</xsl:stylesheet> ' ;

	$relay_state = doXSLT( $ecp_response_file) ;
	
	if ( $TRACE ) {
		output ("relay_state = $relay_state", "XML" ) ;
	}

	# pick out the responseConsumerURL attribute value from the SP response
	# so that it can later be compared to the assertionConsumerURL sent from
	# the IdP
	$style_sheet = '<xsl:stylesheet version="1.0"
 		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 		xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 		xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
 		xmlns:paos="urn:liberty:paos:2003-08" >

 		<xsl:output omit-xml-declaration="yes"/>

 			<xsl:template match="/">
     			<xsl:value-of select="/S:Envelope/S:Header/paos:Request/@responseConsumerURL" />
 			</xsl:template>

		</xsl:stylesheet> ' ;

	$responseConsumerURL = doXSLT( $ecp_response_file) ;
	if ( $TRACE ) {
		output ("responseConsumerURL = $responseConsumerURL" ) ;
	}
	
	## pick out the messageID value, to be returned eventually to the SP
	$style_sheet = '<xsl:stylesheet version="1.0"
 		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 		xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 		xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
 		xmlns:paos="urn:liberty:paos:2003-08" >

 		<xsl:output omit-xml-declaration="yes"/>

 			<xsl:template match="/">
     			<xsl:value-of select="/S:Envelope/S:Header/paos:Request/@messageID" />
 			</xsl:template>

		</xsl:stylesheet> ' ;

	$messageID = doXSLT( $ecp_response_file) ;
	if ( $TRACE ) {
		output ("messageID = $messageID") ;
	}
	
	## 2.3 Portlet Determines Identity Provider and Obtains Credential
	
	## create timestamp
	## do this here since used to validate Assertion obtained from portal
	##
	$datecmnd = "date -u +\"%Y-%m-%dT%TZ\"" ;
	$timestamp =  $idp_response = exec ( "$datecmnd" ) ;
	if ( $TRACE ) {
		output ("timestamp = $timestamp") ;
	}
	
	## obtain the original assertion issued by the IDP
	if ( $DEBUG) {
		## running from the command line; use Assertion obtained elsewhere
		##
		$assertion_file = '/tmp/tmp.CRLRvy8069' ;
	} else {
		## running behind a web server; obtain Assertion from the web server

		## make sure there is an Assertion
		if ( isset ($_SERVER['Shib-Assertion-Count'] ) ) {
			output ("Assertion count =  {$_SERVER['Shib-Assertion-Count']} ") ;
		} else {
			output ("No Assertions available") ;
		}

		## obtain the url to use to obtain the Assertion
		## fix it so we can pass it thru the shell with the curl command
		$string = $_SERVER['Shib-Assertion-01'] ;
		$ASSERTION_URL = escapeshellcmd ( $string ) ;

		$assertion_file = maketemp( "assertion_file" ) ;

 		$curl_command = "curl " . $curl_mode . " --insecure -o $assertion_file  $ASSERTION_URL" ;
		if ( $TRACE ) {
			output ("curl_command = $curl_command") ;
		}
		$sp_resp = passthru ( "$curl_command", $ret ) ;
		## output of curl command is stored in $assertion_file

		if ( $ret ) {
			echo  "error from curl - trying to obtain delivered credential from local SP - $ret\n" ;
			exit;
		}

		## verify that obtained asserion is still valid
		## <saml2:Conditions NotBefore="2012-06-07T16:25:30.132Z" NotOnOrAfter="2012-06-07T16:30:30.132Z">
		## <saml2:AudienceRestriction>
		## <saml2:Audience>https://stc-test6.cis.brown.edu/shibboleth</saml2:Audience>
		## <saml2:Audience>https://stc-test16.cis.brown.edu/idp/shibboleth</saml2:Audience>
		## </saml2:AudienceRestriction>
		## </saml2:Conditions>
		##
		## timestamp = 2012-06-07T16:41:09Z 

		$style_sheet = '<xsl:stylesheet version="1.0"
 			xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 			xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 			xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
 			xmlns:paos="urn:liberty:paos:2003-08" 
 			xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" >

 			<xsl:output omit-xml-declaration="yes"/>

 				<xsl:template match="/">
     				<xsl:value-of select="/saml2:Assertion/saml2:Subject/saml2:SubjectConfirmation/saml2:SubjectConfirmationData/@NotOnOrAfter" />
 				</xsl:template>

			</xsl:stylesheet> ' ;

		$NotOnOrAfter = doXSLT( $assertion_file) ;
		if ( $TRACE ) {
			output ("NotOnOrAfter = $NotOnOrAfter" ) ;
		}
	

	}

	## the IDP Assertion is in $assertion_file
	##      obtain it, since it will be included in the SOAP request
	##		sent back to the IDP
	$idp_assertion = file_get_contents( $assertion_file ) ;
	if ( $TRACE ) {
		output ("idp_assertion: =") ;
		output ( $idp_assertion, "XML" ) ;
	}

	## determine which IdP will need to be contacted
	## obtain entityID value of the IDP that issued the original Assertion
	$style_sheet = '<xsl:stylesheet version="1.0"
 		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 		xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
	 	xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
 		xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" >

 		<xsl:output omit-xml-declaration="yes"/>

 		<xsl:template match="/">
     		<xsl:value-of select="//saml2:Issuer" />
 		</xsl:template>

		</xsl:stylesheet> ' ;

	$idp = doXSLT( $assertion_file) ;
	if ( $TRACE ) {
		output ("idp = \n $idp") ;
	}

	## (not currently implemented)
	## verifying that the WSP does not preclude the use of that IdP via a SOAP header block in the request in step 2 above.

	## obtain the EPR endpoint of the issuing IDP
	##	(from the original IDP assertion)
	$style_sheet = '<xsl:stylesheet version="1.0"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
		xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
		xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
		xmlns:wsa="http://www.w3.org/2005/08/addressing" >

		<xsl:output omit-xml-declaration="yes"/>

			<xsl:template match="/">
				<xsl:value-of select="//wsa:Address" />
			</xsl:template>

		</xsl:stylesheet> ' ;

	$epr = doXSLT( $assertion_file) ;
	if ( $TRACE ) {
		output ("epr = $epr") ;
	}
	
	## 2.4. Portlet Forwards <samlp:AuthnRequest> to Identity Provider
	
	## begin to build the SOAP msg that will be sent back to the IDP, 
	## 		asking to refresh the original assertion for use with the backend service

	## first, generate the various values we will need to insert into the SOAP msg

	## generate UUID value for msg ID
	$uuid = uniqid('prefix', true) ;
	if ( $TRACE ) {
		output ("uuid = $uuid") ;
	}

	### create the SOAP Request to IDP, inserting variables as appropriate
	$template = '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
   <S:Header xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:sbf="urn:liberty:sb" xmlns:sb="urn:liberty:sb:2006-08"
					xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" 
					xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" >
 
    <!-- ID-WSF defined headers -->
    <sbf:Framework version="2.0"/>
    <sb:Sender providerID="' . $SENDER . '"/>
 
    <!-- WS-Addressing headers with routing information -->
    <wsa:MessageID>uuid:' . $uuid . '</wsa:MessageID>
    <wsa:Action>urn:liberty:ssos:2006-08:AuthnRequest</wsa:Action>
 
    <!-- WS-Security header with timestamp and security token -->
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        S:mustUnderstand="1">
 
      <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <wsu:Created>' . $timestamp . '</wsu:Created>
      </wsu:Timestamp>
 
      <!-- this is the signed assertion issued for authentication of the Portlet -->
      ' . $idp_assertion . '
 
    </wsse:Security>
 
  </S:Header>
 
  <S:Body>' . $idp_request . '</S:Body>
 
	</S:Envelope>' ;

$style_sheet = '<xsl:stylesheet version="1.0"
 xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
    xmlns:sb="urn:liberty:sb:2006-08" 
    xmlns:sbf="urn:liberty:sb" 
    xmlns.saml="urn:oasis:names:tc:SAML:1.0:assertion"
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" >

 <xsl:output omit-xml-declaration="no" encoding="UTF-8"/>

    <xsl:template match="node()|@*">
      <xsl:copy>
         <xsl:apply-templates select="node()|@*"/>
      </xsl:copy>
    </xsl:template>

</xsl:stylesheet> ' ;

	## echo "\ntemplate = $template \n" ;

	if ( $TRACE ) {
		output ("idp_request_file contents: ") ;
    	output ($template, "XML") ;
	}
	
	$idp_request_file = maketemp("idp_request_file" ) ;
	$ret = file_put_contents ($idp_request_file , $template ) ;
	$tmp2 = "@" . $idp_request_file ;
	
	## actually send the SOAP msg to the IDP
	##		read back the response
	## 2.6. Identity Provider Issues <samlp:Response> to Web Service Provider via Portlet
	
	# use curl to POST the request to the IdP the user signalled on the command line
	# and use the login supplied by the user, prompting for a password

	## output of curl command is in $idp_response_file
	$idp_response_file = maketemp("idp_response_file" ) ;
	
	if ( $TRACE ) {
		output ("idp_response_file = $idp_response_file") ;
	}
	
	$tmp = "@" . $idp_response_file ;

	## authenticate to the IDP using the portal's key
	$curl_command = "curl " . $curl_mode . " --insecure --fail --cert /etc/shibboleth/sp-cert.pem --key /etc/shibboleth/sp-key.pem -o $idp_response_file -X POST -c $cookie_file -b $cookie_file --data-binary $tmp2 $epr" ;
	if ( $TRACE ) {
		output ("curl_command (contact IDP)  = $curl_command ") ;
	}
	$idp_response = passthru ( "$curl_command", $ret ) ;

	if ( $TRACE ) {
		output ("idp_response_file contents:") ;
    	$tmp =  file_get_contents($idp_response_file) ;
    	output ($tmp, "XML") ;
	}

	## 2.6 validate received response from IDP
	
	## do some validation of the contents of the response
	
	$style_sheet = '<xsl:stylesheet version="1.0"
 		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 		xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 		xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
 		xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/" >

		<xsl:output omit-xml-declaration="yes"/>

 			<xsl:template match="/">
     			<xsl:value-of select="soap11:Envelope/soap11:Body/soap11:Fault/faultstring" />
 			</xsl:template>

		</xsl:stylesheet> ' ;

	## output ("Scanning for faultstring") ;
	$fault = doXSLT( $idp_response_file) ;
	if ( $TRACE ) {
		output ("faultstring = $fault ") ;
	}
	$x = strlen($fault);
	if ( $TRACE ) {
		output ("length of faultstring = $x");
	}
	if ( strlen($fault) != 1 ) {
		output ("Error from IDP obtaining delegated assertion -- $fault ") ;
		exit;
	}
	
	# use xlstproc to pick out the assertion consumer service URL
	# from the response sent by the IdP
	$style_sheet = '<xsl:stylesheet version="1.0"
 		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 		xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 		xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
 		xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/" >

		<xsl:output omit-xml-declaration="yes"/>

 			<xsl:template match="/">
     			<xsl:value-of select="soap11:Envelope/soap11:Header/ecp:Response/@AssertionConsumerServiceURL" />
 			</xsl:template>

		</xsl:stylesheet> ' ;

	## output ("Scanning for assertionConsumerServiceURL") ;
	$assertionConsumerServiceURL = doXSLT( $idp_response_file) ;
	if ( $TRACE ) {
		output ("assertionConsumerServiceURL = $assertionConsumerServiceURL ");
	}

	# compare the responseConsumerURL from the SP to the 
	# assertionConsumerServiceURL from the IdP and if they
	# are not identical then send a SOAP fault to the SP

	if ( $responseConsumerURL != $assertionConsumerServiceURL ) {

		output ("ERROR: assertionConsumerServiceURL $assertionConsumerServiceURL does not") ;
		output ("match responseConsumerURL $responseConsumerURL") ;
		output  ("  ") ;
		output ("sending SOAP fault to SP") ;
		exit  ;
	}

	## 2.7 Portlet Forwards <samlp:Response> to Web Service Provider
	##
	## first, remove samlp:Response from the IDP response
	
	$style_sheet = '<xsl:stylesheet version="1.0"
 		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 		xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 		xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
 		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
 		xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/" 
 		xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" >

		<xsl:output omit-xml-declaration="yes"/>

 			<xsl:template match="/">
     			<xsl:copy-of select="soap11:Envelope/soap11:Body/saml2p:Response" />
 			</xsl:template>

		</xsl:stylesheet> ' ;

	## output ("Scanning for idp_delegated_response") ;
	$idp_delegated_response = doXSLT( $idp_response_file) ;
	
	if ($TRACE) {
		output ("idp_delegated_response:") ;
		output ( $idp_delegated_response , "XML" ) ;
	}
	
	## construct MSG to the backend service (Web Service Provider)
	
	$sp_response = '<?xml version="1.0" encoding="UTF-8"?>
	<soap11:Envelope  xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"
						xmlns:paos="urn:liberty:paos:2003-08" 
						xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 						xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" >
 
  <soap11:Header>
    <paos:Response 
        soap11:actor="http://schemas.xmlsoap.org/soap/actor/next/" soap11:mustUnderstand="1"/>
 
    <!-- equivalent of the RelayState parameter in a browser-based SSO profile -->
	' . $relay_state . '
 
  </soap11:Header>
 
  <soap11:Body>' . $idp_delegated_response . '
  </soap11:Body>
 
</soap11:Envelope>' ;

	if ($TRACE) {
		output ("sp_response:") ;
		output ( $sp_response , "XML" ) ;
	}
	
	##
	## send the constructed msg to the backend service (Web Service Provider)
	##
	$response_to_sp_file = maketemp("response_to_sp_file") ;
	$ret = file_put_contents ($response_to_sp_file , $sp_response ) ;
	$tmp3 = "@" . $response_to_sp_file ;

	$sp_response_file = maketemp("sp_response_file") ;
	## output ("tmp3 = $tmp3 ") ;
	
	$curl_command = "curl " . $curl_mode . " --insecure -o $sp_response_file -c $cookie_file -b $cookie_file  -X POST -d $tmp3  -H \"$header_post_soap\"  $responseConsumerURL " ;

	if ( $TRACE ) {	
		output ("curl_command = $curl_command ") ;
	}
	
	$sp_resp = passthru ( "$curl_command", $ret ) ;
	## output of curl command is stored in $sp_response_file
	
	if ( $ret ) {
		output  ("error from curl on second visit to SP") ;
	}
	
	if ( $TRACE ) {
		output ("success when forwarding to SP");
	}
	
	if ( $TRACE ) {
		output ("sp_response_file contents: ") ;
    	$tmp =  file_get_contents($sp_response_file) ;
    	output ($tmp, "XML") ;
	}

	## echo ("SP response is in $sp_response_file\n") ;
	
	##
	## now that we presumably  have a Shib session at the backend service ....
	## use curl and the existing established session to get the original target
	## note that the cookies creaated By Shib at the SP are included when contacting the
	## original target
	##
	
	$target_response_file = maketemp("sp_response_file") ;
	$curl_command = "curl " . $curl_mode . " --insecure -o $target_response_file -c $cookie_file -b $cookie_file -X GET $TARGET " ;
	if ( $TRACE ) {
		output ("curl_command = $curl_command ") ;
	}
	$sp_resp = passthru ( "$curl_command", $ret ) ;
	if ( $TRACE ) {
		output ("back from SP; final access to destination") ;
	}

	if ( $ret ) {
		output  ("error from curl with final access to original target at the SP") ;
	}
	
	output ("target_response_file contents: ") ;
    $tmp =  file_get_contents($target_response_file) ;
	output ( $tmp, "XML") ;
	
	return ;

}