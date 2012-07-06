<?php
 
function backMaketemp ($s) {
	$t = `mktemp` ;
	## echo "(inside) $s = $t" ;
	$t = substr($t,0,-1) ;
	## remember filename, so can erase on exit 
	$temp_file_names[] = $t ;
	return $t ;
}

function backDoXSLT ($u) {
	global $style_sheet_file ;
	global $style_sheet ;
	$ret = file_put_contents ($style_sheet_file , $style_sheet ) ;
	$k = `xsltproc $style_sheet_file $u ` ;
	return $k ;
}

$FALSE = 0 ;
$TRUE = 1;

$SIMPLE_MODE = $TRUE ; 	// TRUE means do NOT directly contact back
$SIMPLE_MODE = $FALSE ; // do invoke the backend processor

$style_sheet_file = backMaketemp ("style sheet file") ;

$IDP = "stc-test16.cis.brown.edu" ;
$HOST = "stc-test6.cis.brown.edu" ;
$ASSERTION_URL = "https://$HOST/Shibboleth.sso/GetAssertion" ;
## print "ASSERTION_URL = $ASSERTION_URL \n" ;

## echo "\n\nThe SERVER hash:\n\n" ;

## print_r_html($_SERVER) ;

	if ( $SIMPLE_MODE ) {	// just producing output, to be used from command line

		if ( isset ($_SERVER['Shib-Assertion-Count'] ) ) {
			print "Assertion count =  {$_SERVER['Shib-Assertion-Count']} \n" ;
		} else {
			print "No Assertions available\n" ;
		}

		$string = $_SERVER['Shib-Assertion-01'] ;
		$ASSERTION_URL = escapeshellcmd ( $string ) ;

		$assertion_file = backMaketemp( "assertion_file" ) ;

		## stc added --insecure
		# request the target from the SP and include headers signalling ECP
		## $sp_resp = `curl --silent --insecure -c $cookie_file -b $cookie_file -H "$header_accept" -H "$header_paos" "$TARGET"` ;

		$curl_command = "curl --silent --insecure -o $assertion_file  $ASSERTION_URL" ;

		echo "curl_command = $curl_command \n" ;
		$sp_resp = passthru ( "$curl_command", $ret ) ;
		## output of curl command is stored in $ecp_response_file

		if ( $ret ) {
			echo  "error from first curl - $ret\n" ;
		}

		if (file_exists($assertion_file))   {  
			$file = fopen("$assertion_file", "r");  
 			while (!feof($file))   {  
  				$display = fgets($file, filesize("$assertion_file"));  
				##  echo $display . "  ";  
 			}  
 			fclose($file);  
		}   
		else   
		{  
			echo "Error occured ! ! ! Try again or report it to us";  
		} 

		$style_sheet = '<xsl:stylesheet version="1.0"
 			xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 			xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
 			xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" 
 			xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" >

 			<xsl:output omit-xml-declaration="yes"/>

 				<xsl:template match="/">
				<xsl:copy-of select="//saml2:Issuer" />
 				</xsl:template>

			</xsl:stylesheet> ' ;

		## $relay_state = `xsltproc $stylesheet_get_relay_state $ecp_response_file` ;
		$idp = backDoXSLT( $assertion_file) ;
		echo "idp = \n $idp \n" ;
	} else { 		// actually contact the backend server 
	
		include 'contactBackendService.php' ;
		
		## invoke a function in that module 
		$ret = contactBackendService("WEB") ;

		echo "ret = $ret\n" ;
	}
	
exit;

 ?>
