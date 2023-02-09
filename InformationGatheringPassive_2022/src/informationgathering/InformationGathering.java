package informationgathering;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.*;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.util.*;
import java.util.Objects;
import burp.api.montoya.http.message.requests.*;
import burp.api.montoya.http.message.MarkedHttpRequestResponse;
import burp.api.montoya.http.message.responses.*;
import burp.api.montoya.http.message.headers.*;
import burp.api.montoya.sitemap.*;
import burp.api.montoya.http.message.*;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;

//Burp will auto-detect and load any class that extends BurpExtension.
public class InformationGathering implements BurpExtension
{
	
    @Override
    public void initialize(MontoyaApi api)
    {
    	// set extension name
        api.extension().setName("Information Gathering");

        Logging logging = api.logging();
        Proxy p = api.proxy();
        SiteMap site = api.siteMap();
        
        // write a message to our output stream
        logging.logToOutput("Running...");
        
        List<ProxyRequestResponse> proxyReqResp = p.history();
        List<HttpRequestResponse> sitemapReqResp = site.requestResponses();
        
        analyse(logging, proxyReqResp, sitemapReqResp, site);
    }
    
    public void analyse(Logging logging, List<ProxyRequestResponse> proxyReqResp, List<HttpRequestResponse> sitemapReqResp, SiteMap site) {
    	UrlsMap fingerprintDict = new UrlsMap();
    	UrlsMap securityDict = new UrlsMap();
    	UrlsMap missingSecDict = new UrlsMap();

    	for(ProxyRequestResponse r : proxyReqResp) {
    		HttpRequest request = r.finalRequest();
    		HttpResponse response = r.originalResponse();
    		    		
    		if(!Objects.isNull(response)) { 
    			List<HttpHeader> headers = response.headers();
    	    	List<String> foundSecHeaders = new ArrayList<String>();
    	    	MarkedHttpRequestResponse x = MarkedHttpRequestResponse.markedRequestResponse(request, response, Annotations.annotations(HighlightColor.BLUE));
    	    	
	    		for(HttpHeader h : headers) {
	    			String name = h.name();
	    			String value = h.value();
	    			
	    			if(UsefulInfo.FINGERPRINTING_HEADERS.contains(name.toLowerCase())) {
	    				fingerprintDict.insert(request.url(), x, name.toLowerCase(), value);
	    			}
	    			
	    			if(UsefulInfo.SECURITY_HEADERS.contains(name.toLowerCase())) {
	    				securityDict.insert(request.url(), x, name.toLowerCase(), value);
	    				foundSecHeaders.add(name.toLowerCase());
	    			}
	    		}
	    		
	    		for(String h : UsefulInfo.SECURITY_HEADERS) {
	    			if(!(foundSecHeaders.contains(h))) {
	    				missingSecDict.insert(request.url(), x, h, "");
	    			}
	    		}
    		}
    	}
    	
    	for(HttpRequestResponse r : sitemapReqResp) {
    		HttpRequest request = r.httpRequest();
    		HttpResponse response = r.httpResponse();
    		    		
    		if(!Objects.isNull(response)) { 
    			List<HttpHeader> headers = response.headers();    			
    			List<String> foundSecHeaders = new ArrayList<String>();
    			MarkedHttpRequestResponse x = MarkedHttpRequestResponse.markedRequestResponse(request, response, Annotations.annotations(HighlightColor.BLUE));
    	    	
    			for(HttpHeader h : headers) {
	    			String name = h.name();
	    			String value = h.value();
	    			
	    			if(UsefulInfo.FINGERPRINTING_HEADERS.contains(name.toLowerCase())) {
	    				fingerprintDict.insert(request.url(), x, name.toLowerCase(), value);
	    			}

	    			if(UsefulInfo.SECURITY_HEADERS.contains(name.toLowerCase())) {
	    				securityDict.insert(request.url(), x, name.toLowerCase(), value);
	    				foundSecHeaders.add(name.toLowerCase());
	    				//logging.logToOutput(request.url()+": "+name+'\n');
	    			}
	    		}
    			
    			for(String h : UsefulInfo.SECURITY_HEADERS) {
	    			if(!(foundSecHeaders.contains(h))) {
	    				missingSecDict.insert(request.url(), x, h, "");
	    			}
	    		}
    		}
    	}
    	
    	fingerprintDict.audit(logging, 
    						  site, 
    						  "Information dislosure via HTTP headers", 
    						  "If possible, remove direct references to adopted technologies", 
    						  AuditIssueSeverity.LOW,
    						  AuditIssueConfidence.CERTAIN,
    						  "Misconfiguration of the server",
    						  "If possible, remove direct references to adopted technologies");
    	
    	securityDict.audit(logging, 
    					   site, 
 						   "Implemented HTTP Security headers", 
 						   "CHECK ITS VALUE", 
 						   AuditIssueSeverity.INFORMATION,
 						   AuditIssueConfidence.CERTAIN,
 						   "CHECK ITS VALUE", 
 						   "CHECK ITS VALUE");
    	
    	missingSecDict.auditMissing(logging, 
				   				  site, 
				   				  "Missing HTTP Security headers", 
				   				  "Configure Web Server to reply with HTTP Security Headers", 
				   				  AuditIssueSeverity.MEDIUM,
				   				  AuditIssueConfidence.CERTAIN,
				   				  "Misconfiguration of the server",
				   				  "Configure Web Server to reply with HTTP Security Headers");
    }
}