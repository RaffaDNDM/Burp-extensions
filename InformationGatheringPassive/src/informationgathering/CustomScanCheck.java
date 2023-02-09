package informationgathering;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.util.List;
import java.util.Objects;
import java.util.ArrayList;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_NEW;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static java.util.Collections.emptyList;

public class CustomScanCheck implements ScanCheck{
    
	private final MontoyaApi api;
	
	public CustomScanCheck(MontoyaApi api)
    {
		this.api = api;
    }
    
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint)
    {
    	return null;
    }
	
    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse)
    {
    	// set extension name
        api.extension().setName("Information Gathering");

        Logging logging = api.logging();
        logging.logToOutput("Running...");
        
        return analyse(logging, baseRequestResponse);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue)
    {
        //Management of duplicated issues
    	if (existingIssue.name().equals(newIssue.name()))
        	return KEEP_EXISTING;
        else
        	return KEEP_NEW;
    }
	
    public AuditResult analyse(Logging logging, HttpRequestResponse baseRequestResponse) {
    	//HTTP request and response from the couple
    	HttpRequest request = baseRequestResponse.request();
    	HttpResponse response = baseRequestResponse.response();
    		    		
    	//If server response is available
    	if(!Objects.isNull(response)) {
	    	UrlsMap fingerprintDict = new UrlsMap(request.url(), baseRequestResponse);
	    	UrlsMap securityDict = new UrlsMap(request.url(), baseRequestResponse);
	    	UrlsMap missingSecDict = new UrlsMap(request.url(), baseRequestResponse);
			
			List<HttpHeader> headers = response.headers();
	    	List<String> foundSecHeaders = new ArrayList<String>();
	    	
    		//Analysis of all headers in HTTP response
	    	for(HttpHeader h : headers) {
    			String name = h.name();
    			String value = h.value();
    			
    			//If response contains HTTP Fingerprint headers
    			if(UsefulInfo.FINGERPRINTING_HEADERS.contains(name.toLowerCase())) {
    				fingerprintDict.insert(name, value);
    			}
    			
    			//If response contains HTTP Security headers
    			if(UsefulInfo.SECURITY_HEADERS.contains(name.toLowerCase())) {
    				securityDict.insert(name, value);
    				foundSecHeaders.add(name.toLowerCase());
    			}    			
    		}
    		
	    	//Missing Security headers
			for(String h : UsefulInfo.SECURITY_HEADERS) {
    			if(!(foundSecHeaders.contains(h))) {
    				//Add HTTP Security header to list of missing ones
    				missingSecDict.insert(h, "");
    			}
    		}
    		
    		//Create issue to be reported
			AuditIssue issue = null;
    		List<AuditIssue> issueList = new ArrayList<AuditIssue>();
    		
    		//Issue for HTTP Fingerprint headers
    		issue = fingerprintDict.audit(logging, 
					  					  "Information dislosure via HTTP headers", 
					  					  "If possible, remove direct references to adopted technologies", 
					  					  AuditIssueSeverity.LOW,
					  					  AuditIssueConfidence.CERTAIN,
					  					  "Misconfiguration of the server",
					  					  "If possible, remove direct references to adopted technologies");

    		//If there is fingerprint header, report it
    		if(!Objects.isNull(issue))
    			issueList.add(issue);
			
    		//Issue for HTTP Security headers
    		issue = securityDict.audit(logging, 
							   "Implemented HTTP Security headers", 
							   "CHECK ITS VALUE", 
							   AuditIssueSeverity.INFORMATION,
							   AuditIssueConfidence.CERTAIN,
							   "CHECK ITS VALUE", 
							   "CHECK ITS VALUE");
			
    		//If there is HTTP Security header, report it
    		if(!Objects.isNull(issue))
    			issueList.add(issue);

    		//Issue for missing HTTP Security headers
    		issue = missingSecDict.auditMissing(logging, 
					   				  "Missing HTTP Security headers", 
					   				  "Configure Web Server to reply with HTTP Security Headers", 
					   				  AuditIssueSeverity.MEDIUM,
					   				  AuditIssueConfidence.CERTAIN,
					   				  "Misconfiguration of the server",
					   				  "Configure Web Server to reply with HTTP Security Headers");
    		
    		//If HTTP Security header are missing, report it
    		if(!Objects.isNull(issue))
    			issueList.add(issue);
    		
    		issueList = issueList.isEmpty() ? emptyList() : issueList;
    		
    		return auditResult(issueList);
		}
		
		//Add list of issues
    	return auditResult(emptyList());
    }

}
