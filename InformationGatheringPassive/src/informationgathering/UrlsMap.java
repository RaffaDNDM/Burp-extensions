package informationgathering;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.Marker;
import java.util.Objects;

public class UrlsMap {
	private Map<String, String> dict;
	private String url;
	private HttpResponse resp;
	private HttpRequestResponse baseRequestResponse;
	
	public UrlsMap(String url, HttpRequestResponse baseRequestResponse) {
		//Dictionary with Header name as key, Header value as value
		this.dict = new HashMap<String, String>();
		//Request URL
		this.url=url;
		//HTTP Response
		this.resp = baseRequestResponse.response();
		//Couple of HTTP request & response
		this.baseRequestResponse = baseRequestResponse;
	}
	
	public void insert(String headerName, String headerValue) {
		//Add header and its value to dictionary
		dict.put(headerName, headerValue);
	}
	
	public AuditIssue audit(Logging logging, 
					  String name,
					  String remediation,
					  AuditIssueSeverity severity,
					  AuditIssueConfidence confidence,
					  String issueBackground,
					  String remediationBackground) {
		
		//Check if dictionary is empty
		if(dict.keySet().size()==0)
			return null;

		//List of markers in HTTP response based on values of analysed headers
		List<Marker> highlights = new ArrayList<>();
		String values = "<ul><li>";
		
		for(String headerName : dict.keySet()) {
			//Include headers and names in evidences
			values = values + dict.get(headerName) + " ("+headerName+")" + "</li><li>";
			
			//Create marker looking for positions of header values in the response
			Marker marker = getResponseHighlights(dict.get(headerName));
			
			if(!Objects.isNull(marker)) {
				highlights.add(marker);
			}
		}
		
		//String of evidences to be printed in issue
		values = values.substring(0, values.length()-4)+"</ul>";
		
		//Create issue
		AuditIssue issue = AuditIssue.auditIssue(name, 
												 values, 
												 remediation,
												 url,
												 severity,
												 confidence,
												 issueBackground,
												 remediationBackground,
												 severity,
												 baseRequestResponse.withResponseMarkers(highlights));
		//Return issue
		return issue;
	}
	
	public AuditIssue auditMissing(Logging logging, 
			  String name,
			  String remediation,
			  AuditIssueSeverity severity,
			  AuditIssueConfidence confidence,
			  String issueBackground,
			  String remediationBackground) {

		//Check if dictionary is empty
		if(dict.keySet().size()==0)
			return null;
		
		String values = "<ul><li>";
		
		for(String headerName : dict.keySet()) {
			//Include only headers in evidences
			values = values + headerName+ "</li><li>";
		}
		
		//String of evidences to be printed in issue
		values = values.substring(0, values.length()-4)+"</ul>";
		
		//Create issue
		AuditIssue issue = AuditIssue.auditIssue(name, 
												 values, 
												 remediation,
												 url,
												 severity,
												 confidence,
												 issueBackground,
												 remediationBackground,
												 severity,
												 baseRequestResponse);
		
		//Return issue
		return issue;
	}
	
    private Marker getResponseHighlights(String match)
    {
    	//Create marker of value in response
        String response = resp.toString();

        int start = response.indexOf(match, 0);

        if (start == -1)
        {
            return null;
        }

        Marker marker = Marker.marker(start, start+match.length());
        return marker;    
    }
}