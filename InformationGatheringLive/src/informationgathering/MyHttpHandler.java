package informationgathering;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static java.util.Collections.emptyList;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class MyHttpHandler implements HttpHandler
{
	private Logging logging;
	private String color;
	private String analysisType;
	
    public MyHttpHandler(MontoyaApi api, String color, String analysisType)
    {
    	this.logging = api.logging();
    	this.color = color;
    	this.analysisType = analysisType;
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent)
    {
    	return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived)
    {   
    	List<HttpHeader> headers = responseReceived.headers();
    	List<Marker> fingerprintEvidences = new ArrayList<Marker>();
    	List<String> fingerprintNames = new ArrayList<String>();
    	List<Marker> secHeadersEvidences = new ArrayList<Marker>();
    	List<String> secHeadersNames = new ArrayList<String>();
    	
    	String responseString = responseReceived.toString();
    	
    	//Analysis of all headers in HTTP response
    	for(HttpHeader h : headers) {
			String name = h.name();
			String value = h.value();
			
			//If response contains HTTP Fingerprint headers
			if(analysisType == UsefulInfo.typeChoices[0] && UsefulInfo.FINGERPRINTING_HEADERS.contains(name.toLowerCase())) {
				fingerprintEvidences.add(getEvidence(responseString, value));
				fingerprintNames.add(name);
			}

			//If response contains HTTP Security headers
			if(analysisType != UsefulInfo.typeChoices[0] && UsefulInfo.SECURITY_HEADERS.contains(name.toLowerCase())) {
				secHeadersEvidences.add(getEvidence(responseString, value));
				secHeadersNames.add(name.toLowerCase());
			}
		}
		
		Annotations annotations = responseReceived.annotations();
		List<String> missingSecHeadersNames = new ArrayList<String>();
		
		//If Missing HTTP Security headers analysis is considered
		if(analysisType == UsefulInfo.typeChoices[2] && UsefulInfo.SECURITY_HEADERS.size()!=secHeadersNames.size()) {
			
			//Generate list of missing HTTP Security headers in the response
			for(String h : UsefulInfo.SECURITY_HEADERS) {
				if(!(secHeadersNames.contains(h))) {
					missingSecHeadersNames.add(h);
				}
			}
    	}
    
		//Create annotations for all the analysis modes
		if((analysisType == UsefulInfo.typeChoices[0] && (!fingerprintEvidences.isEmpty())) ||
		   (analysisType == UsefulInfo.typeChoices[1] && (!secHeadersEvidences.isEmpty())) ||
		   (analysisType == UsefulInfo.typeChoices[2] && (!missingSecHeadersNames.isEmpty()))) {
	        
			HttpResponse resp = null;
			
			annotations.setHighlightColor(HighlightColor.highlightColor(color));
		
	    	if(analysisType == UsefulInfo.typeChoices[0]) {
	    		resp = responseReceived.withMarkers(fingerprintEvidences);
	    		annotations.setNotes("["+analysisType+"] "+String.join(",", fingerprintNames));
	    	}
	    	else if(analysisType == UsefulInfo.typeChoices[1]) {
	    		resp = responseReceived.withMarkers(secHeadersEvidences);
	    		annotations.setNotes("["+analysisType+"] "+String.join(",", secHeadersNames));
	    	}
	    	else if (analysisType == UsefulInfo.typeChoices[2]) {
	    		resp = responseReceived;
	    		annotations.setNotes("["+analysisType+"] "+String.join(",", missingSecHeadersNames));
	    	}
	    	
	    	return ResponseReceivedAction.continueWith(resp, annotations);
		
		}

		return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    private Marker getEvidence(String response, String value) {
    	//Create marker of value in response
    	int start = response.indexOf(value, 0);

        if (start == -1)
        {
            return null;
        }
        
        return Marker.marker(start, start+value.length());
    }
}