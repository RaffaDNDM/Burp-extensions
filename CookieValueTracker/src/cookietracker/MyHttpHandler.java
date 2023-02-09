package cookietracker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.logging.Logging;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class MyHttpHandler implements HttpHandler
{
	private Logging logging;
	private String color;
	private String name;
	private String cookie;
	
    public MyHttpHandler(MontoyaApi api, String cookie, String color, String name)
    {
    	this.logging = api.logging();
    	this.color = color;
    	this.name = name;
    	this.cookie = cookie;
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent)
    {
    	Annotations annotations = requestToBeSent.annotations();
    	String request = requestToBeSent.toString();
    	
        if(request.indexOf(cookie)!=-1) {
        	//Add Highlight Color (Color Set globally)
        	annotations.setHighlightColor(HighlightColor.highlightColor(color));
        	annotations.setNotes(name);
        	//Return the modified request to burp with updated annotations.
	        return RequestToBeSentAction.continueWith(requestToBeSent, annotations);
        }
        else {
        	//Add Highlight Color (Color Set globally)
        	annotations.setHighlightColor(HighlightColor.NONE);
        	//Return original request
	        return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived)
    {
    	//Return original response
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}