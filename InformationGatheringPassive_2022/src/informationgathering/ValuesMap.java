package informationgathering;

import java.util.HashMap;
import java.util.Map;

import burp.api.montoya.http.message.MarkedHttpRequestResponse;

public class ValuesMap {
	private Map<String, MarkedHttpRequestResponse> dict; 
	
	public ValuesMap() {
		dict = new HashMap<String, MarkedHttpRequestResponse>();
	}
	
	public void add(MarkedHttpRequestResponse r, String headerValue) {		
		if(dict.get(headerValue) == null) {
			dict.put(headerValue, r);
		}
	}
	
	public Map<String, MarkedHttpRequestResponse> getDict() {
		return dict;
	}
}