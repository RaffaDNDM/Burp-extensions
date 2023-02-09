package informationgathering;

import java.util.HashMap;
import java.util.Map;

import burp.api.montoya.http.message.MarkedHttpRequestResponse;

public class HeadersMap {
	private Map<String, ValuesMap> dict; 
	
	public HeadersMap() {
		dict = new HashMap<String, ValuesMap>();
	}
	
	public void add(MarkedHttpRequestResponse r, String headerName, String headerValue) {
		if(dict.get(headerName) == null) {
			ValuesMap vm = new ValuesMap();
			vm.add(r, headerValue);
			dict.put(headerName, vm);
		}
		else {
			ValuesMap vm = dict.get(headerName);
			vm.add(r, headerValue);
			dict.put(headerName, vm);
		}
	}
	
	public Map<String, ValuesMap> getDict() {
		return dict;
	}
}
