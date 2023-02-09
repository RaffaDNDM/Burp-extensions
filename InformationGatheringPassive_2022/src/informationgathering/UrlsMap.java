package informationgathering;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.http.message.MarkedHttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;

public class UrlsMap {

	private Map<String, HeadersMap> dict;
	
	public UrlsMap() {
		this.dict = new HashMap<String, HeadersMap>();
	}
	
	public void insert(String url, MarkedHttpRequestResponse r, String headerName, String headerValue) {
		if(dict.get(url) == null) {
			HeadersMap hm = new HeadersMap();
			hm.add(r, headerName, headerValue);
			dict.put(url, hm);
		}
		else {
			HeadersMap hm = dict.get(url);
			hm.add(r, headerName, headerValue);
			dict.put(url, hm);
		}
	}
	
	public void audit(Logging logging, 
					  SiteMap site, 
					  String name,
					  String remediation,
					  AuditIssueSeverity severity,
					  AuditIssueConfidence confidence,
					  String issueBackground,
					  String remediationBackground) {
		
		for(String url : dict.keySet()) {
			String values = "<ul><li>";
			List<MarkedHttpRequestResponse> listR = new ArrayList<>();
			
			HeadersMap hm = dict.get(url);
			Map<String, ValuesMap> hmDict = hm.getDict();
			
			for(String headerName : hmDict.keySet()) {
				ValuesMap vm = hmDict.get(headerName);
				Map<String, MarkedHttpRequestResponse> vmDict = vm.getDict();
				
				for(String headerValue : vmDict.keySet()) {
					values = values + headerValue+ " ("+headerName+")" + "</li><li>";
					
					listR.add(vmDict.get(headerValue));
				}
			}
			
			values = values.substring(0, values.length()-4)+"</ul>";
			
			AuditIssue issue = AuditIssue.auditIssue(name, 
													 values, 
													 remediation,
													 url,
													 severity,
													 confidence,
													 issueBackground,
													 remediationBackground,
													 severity,
													 listR);
			
			site.add(issue);
		}
	}
	
	public void auditMissing(Logging logging, 
			  SiteMap site, 
			  String name,
			  String remediation,
			  AuditIssueSeverity severity,
			  AuditIssueConfidence confidence,
			  String issueBackground,
			  String remediationBackground) {
		
		for(String url : dict.keySet()) {
			
			String values = "<ul><li>";
			List<MarkedHttpRequestResponse> listR = new ArrayList<>();
			
			HeadersMap hm = dict.get(url);
			Map<String, ValuesMap> hmDict = hm.getDict();
			
			for(String headerName : hmDict.keySet()) {
				ValuesMap vm = hmDict.get(headerName);
				Map<String, MarkedHttpRequestResponse> vmDict = vm.getDict();
				
				for(String headerValue : vmDict.keySet()) {
					values = values + headerName + "</li><li>";
					
					listR.add(vmDict.get(headerValue));
				}
			}
			
			values = values.substring(0, values.length()-4)+"</ul>";
			
			AuditIssue issue = AuditIssue.auditIssue(name, 
													 values, 
													 remediation,
													 url,
													 severity,
													 confidence,
													 issueBackground,
													 remediationBackground,
													 severity,
													 listR);
			
			site.add(issue);
		}
	}
}