from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
import re

#Security Headers to be searched in response headers
SECURITY_HEADERS = {'X-Frame-Options': 'x-frame-options: ([\W\w]+)',
                    'X-Content-Type-Options': 'x-content-type-options: ([\W\w]+)',
                    'HSTS': 'strict-transport-security: ([\W\w]+)',
                    'CSP': 'content-security-policy: ([\W\w]+)',
                    'Referrer-Policy': 'referrer-policy: ([\W\w]+)',
                    'X-XSS-Protection': 'x-xss-protection: ([\W\w]+)',
                    'Except-CT': 'expect-ct: ([\W\w]+)',
                    'Permissions-Policy': 'permissions-policy: ([\W\w]+)',
                    'Cross-Origin-Embedder-Policy': 'cross-origin-embedder-policy: ([\W\w]+)',
                    'Cross-Origin-Resource-Policy': 'cross-origin-resource-policy: ([\W\w]+)',
                    'Cross-Origin-Opener-Policy': 'cross-origin-opener-policy: ([\W\w]+)'}

FINGERPRINTING_HEADERS = {'via': 'via: ([\W\w]+)',
                          'server': 'server: ([\W\w]+)',
                          'x-powered-by': 'x-powered-by: ([\W\w]+)',
                          'x-aspnet-version': 'x-aspnet-version: ([\W\w]+)',
                          'microsoftsharepointteamservices': 'microsoftsharepointteamservices: ([\W\w]+)'
                         }

class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Header analysis")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    #
    # implement IScannerCheck
    #
    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        response = self._helpers.bytesToString(baseRequestResponse.getResponse()).split("\r\n\r\n")
        
        headers = response[0].split("\r\n")
        ISSUES = []

        for sh in SECURITY_HEADERS:
            MISSING_SH = True

            for i, val in enumerate(headers):
                if re.match(SECURITY_HEADERS[sh], val, re.IGNORECASE):
                    MISSING_SH = False
                
            if MISSING_SH:
                ISSUES.append(CustomScanIssue( baseRequestResponse.getHttpService(), 
                                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                                                [self._callbacks.applyMarkers(baseRequestResponse, None, None),], 
                                                'Missing '+sh, 
                                                "The response doesn't contain the header: " + sh, 
                                                "Information",
                                                "Misconfiguration of the server",
                                                "Configure correct headers"))
            else:
                ISSUES.append(CustomScanIssue( baseRequestResponse.getHttpService(), 
                                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                                                [self._callbacks.applyMarkers(baseRequestResponse, None, None),], 
                                                'IMPLEMENTED '+sh, 
                                                "The response doesn't contain the header: " + sh, 
                                                "Information",
                                                "Misconfiguration of the server",
                                                "Configure correct headers"))

        info = []

        for fh in FINGERPRINTING_HEADERS:
            for i, val in enumerate(headers):
                if re.match(FINGERPRINTING_HEADERS[fh], val, re.IGNORECASE):
                    info.append(re.match(FINGERPRINTING_HEADERS[fh], val, re.IGNORECASE).group(1))


        if len(info)>0:
            ISSUES.append(CustomScanIssue( baseRequestResponse.getHttpService(), 
                                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                                                [self._callbacks.applyMarkers(baseRequestResponse, None, None),], 
                                                'Information disclosure via HTTP Header', 
                                                "The response discloses the following informations: <ul><li>" + '</li><li>'.join(info)+'</li>', 
                                                "Low",
                                                "Misconfiguration of the server",
                                                "If possible, emove direct references to adopted technologies"))
            
        # report the issue
        return  ISSUES

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, issue_background, remediation_background):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._issue_background = issue_background
        self._remediation_background = remediation_background

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return self._issue_background

    def getRemediationBackground(self):
        return self._remediation_background

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
