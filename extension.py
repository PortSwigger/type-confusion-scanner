from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IScannerInsertionPoint
from burp import IRequestInfo
from array import array
import json
 
 
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
        callbacks.setExtensionName("Type Confusion Extension")
        print("Starting Extension...")
        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)
 
    # helper method to search a request for occurrences of a literal match string
    # iterate thru JSON values and see if our injection point is a Full value, burp will auto select substrings in a JSON value to do injections and we don't want to test those
    # we also do not want to test str/unicode values as they are already strings, so ignore them
    def _searchForValueAndCheckIfString(self, json, value):
        for key in json:
            val = json[key]
            #we need to cast the json value as a string for comparison as the insertPoint auto-casts when it reads and there isn't a way to get the native type
            #the logic below will figure out if it is a testable parameter
            if str(val) == value:
                if isinstance(val, str):
                    return True
                elif isinstance(val, unicode):
                    return True
                else:
                    return False
        
        #it's some substring of a value, flag it as not testable
        return True
 
    #
    # implement IScannerCheck
    #
    #
 
    #no passive scan is applicable
    def doPassiveScan(self, baseRequestResponse):
        return None
 
    def doActiveScan(self, baseRequestResponse, insertionPoint):
    
        try:
            # Check to see if request is content-type JSON
            baseRequest = baseRequestResponse.getRequest()
            request_info = self._helpers.analyzeRequest(baseRequest)
            response_info = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
            if not (request_info.getContentType() == IRequestInfo.CONTENT_TYPE_JSON):
                return None
            
            # Check to see if its successful in the first place, don't waste time checking bad reqs
            if not (response_info.getStatusCode() == 200):
                return None
                
            #Don't need to check entire body insertions
            if insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_ENTIRE_BODY:
                return None
        
            #get our injection value
            baseValue = insertionPoint.getBaseValue()
            
            #get the original request body as a string
            baseRequestBody = baseRequest[request_info.getBodyOffset():].tostring() 

            #if it happens to be 0, just stop
            if len(baseRequestBody) == 0:
                return None
            
            #load body as a json object for searching
            baseRequestBodyJSON = json.loads(baseRequestBody)
         
            #String check
            if self._searchForValueAndCheckIfString(baseRequestBodyJSON, baseValue):
                return None
    
            # Change Number into a string then make new request
            # Simply re-inserting the value automatically gives it quotes
            checkRequest = insertionPoint.buildRequest(baseValue)
            checkRequestResponse = self._callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), checkRequest)
    
    
            # Check if original request and modified request are the same
            #we need to just check the body legnth, maybe just check for a 200
            checkresponse_info = self._helpers.analyzeResponse(checkRequestResponse.getResponse())
            if not (checkresponse_info.getStatusCode() == 200):
                return None
    
            # get the offsets of the payload within the request, for in-UI highlighting    
            requestHighlights = [insertionPoint.getPayloadOffsets(baseValue)]

            url = self._helpers.analyzeRequest(checkRequestResponse).getUrl()
            # report the issue
            return [CustomScanIssue(
                checkRequestResponse.getHttpService(),
                url,
                [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, [])],
                "Type confusion found in JSON body",
                "Original request has the same length response as request with modified request. The value <b>"+baseValue+"</b>, was resubmitted as a string <b>\""+baseValue+"\"</b> and the reponse was the same at <b>"+str(url)+"</b>.",
                "Information")]
        except Exception as e: 
            print(e)
 
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        #if existingIssue.getIssueName() == newIssue.getIssueName():
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
 
        return 0
 
#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
 
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
        pass
 
    def getRemediationBackground(self):
        pass
 
    def getIssueDetail(self):
        return self._detail
 
    def getRemediationDetail(self):
        pass
 
    def getHttpMessages(self):
        return self._httpMessages
 
    def getHttpService(self):
        return self._httpService