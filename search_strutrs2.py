from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IProxyListener
from burp import IHttpService
import re

print 'this  extender by  jkwolf18 '
print 'struts2 action hunter '




class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
    
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("jkwolf18")
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        if  toolFlag == 8 or toolFlag == 4: #if tool is Proxy Tab or repeater
            if not messageIsRequest:#only handle responses
            
                #response
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response) # returns IResponseInfo
                response_headers = analyzedResponse.getHeaders()
                response_bodys = response[analyzedResponse.getBodyOffset():].tostring()
                response_StatusCode = analyzedResponse.getStatusCode()
                
                #request
                resquest = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeResponse(resquest)
                request_header = analyzedRequest.getHeaders()
                request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()
                
                
                #fuwu
                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()
                Protocol = httpService.getProtocol()
                
                
                #if response_StatusCode==200:
                for rqheader in request_header:
                    if rqheader.startswith("Host"):
                        rqhost = rqheader
                        #print rqhost
                        
                a='.action'
                if a in request_header[0]:
                	print rqhost+"===="+request_header[0]
                
                
                
                
                
                '''

                    if rqheader.startswith("Referer"):
                        rqrefer = rqheader
                        print rqrefer
                '''

                    
                    #print "--------------------------------Jkwolf-----------------------------------------"
                    #print request_header
                    #print "======"+request_bodys+"======"
                    #print "--------------------------------Jkwolf-----------------------------------------"
                    #print request_bodys   
                    #print response_headers  
                    #print response_bodys  
