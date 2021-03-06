import os
from io import open

from burp import IBurpExtender
from burp import IIntruderPayloadGenerator
from burp import IIntruderPayloadGeneratorFactory
from burp import IHttpListener

# url modification module
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

# Global Variables
MessageInfo_Function = ""

thirdparty = [
    "https://whatever.github.io",
    "http://jsbin.com",
    "https://codepen.io",
    "https://jsfiddle.net",
    "http://www.webdevout.net",
    "https://repl.it"
]

PAYLOADS = [
    'reflect_any_origin',
    'trust_any_subdomain',
    'trust_null',
    'prefix_match',
    'suffix_match',
    'subString_match',
    'escape_Dot_WithCharacter',
    'escape_Dot_WithoutCharacter',
    'https_trust_http']

# ----------------------------tld extract start-----------------------------
dirname = os.getcwd()
filename = os.path.join(dirname, 'effective_tld_names.dat.txt')

# load tlds, ignore comments and empty lines:
with open(filename, 'r', encoding='utf8', errors='ignore') as tld_file:
    tlds = [line.strip() for line in tld_file if line[0] not in "/\n"]


class DomainParts(object):
    def __init__(self, url_scheme, domain_parts, tld):
        self.domain = None
        self.subdomains = None
        self.tld = tld
        self.scheme = url_scheme
        if domain_parts:
            self.domain = domain_parts[-1]
            if len(domain_parts) > 1:
                self.subdomains = domain_parts[:-1]


def get_domain_parts(url):
    parsed_url = urlparse(url)
    if parsed_url is not None and parsed_url.hostname is not None:
        urlElements = parsed_url.hostname.split('.')
        for i in range(-len(urlElements), 0):
            lastIElements = urlElements[i:]
            candidate = ".".join(lastIElements)
            wildcardCandidate = ".".join(["*"] + lastIElements[1:])
            exceptionCandidate = "!" + candidate

            # match tlds:
            if exceptionCandidate in tlds:
                return ".".join(urlElements[i:])
            if candidate in tlds or wildcardCandidate in tlds:
                return DomainParts(parsed_url.scheme, urlElements[:i], '.'.join(urlElements[i:]))

    else:
        raise ValueError("Url parse Error please provide url in correct format")


# ----------------------------tld extract ends-----------------------------

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IHttpListener):

    #
    # implement IBurpExtender
    #
    def __init__(self):
        self._instance = None

    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name that we add in extender
        callbacks.setExtensionName("Payload generator extension Sample")
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.registerHttpListener(self)

    #
    # implement IIntruderPayloadGeneratorFactory
    #

    def getGeneratorName(self):
        return "Intruder Payload"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        self._instance = SampleIntruderPayloadGenerator(self, attack)
        return self._instance

    # implement IHTTPListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # global Variable
        global MessageInfo_Function
        print("Processing the HttpMessage starts")
        # Processing HTTP
        origin_header_response = ""
        origin_header_request = ""

        # get Origin from Request
        request = messageInfo.getRequest()
        request_analyzed = self._helpers.analyzeRequest(request)
        if request is not None:
            request_analyzed = self._helpers.analyzeRequest(request)
            headers = request_analyzed.getHeaders()
            if len(headers) > 0:
                for header in headers:
                    if "origin".lower() in header.lower():
                        origin_header_request = header[header.find(':') + 1:]
        print("Processing the HttpMessage got origin header request origin_header_request as "+ origin_header_request)
        # get Origin from Response
        response = messageInfo.getResponse()
        if response is not None:
            response_analyzed = self._helpers.analyzeResponse(response)
            headers = response_analyzed.getHeaders()
            if len(headers) > 0:
                for header in headers:
                    if "Access-Control-Allow-Origin".lower() in header.lower():
                        origin_header_response = header[header.find(':') + 2:]
        print("Processing the HttpMessage got origin header request origin_header_response as "+ origin_header_response)
        # Verification of Result by comparing the Origin from Request and Response
        result = "Success" if (origin_header_request == origin_header_response) else "Fail"
        print("Processing the HttpMessage got result as "+ result)
        # to avoid default test case where function name is empty string
        if messageIsRequest == 0 and len(MessageInfo_Function) > 0 and SampleIntruderPayloadGenerator.start == 1:
            print("Setting the MessageInfo")
            messageInfo.setComment("Test case: " + str(MessageInfo_Function) + " && Result: " + str(result))
            SampleIntruderPayloadGenerator.start = 0
#
# class to generate payloads from a simple list
#

class SampleIntruderPayloadGenerator(IIntruderPayloadGenerator):

    start = 0

    def __init__(self, extender, attack):
        self._extender = extender
        self._attack = attack
        self._payloadIndex = 0
        return

    # reflecting any origin
    # www.example.com -> evil.com
    def reflect_any_origin(self, original_payload):
        test_url = original_payload
        parsed = urlparse(test_url)

        test_origin = parsed.scheme + "://" + "evil.com"

        return test_origin

    # remove any subdomain and just replace with evil
    def trust_any_subdomain(self, original_payload):
        test_url = original_payload
        parsed = get_domain_parts(test_url)

        (url_schema, domain, suffix) = (
            parsed.scheme, parsed.domain, parsed.tld)
        url_schema = "" if (url_schema == "") else url_schema + "://"
        domain = "" if (domain is None) else domain

        test_origin = parsed.scheme + "://" + "evil." + domain + "." + suffix

        return test_origin

    # trust null
    # what ever may be the payload the origin will be null
    def trust_null(self, original_payload):
        test_url = original_payload
        test_origin = "null"
        return test_origin

    def https_trust_http(self, original_payload):
        test_url = original_payload
        parsed = urlparse(test_url)
        if parsed.scheme != "https":
            return None
        test_origin = "http://" + parsed.netloc.split(':')[0]
        return test_origin

    # appending evil at the end of the domain
    # www.example.com -> exampleevil.com
    def prefix_match(self, original_payload):
        test_url = original_payload
        parsed = get_domain_parts(test_url)

        (url_schema, subdomains, domain, suffix) = (
            parsed.scheme, parsed.subdomains, parsed.domain, parsed.tld)

        url_schema = "" if (url_schema == "") else url_schema + "://"
        subdomain = (".".join(subdomains)) + "." if (subdomains is not None) else ""
        # addition of the
        domain = "" if (domain is None) else domain

        test_origin = url_schema + subdomain + domain + "." + suffix + ".evil." + suffix

        return test_origin

    # appending evil at the end of the domain
    # www.example.com -> exampleevil.com
    def suffix_match(self, original_payload):
        test_url = original_payload
        parsed = get_domain_parts(test_url)
        (url_schema, domain, suffix) = (
            parsed.scheme, parsed.domain, parsed.tld)

        url_schema = "" if (url_schema == "") else url_schema + "://"

        # addition of the
        domain = "" if (domain is None) else "evil" + domain + "."

        test_origin = url_schema + domain + suffix

        return test_origin

    # appending evil at the end of the domain
    # www.example.com -> exampleevil.com
    def subString_match(self, original_payload):
        test_url = original_payload
        parsed = get_domain_parts(test_url)

        (url_schema, subdomains, domain, suffix) = (
            parsed.scheme, parsed.subdomains, parsed.domain, parsed.tld)
        url_schema = "" if (url_schema == "") else url_schema + "://"
        subdomain = (".".join(subdomains)) + "." if (subdomains is not None) else ""

        domain = "" if (domain is None) else domain + "."
        length = len(subdomain + domain + suffix)
        test_origin = url_schema + (subdomain + domain + suffix)[:length - 1]

        return test_origin

    # appending evil at the end of the domain
    # www.example.com -> exampleevil.com
    def escape_Dot_WithCharacter(self, original_payload):
        test_url = original_payload
        parsed = get_domain_parts(test_url)

        (url_schema, subdomains, domain, suffix) = (
            parsed.scheme, parsed.subdomains, parsed.domain, parsed.tld)
        url_schema = "" if (url_schema == "") else url_schema + "://"

        if subdomains is not None:
            subdomain = (".".join(subdomains)) + "a" if (subdomains is not None) else ""
            domain = "" if (domain is None) else domain + "."
            test_origin = url_schema + (subdomain + domain + suffix)
        else:
            return None
        return test_origin

    # appending evil at the end of the domain
    # www.example.com -> exampleevil.com
    def escape_Dot_WithoutCharacter(self, original_payload):
        test_url = original_payload
        parsed = get_domain_parts(test_url)

        (url_schema, subdomains, domain, suffix) = (
            parsed.scheme, parsed.subdomains, parsed.domain, parsed.tld)
        url_schema = "" if (url_schema == "") else url_schema + "://"

        if subdomains is not None:
            subdomain = (".".join(subdomains)) if (subdomains is not None) else ""
            domain = "" if (domain is None) else domain + "."
            test_origin = url_schema + (subdomain + domain + suffix)
        else:
            return None
        return test_origin

    # implementation of IPayload Generator

    def hasMorePayloads(self):
        return self._payloadIndex < len(PAYLOADS) + len(thirdparty)

    def getNextPayload(self, current_payload):

        # global Function
        global MessageInfo_Function
        SampleIntruderPayloadGenerator.start = 1
        print("Process Start")
        # convert into a string
        current_payload_actual = current_payload
        current_payload = "".join(chr(x) for x in current_payload)
        if self._payloadIndex < len(PAYLOADS):
            print("Process from Generator Functions end")
            payloadFunction = PAYLOADS[self._payloadIndex]
            func = getattr(self, payloadFunction)

            # populating Global Function name
            MessageInfo_Function = payloadFunction

            # executing function
            payload = func(current_payload)
            self._payloadIndex = self._payloadIndex + 1
            print("Process from Generator Functions end")

        else:
            print("Process from ThirdParty starts")
            payload = thirdparty[self._payloadIndex - len(PAYLOADS)]

            # populating Global Function name
            MessageInfo_Function = "Third Party [" + str(self._payloadIndex - len(PAYLOADS)+1) + "]"
            print("Process from ThirdParty ends")
            self._payloadIndex = self._payloadIndex + 1

        # skip test cases which are not applicable as they return None
        if payload is None:
            print("Payload became none")
            if self._payloadIndex < len(PAYLOADS) + len(thirdparty):
                print("as payload is none going to the next payload")
                payload = self.getNextPayload(current_payload_actual)
        return payload

    def reset(self):
        self._payloadIndex = 0
        return
