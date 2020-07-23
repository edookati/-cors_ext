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

thirdparty = [
    "https://whatever.github.io",
    "http://jsbin.com",
    "https://codepen.io",
    "https://jsfiddle.net",
    "http://www.webdevout.net",
    "https://repl.it"
]

MessageInfo_Function = ""
payload_Global = ""

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

    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name that we add in extender
        callbacks.setExtensionName("Payload generator extension Sample")

        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        callbacks.registerHttpListener(self)

    #
    # implement IIntruderPayloadGeneratorFactory
    #

    def getGeneratorName(self):
        return "Sample payload"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return SampleIntruderPayloadGenerator(self, attack)

    # implement IHTTPListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        global MessageInfo_Function
        global payload_Global
        header_response = ""
        response = messageInfo.getResponse()

        if response is not None:
            response_analyzed = self._helpers.analyzeResponse(response)
            headers = response_analyzed.getHeaders()
            if len(headers) > 0:
                for header in headers:
                    if "Access-Control-Allow-Origin" in header:
                        header_response = header[header.find(':') + 2:]
        # to avoid default test case where function name is empty string
        if len(MessageInfo_Function) > 0:
            success = (str(header_response) == str(payload_Global))
            messageInfo.setComment("TEST CASE : " + str(MessageInfo_Function) + " &&  Result : " + ("Success" if (success) else "Fail"))

#
# class to generate payloads from a simple list
#

class SampleIntruderPayloadGenerator(IIntruderPayloadGenerator):
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
            parsed.scheme,  parsed.domain, parsed.tld)

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
        # convert into a string
        global MessageInfo_Function
        global payload_Global
        current_payload_actual = current_payload
        current_payload = "".join(chr(x) for x in current_payload)
        if self._payloadIndex < len(PAYLOADS):
            payloadFunction = PAYLOADS[self._payloadIndex]
            func = getattr(self, payloadFunction)
            # executing function
            MessageInfo_Function = payloadFunction
            payload = func(current_payload)
            self._payloadIndex = self._payloadIndex + 1

        else:
            payload = thirdparty[self._payloadIndex - len(PAYLOADS)]
            MessageInfo_Function = "Third Party [" + str(self._payloadIndex - len(PAYLOADS)) + "]"
            self._payloadIndex = self._payloadIndex + 1

        # skip test cases which are not applicable as they return None
        if payload is None:
            if self._payloadIndex < len(PAYLOADS) + len(thirdparty):
                payload = self.getNextPayload(current_payload_actual)

        payload_Global = payload
        return payload

    def reset(self):
        global MessageInfo_Function
        self._payloadIndex = 0
        MessageInfo_Function = ""
        print("End")
        return
