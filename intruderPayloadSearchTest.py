import os
from io import open

from burp import IBurpExtender
from burp import IIntruderPayloadGenerator
from burp import IIntruderPayloadGeneratorFactory

# url modification module
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

PAYLOADS = [
    'test_reflect_origin',
    'test_trust_any_subdomain',
    'test_trust_null',
    'test_prefix_match',
    'test_suffix_match',
    'test_https_trust_http']

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

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._callbacks = callbacks

        # set our extension name that we add in extender
        callbacks.setExtensionName("Payload generator extension")

        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)

    #
    # implement IIntruderPayloadGeneratorFactory
    #

    def getGeneratorName(self):
        return "Sample payload"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return SampleIntruderPayloadGenerator(self, attack)

    #
    # implement IIntruderPayloadProcessor
    #


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
    def test_reflect_origin(self, original_payload):
        test_url = original_payload
        parsed = urlparse(test_url)

        test_origin = parsed.scheme + "://" + "evil.com"

        return test_origin

    # remove any subdomain and just replace with evil
    def test_trust_any_subdomain(self, original_payload):
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
    def test_trust_null(self, original_payload):
        test_url = original_payload
        test_origin = "null"
        return test_origin

    def test_https_trust_http(self, original_payload):
        test_url = original_payload
        parsed = urlparse(test_url)
        if parsed.scheme != "https":
            return
        test_origin = "http://" + parsed.netloc.split(':')[0]

        return test_origin

    # appending evil at the end of the domain
    # www.example.com -> exampleevil.com
    def test_prefix_match(self, original_payload):
        test_url = original_payload
        parsed = get_domain_parts(test_url)

        (url_schema, subdomains, domain, suffix) = (
            parsed.scheme, parsed.subdomains, parsed.domain, parsed.tld)

        url_schema = "" if (url_schema == "") else url_schema + "://"

        subdomain = (".".join(subdomains))+"." if (subdomains is not None) else ""

        # addition of the
        domain = "" if (domain is None) else domain

        test_origin = url_schema + subdomain + domain + "." + suffix + ".evil." + suffix

        return test_origin

    # appending evil at the end of the domain
    # www.example.com -> exampleevil.com
    def test_suffix_match(self, original_payload):
        test_url = original_payload
        parsed = get_domain_parts(test_url)

        (url_schema, subdomains, domain, suffix) = (
            parsed.scheme, parsed.subdomains, parsed.domain, parsed.tld)

        url_schema = "" if (url_schema == "") else url_schema + "://"

        subdomain = (".".join(subdomains))+"." if (subdomains is not None) else ""

        # addition of the
        domain = "" if (domain is None) else "evil" + domain + "."

        test_origin = url_schema + subdomain + domain + suffix

        return test_origin

    def hasMorePayloads(self):
        return self._payloadIndex < len(PAYLOADS)

    def getNextPayload(self, current_payload):
        # convert into a string
        current_payload = "".join(chr(x) for x in current_payload)

        payload_function = PAYLOADS[self._payloadIndex]

        func = getattr(self, payload_function)
        # executing function
        payload = func(current_payload)

        # call our simple mutator to fuzz the post
        self._payloadIndex = self._payloadIndex + 1

        return payload

    def reset(self):
        self._payloadIndex = 0
        return
