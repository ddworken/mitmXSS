from mitmproxy import ctx  # Used for logging information to mitmproxy
from socket import gaierror, gethostbyname  # Used to check whether a domain name resolves
from urllib.parse import urlparse  # Used to modify paths and queries for URLs
from lxml.etree import ParserError, XMLSyntaxError  # Catch errors caused by parsing trees
from lxml.html import fromstring, tostring  # Used when processing HTML as a tree
import requests  # Used to send additional requests when looking for XSSs
import re  # Used for pulling out the payload

# The actual payload is put between a frontWall and a backWall to make it easy
# to locate the payload with regular expressions
frontWall = b"1029zxc"
backWall  = b"3847asd"
payload   = b"""s'd"ao<ac>so[sb]po(pc)se;sl/bsl\\"""
fullPayload = frontWall + payload + backWall

# A URL is a string starting with http:// or https:// that points to a website
# A XSSDict is a dictionary with the following keys value pairs:
#   - 'URL' -> URL
#   - 'Injection Point' -> String
#   - 'Exploit' -> String
#   - 'Line' -> String

def findUnclaimedURLs(body, requestUrl):
    """ Look for unclaimed URLs in script tags and log them if found
        String URL -> None """
    try:
        tree = fromstring(body)
        scriptURLs = tree.xpath('//script/@src')
        for url in scriptURLs:
            parser = urlparse(url)
            domain = parser.netloc
            try:
                gethostbyname(domain)
            except gaierror:
                ctx.log.error("XSS found in %s due to unclaimed URL \"%s\" in script tag." % (requestUrl, url))
    except XMLSyntaxError:
        pass
    except ParserError:
        pass
                
def testEndOfURLInjection(requestURL):
    """ Test the given URL for XSS via injection onto the end of the URL and
        log the XSS if found
        URL -> None """
    parsedURL = urlparse(requestURL)
    path = parsedURL.path
    if path[-1] != "/":  # ensure the path ends in a /
        path += "/"
    path += fullPayload.decode('utf-8')  # the path must be a string while the payload is bytes
    url = parsedURL._replace(path=path).geturl()
    body = requests.get(url).text.lower() 
    xssInfo = getXSSInfo(body, url, "End of URL")
    ctxLog(xssInfo)

def testRefererInjection(requestURL):
    """ Test the given URL for XSS via injection into the referer and 
        log the XSS if found 
        URL -> None """
    body = requests.get(requestURL, headers={'referer': fullPayload}).text.lower()
    xssInfo = getXSSInfo(body, requestURL, "Referer")
    ctxLog(xssInfo)

def testUserAgentInjection(requestURL):
    """ Test the given URL for XSS via injection into the user agent and
        log the XSS if found 
        URL -> None """
    body = requests.get(requestURL, headers={'User-Agent': fullPayload}).text.lower()
    xssInfo = getXSSInfo(body, requestURL, "User Agent")
    ctxLog(xssInfo)
    
def testQueryInjection(requestURL):
    """ Test the given URL for XSS via injection into URL queries and
        log the XSS if found
        URL -> None """
    parsedURL = urlparse(requestURL)
    queryString = parsedURL.query
    # queries is a list of parameters where each parameter is set to the payload
    queries = [query.split("=")[0]+"="+fullPayload.decode('utf-8') for query in queryString.split("&")]
    newQueryString = "&".join(queries)
    newURL = parsedURL._replace(query=newQueryString).geturl()
    body = requests.get(newURL).text.lower()
    xssInfo = getXSSInfo(body, newURL, "Query")
    ctxLog(xssInfo)

def ctxLog(xssInfo):
    """ Log information about the given XSS to mitmproxy
        (XSSDict or None) -> None """
    # If it is None, then there is no info to log
    if not xssInfo:
        return
    ctx.log.error("===== XSS Found ====")
    ctx.log.error("XSS URL: %s" % xssInfo['URL'])
    ctx.log.error("Injection Point: %s" % xssInfo['Injection Point'])
    ctx.log.error("Suggested Exploit: %s" % xssInfo['Exploit'])
    ctx.log.error("Line: %s" % xssInfo['Line'])

def getXSSInfo(body, requestURL, injectionPoint):
    """ Return a XSSDict if there is a XSS otherwise return None
        String URL String -> (XSSDict or None) """
    # All of the injection tests work by checking whether the character (with
    # the fences on the side) appear in the body of the HTML
    def injectOA(match):
        """ Whether or not you can inject <
            Bytes -> Boolean """
        return b"ao<ac" in match
    def injectCA(match):
        """ Whether or not you can inject >
            Bytes -> Boolean """
        return b"ac>so" in match
    def injectSingleQuotes(match):
        """ Whether or not you can inject '
            Bytes -> Boolean """
        return b"s'd" in match
    def injectDoubleQuotes(match):
        """ Whether or not you can inject "
            Bytes -> Boolean """
        return b'd"ao' in match
    def injectSlash(match):
        """ Whether or not you can inject /
            Bytes -> Boolean """
        return b"sl/bsl" in match
    def injectSemi(match):
        """ Whether or not you can inject ;
            Bytes -> Boolean """
        return b"se;sl" in match
    # A Path is a String containing HTML nodes separated by forward slashes
    # A HTMLTree is a lxml tree returned by fromstring()
    # A TreePathTuple is a (HTMLTree, Path)
    def pathsToText(listOfTreePathTuples, str, found=[]):
        """ Return list of Paths to a given str in the given HTML tree
              - Note that it does a BFS
            TreePathTuple String -> [ListOf Path] """
        newLOTPT = []
        if not listOfTreePathTuples:
            return found
        for tuple in listOfTreePathTuples:
            tree = tuple[0]
            path = tuple[1]
            if tree.text and str in tree.text:
                found.append(path+"/"+tree.tag)
            else:
                newLOTPT.extend([(child, path+"/"+tree.tag) for child in tree.getchildren()])
        return pathsToText(newLOTPT, str, found)
    def inScript(text, index, body):
        """ Whether the Numberth occurence of the first string in the second
            string is inside a script tag
            String Number String -> Boolean """
        paths = pathsToText([(fromstring(body), "")], text.decode("utf-8"), found=[])
        try:
            path = paths[index]
            return "script" in path
        except IndexError:
            return False
    def inHTML(text, index, body):
        """ Whether the Numberth occurence of the first string in the second
            string is inside the HTML but not inside a script tag or part of
            a HTML attribute
            String Number String -> Boolean """
        # if there is a < then lxml will interpret that as a tag, so only search for the stuff before it
        text = text.split(b"<")[0]
        paths = pathsToText([(fromstring(body), "")], text.decode("utf-8"), found=[])
        try:
            path = paths[index]
            return "script" not in path
        except IndexError:
            return False
    # A QuoteChar is either ' or "
    def insideQuote(qc, text, textIndex, body):
        """ Whether the Numberth occurence of the first string in the second
            string is inside quotes as defined by the supplied QuoteChar
            QuoteChar String Number String -> Boolean """
        text = text.decode('utf-8')
        body = body.decode('utf-8')
        inQuote = False
        count = 0
        for index,char in enumerate(body):
            if char == qc and body[index-1] != "\\":
                inQuote = not inQuote
            if body[index:index+len(text)] == text:
                if count == textIndex:
                    return inQuote
                count += 1
        raise Exception("Failed in inside quote")
    def injectJavascriptHandler(lot):
        """ Whether you can inject a Javascript:alert(0) as a link
            [ListOf HTMLTree] -> Boolean """
        newLot = []
        if not lot:
            return False
        for tree in lot:
            if tree.attrib and 'href' in tree.attrib.keys() and tree.attrib['href'].startswith(frontWall.decode('utf-8')):
                return True
            else:
                newLot.extend([child for child in tree])
        return injectJavascriptHandler(newLot)
    # Only convert the body to bytes if needed
    if isinstance(body, str):
        body = bytes(body, 'utf-8')
    # Regex for between 24 and 72 (aka 24*3) characters encapsulated by the walls
    regex = re.compile(b"""%s.{24,72}?%s""" % (frontWall, backWall))
    matches = regex.findall(body)
    for index,match in enumerate(matches):
        # Where the string is injected into the HTML
        inScript = inScript(match, index, body)
        inHTML   =   inHTML(match, index, body)
        inTag    = not inScript and not inHTML
        inSingleQuotes = insideQuote("'", match, index, body)
        inDoubleQuotes = insideQuote('"', match, index, body)
        # Whether you can inject: 
        injectOA = injectOA(match)  # open angle brackets
        injectCA = injectCA(match)  # close angle brackets
        injectSingleQuotes = injectSingleQuotes(match)  # single quotes
        injectDoubleQuotes = injectDoubleQuotes(match)  # double quotes
        injectSlash = injectSlash(match)  # forward slashes
        injectSemi  = injectSemi(match)  # semicolons
        # The initial response dict: 
        respDict = {'Line': match.decode('utf-8'),
                    'URL': requestURL,
                    'Injection Point': injectionPoint}
        # Debugging: 
        #print("====================================")
        #print("In Script: %s" % inScript)
        #print("In HTML: %s" % inHTML)
        #print("In Tag: %s" % inTag)
        #print("inSingleQuotes: %s" % inSingleQuotes)
        #print("inDoubleQuotes: %s" % inDoubleQuotes)
        #print("injectOA: %s" % injectOA)
        #print("injectCA: %s" % injectCA)
        #print("injectSingleQuotes: %s" % injectSingleQuotes)
        #print("injectDoubleQuotes: %s" % injectDoubleQuotes)
        #print("injectSlash: %s" % injectSlash)
        #print("injectSemi: %s" % injectSemi)
        if inScript and injectSlash and injectOA and injectCA:  # e.g. <script>PAYLOAD</script>
            respDict['Exploit'] = '</script><script>alert(0)</script><script>'
            return respDict
        elif inScript and inSingleQuotes and injectSingleQuotes and injectSemi:  # e.g. <script>t='PAYLOAD';</script>
            respDict['Exploit'] = "';alert(0);g='"
            return respDict
        elif inScript and inDoubleQuotes and injectDoubleQuotes and injectSemi:  # e.g. <script>t="PAYLOAD";</script>
            respDict['Exploit'] = '";alert(0);g="'
            return respDict
        elif inTag and inSingleQuotes and injectSingleQuotes and injectOA and injectCA and injectSlash:  # e.g. <a href='PAYLOAD'>Test</a>
            respDict['Exploit'] = "'><script>alert(0)</script>"
            return respDict
        elif inTag and inDoubleQuotes and injectDoubleQuotes and injectOA and injectCA and injectSlash:  # e.g. <a href="PAYLOAD">Test</a>
            respDict['Exploit'] = '"><script>alert(0)</script>'
            return respDict
        elif inTag and not inDoubleQuotes and not inSingleQuotes and injectOA and injectCA and injectSlash:  # e.g. <a href=PAYLOAD>Test</a>
            respDict['Exploit'] = '><script>alert(0)</script>'
            return respDict
        elif inHTML and not inScript and injectOA and injectCA and injectSlash:  # e.g. <html>PAYLOAD</html>
            respDict['Exploit'] = '<script>alert(0)</script>'
            return respDict
        elif injectJavascriptHandler([fromstring(body)]):  # e.g. <html><a href=PAYLOAD>Test</a>
            respDict['Exploit'] = 'Javascript:alert(0)'
            return respDict
        # TODO: Injection of JS executing attributes (e.g. onmouseover)
        else:
            return None

# response is mitmproxy's entry point
def response(flow):
    findUnclaimedURLs(flow.response.content, flow.request.url)  # Example: http://xss.guru/unclaimedScriptTag.html
    testEndOfURLInjection(flow.request.url)
    testRefererInjection(flow.request.url)  # Example: https://daviddworken.com/vulnerableReferer.php
    testUserAgentInjection(flow.request.url)  # Example: https://daviddworken.com/vulnerableUA.php
    if "?" in flow.request.url:
        testQueryInjection(flow.request.url)  # Example: https://daviddworken.com/vulnerable.php?name=
