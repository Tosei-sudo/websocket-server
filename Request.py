from urlparse import urlparse, parse_qs

class Request(object):
    method = ''
    target = ''
    http_version = ''
    headers = {}
    
    path = ""
    query = {}
    
    def parse_request(self, request):
        # Assume headers and body are split by '\r\n\r\n' and we always have them.
        # Also assume all headers end with'\r\n'.
        # Also assume it starts with the method.
        split_request = request.split('\r\n\r\n')[0].split('\r\n')
        [method, target, http_version] = split_request[0].split(' ')
        headers = split_request[1:]
        for header_entry in headers:
            [header_name, value] = header_entry.split(': ')
            # Headers are case insensitive, so we can just keep track in lowercase.
            # Here's a trick though: the case of the values matter. Otherwise,
            # things don't hash and encode right!
            self.headers[header_name.lower()] = value
        self.method = method
        self.target = target
        self.http_version = http_version
        
        url = urlparse(self.target)
        
        self.path = url.path
        self.query = parse_qs(url.query)

    def __init__(self, request):
        self.parse_request(request)


class ResponseBuilder():
    def __init__(self, body = "", code = 200, headers = {}):
        self.body = body
        self.code = code
        self.headers = headers
    
    def change_parameters(self, body = None, code = None, headers = None):
        if body is not None:
            self.body = body
        if code is not None:
            self.code = code
        if headers is not None:
            self.headers = headers
    
    def __get_status_message__(self):
        if self.code == 101:
            return 'Switching Protocols'
        elif self.code == 200:
            return 'OK'
        elif self.code == 400:
            return 'Bad Request'
        else:
            return 'Internal Server Error'

    def get_response_string(self):
        response = 'HTTP/1.1 {0} {1}\r\n'.format(self.code, self.__get_status_message__())
        for header in self.headers:
            response += header + ': ' + self.headers[header] + '\r\n'
        response += '\r\n'
        response += self.body
        return bytes(response)