import os
import json

import base64
import hashlib
import select
import socket

from datetime import datetime as dt

import toy_websocket_frame
import Request

TCP_IP = '127.0.0.1'
TCP_PORT = 5006
BUFFER_SIZE = 1024 * 1024

MAGIC_WEBSOCKET_UUID_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

def main():
    '''
    Creates the front-door TCP socket and listens for connections.
    '''

    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.bind((TCP_IP, TCP_PORT))

    listening_socket.listen(1)
    print('Listening on port: ', TCP_PORT)

    input_sockets = [listening_socket]
    output_sockets = []  # Maybe use, we'll see
    xlist = []  # Not using

    ws_sockets = []

    while True:
        readable_sockets = select.select(input_sockets,
                                         output_sockets,
                                         xlist,
                                         5)[0]

        handler(readable_sockets, listening_socket, input_sockets, ws_sockets)


def handler(readable_sockets, listening_socket, input_sockets, ws_sockets):
    for ready_socket in readable_sockets:
        # Make sure it's not already closed
        if (ready_socket.fileno() == -1):
            continue
        if ready_socket == listening_socket:
            handle_new_connection(listening_socket, input_sockets)
        elif ready_socket in ws_sockets:
            handle_websocket_message(ready_socket, input_sockets,
                                        ws_sockets)
        else:
            handle_regular_request(ready_socket, input_sockets, ws_sockets)

def handle_new_connection(main_door_socket, input_sockets):
    client_socket, client_addr = main_door_socket.accept()
    input_sockets.append(client_socket)

def handle_websocket_message(client_socket, input_sockets, ws_sockets):
    try:
        data_in_bytes = bytearray(client_socket.recv(BUFFER_SIZE))

        if len(data_in_bytes) == 0:
            close_socket(client_socket, input_sockets, ws_sockets)
            return

        websocket_frame = toy_websocket_frame.WebsocketFrame()
        websocket_frame.populateFromWebsocketFrameMessage(data_in_bytes)

        bytes_data = websocket_frame.get_payload_data()

        bytes_array = json.loads(bytes_data)
        bytes_array = map(chr, bytes_array)
        print json.loads(''.join(bytes_array))
    except Exception as e:
        pass
    return

def build_ws_msg(payload):
    byte1 = 0x81
    byte2 = 0x00 + len(bytes(payload))

    ws_msg = bytearray()
    ws_msg.append(byte1)
    ws_msg.append(byte2)

    for byte in bytes(payload):
        ws_msg.append(byte)
    return ws_msg

def load_file(file_path):
    if not os.path.exists(file_path):
        return "None"
    with open(file_path, 'rb') as file:
        data = file.read()
    return data

def handle_regular_request(client_socket, input_sockets, ws_sockets):
    message = ''
    while True:
        data_in_bytes = client_socket.recv(BUFFER_SIZE)

        if len(data_in_bytes) == 0:
            close_socket(client_socket, input_sockets, ws_sockets)
            return
        message_segment = data_in_bytes.decode()
        message += message_segment
        if (len(message) > 4 and message_segment[-4:] == '\r\n\r\n'):
            break

    req = Request.Request(message)
    response = Request.ResponseBuilder()
    
    if req.target == "/websocket":
        if is_valid_ws_handshake_request(req):
            handle_ws_handshake_request(
                client_socket,
                ws_sockets,
                req.headers)
            return
        else:
            response.change_parameters(code = 400)
    elif req.path == "/msg":
        # this endpoint is send message "Hello!" to any ws connections
        msg = build_ws_msg(req.query["data"][0])
        for ws_socket in ws_sockets:
            ws_socket.send(msg)
        response.change_parameters(body="ok!")
    else:
        response.change_parameters(body=load_file(req.path[1:]))
        
    client_socket.send(response.get_response_string())
    
    print dt.now(), req.method, req.target, req.http_version, response.code
    
    close_socket(client_socket, input_sockets, ws_sockets)

def handle_ws_handshake_request(client_socket,
                                ws_sockets,
                                headers_map):
    ws_sockets.append(client_socket)

    sec_websocket_accept_value = generate_sec_websocket_accept(
        headers_map.get('sec-websocket-key'))

    websocket_response = Request.ResponseBuilder("", 101, {
        "Upgrade" : "websocket",
        "Connection" : "Upgrade",
        "Sec-WebSocket-Accept" : sec_websocket_accept_value.decode()
    })

    client_socket.send(websocket_response.get_response_string())

def generate_sec_websocket_accept(sec_websocket_key):
    combined = sec_websocket_key + MAGIC_WEBSOCKET_UUID_STRING
    hashed_combined_string = hashlib.sha1(combined.encode())
    encoded = base64.b64encode(hashed_combined_string.digest())
    return encoded

def is_valid_ws_handshake_request(req):
    is_get = req.method == 'GET'

    http_version_number = float(req.http_version.split('/')[1])
    http_version_enough = http_version_number >= 1.1
    
    headers_valid = (
        ('upgrade' in req.headers and
         req.headers.get('upgrade') == 'websocket') and
        ('connection' in req.headers and
         req.headers.get('connection') == 'Upgrade') and
        ('sec-websocket-key' in req.headers)
    )
    return (is_get and http_version_enough and headers_valid)

def close_socket(client_socket, input_sockets, ws_sockets):
    if client_socket in ws_sockets:
        ws_sockets.remove(client_socket)
    input_sockets.remove(client_socket)
    client_socket.close()
    return


if __name__ == '__main__':
    main()