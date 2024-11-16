import socket

def pack_varint(value):
    out = bytearray()
    while True:
        temp = value & 0b01111111
        value >>= 7
        if value != 0:
            temp |= 0b10000000
        out.append(temp)
        if value == 0:
            break
    return out

def pack_string(value):
    encoded = value.encode('utf-8')
    length = pack_varint(len(encoded))
    return length + encoded

def pack_unsigned_short(value):
    return value.to_bytes(2, byteorder='big')

def create_handshake_packet(ip, port=25565, protocol_version=47):
    packet_id = pack_varint(0x00)
    protocol_version = pack_varint(protocol_version)
    server_address = pack_string(ip)
    server_port = pack_unsigned_short(port)
    next_state = pack_varint(1)

    data = packet_id + protocol_version + server_address + server_port + next_state

    packet_length = pack_varint(len(data))
    packet = packet_length + data
    return packet

def create_status_request_packet():
    packet_id = pack_varint(0x00)
    data = packet_id
    packet_length = pack_varint(len(data))
    packet = packet_length + data
    return packet

def read_varint(s):
    num_read = 0
    result = 0
    while True:
        byte = s.recv(1)
        if not byte:
            raise EOFError('Unexpected EOF while reading varint')
        byte_value = byte[0]
        value = byte_value & 0b01111111
        result |= value << (7 * num_read)
        num_read += 1
        if num_read > 5:
            raise ValueError('VarInt is too big')
        if (byte_value & 0b10000000) == 0:
            break
    return result

def read_bytes(s, length):
    data = bytearray()
    while len(data) < length:
        packet = s.recv(length - len(data))
        if not packet:
            raise EOFError('Unexpected EOF while reading bytes')
        data.extend(packet)
    return data

def ping_server(ip, port=25565):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)  # 2 second timeout
        s.connect((ip, port))

        handshake_packet = create_handshake_packet(ip, port)
        s.sendall(handshake_packet)

        status_request_packet = create_status_request_packet()
        s.sendall(status_request_packet)

        # Read the response
        packet_length = read_varint(s)
        packet_id = read_varint(s)

        if packet_id != 0x00:
            return False

        # Read the string (JSON response)
        json_length = read_varint(s)
        json_response = read_bytes(s, json_length)
        json_response = json_response.decode('utf-8')

        # Server responded correctly
        return True

    except (socket.timeout, socket.error, EOFError):
        return False
    except Exception as e:
        return False
    finally:
        s.close()

ip = 'sherbit.net'
if ping_server(ip):
    print(f"Successfully connected to {ip}: It is a Minecraft server.")
else:
    print(f"Failed to connect to {ip}: It is not a Minecraft server or is unreachable.")
