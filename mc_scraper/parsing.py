from enum import Enum
from datetime import datetime


# Constants
MAX_PATH_SIZE = 64
MAX_PACKET_PAYLOAD = 184


# Route Type Values
class RouteType(Enum):
    ROUTE_TYPE_TRANSPORT_FLOOD = 0x00
    ROUTE_TYPE_FLOOD = 0x01
    ROUTE_TYPE_DIRECT = 0x02
    ROUTE_TYPE_TRANSPORT_DIRECT = 0x03


# Payload Type Values
class PayloadType(Enum):
    PAYLOAD_TYPE_REQ = 0x00
    PAYLOAD_TYPE_RESPONSE = 0x01
    PAYLOAD_TYPE_TXT_MSG = 0x02
    PAYLOAD_TYPE_ACK = 0x03
    PAYLOAD_TYPE_ADVERT = 0x04
    PAYLOAD_TYPE_GRP_TXT = 0x05
    PAYLOAD_TYPE_GRP_DATA = 0x06
    PAYLOAD_TYPE_ANON_REQ = 0x07
    PAYLOAD_TYPE_PATH = 0x08
    PAYLOAD_TYPE_TRACE = 0x09
    PAYLOAD_TYPE_MULTIPART = 0x0A
    PAYLOAD_TYPE_CONTROL = 0x0B
    PAYLOAD_TYPE_RESERVED1 = 0x0C
    PAYLOAD_TYPE_RESERVED2 = 0x0D
    PAYLOAD_TYPE_RESERVED3 = 0x0E
    PAYLOAD_TYPE_RAW_CUSTOM = 0x0F


# Payload Version Values
class PayloadVersion(Enum):
    PAYLOAD_VERSION_1 = 0x00
    PAYLOAD_VERSION_2 = 0x01
    PAYLOAD_VERSION_3 = 0x02
    PAYLOAD_VERSION_4 = 0x03


def parse_mc_packet(pkt: bytes) -> dict[str, str]:
    header_f, payload_type, payload = parse_mc_header(pkt)
    payload_f = parse_payload(payload_type, payload)
    return header_f | payload_f


def extract_header(byte: int):
    payload_v = PayloadVersion((byte >> 6) & 0b11)
    payload_t = PayloadType((byte >> 2) & 0b1111)
    route_t = RouteType(byte & 0b11)
    return [route_t, payload_t, payload_v]


def parse_mc_header(bytes: bytes) -> tuple[dict[str, str], PayloadType, bytes]:
    bytes_parsed = 0

    # Parse Header
    header = extract_header(bytes[bytes_parsed])
    bytes_parsed += 1

    # Parse Transport Codes (Optional)
    if header[0] in [
        RouteType.ROUTE_TYPE_TRANSPORT_FLOOD,
        RouteType.ROUTE_TYPE_TRANSPORT_DIRECT,
    ]:
        transport_codes = [bytes[bytes_parsed + idx] for idx in range(4)]
        bytes_parsed += 4
    else:
        transport_codes = []
        bytes_parsed += 0

    # Parse Path Len
    path_len = bytes[bytes_parsed]
    bytes_parsed += 1

    # Parse Path
    path = [bytes[bytes_parsed + idx] for idx in range(path_len)]
    bytes_parsed += path_len

    # Parse Payload
    payload = bytes[bytes_parsed:]

    # Create return struct
    header_dict: dict[str, str] = {
        "header_route_type": header[0].name,
        "header_payload_type": header[1].name,
        "header_payload_version": header[2].name,
        "header_transport_codes": str(transport_codes),
        "header_path_len": str(path_len),
        "header_path": str([hex(item) for item in path]),
        "header_len": str(bytes_parsed),
    }

    return (header_dict, header[1], payload)


def parse_payload(paylod_type: PayloadType, payload: bytes) -> dict[str, str]:
    try:
        match paylod_type:
            case PayloadType.PAYLOAD_TYPE_REQ:
                return _parse_request(payload)
            case PayloadType.PAYLOAD_TYPE_RESPONSE:
                return _parse_response(payload)
            case PayloadType.PAYLOAD_TYPE_TXT_MSG:
                return _parse_plain_text_message(payload)
            case PayloadType.PAYLOAD_TYPE_ACK:
                return _parse_ack(payload)
            case PayloadType.PAYLOAD_TYPE_ADVERT:
                return _parse_advertisement(payload)
            case PayloadType.PAYLOAD_TYPE_GRP_TXT:
                return _parse_group_text_data_message(payload)
            case PayloadType.PAYLOAD_TYPE_GRP_DATA:
                return _parse_group_text_data_message(payload)
            case PayloadType.PAYLOAD_TYPE_ANON_REQ:
                return _parse_anonymous_request(payload)
            case PayloadType.PAYLOAD_TYPE_PATH:
                return _parse_return_path(payload)
            case PayloadType.PAYLOAD_TYPE_TRACE:
                return {"payload_error": "unimplemented"}
            case PayloadType.PAYLOAD_TYPE_MULTIPART:
                return {"payload_error": "unimplemented"}
            case PayloadType.PAYLOAD_TYPE_CONTROL:
                return _parse_control_data(payload)
            case PayloadType.PAYLOAD_TYPE_RESERVED1:
                return {"payload_error": "unimplemented"}
            case PayloadType.PAYLOAD_TYPE_RESERVED2:
                return {"payload_error": "unimplemented"}
            case PayloadType.PAYLOAD_TYPE_RESERVED3:
                return {"payload_error": "unimplemented"}
            case PayloadType.PAYLOAD_TYPE_RAW_CUSTOM:
                return {"payload_error": "unimplemented"}
            case _:
                return {"payload_error": "unimplemented"}

    except Exception as e:
        return {f"payload_error": "Error parsing payload ({e})"}


def _parse_control_data(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    flags = payload[bytes_parsed]
    flag_type_b = flags >> 4
    bytes_parsed += 1

    if flag_type_b == 0x08:
        flag_type = "DISCOVER_REQ"
        prefix_only = flags * 0x0F

        type_filter = payload[bytes_parsed]
        bytes_parsed += 1
        tag = payload[bytes_parsed : bytes_parsed + 4]
        bytes_parsed += 4
        since = payload[bytes_parsed:]

        return {
            "payload_flag_type": flag_type,
            "payload_prefix_only": hex(prefix_only),
            "payload_type_filter": hex(type_filter),
            "payload_tag": tag.hex(),
            "payload_since": since.hex(),
        }

    elif flag_type_b == 0x09:
        flag_type = "DISCOVER_RESP"
        node_type = flags * 0x0F

        snr = payload[bytes_parsed]
        bytes_parsed += 1
        tag = payload[bytes_parsed : bytes_parsed + 4]
        bytes_parsed += 4
        pub_key = payload[bytes_parsed:]

        return {
            "payload_flag_type": flag_type,
            "payload_node_type": hex(node_type),
            "payload_snr": str(int(snr) / 4),
            "payload_tag": tag.hex(),
            "payload_pub_key": pub_key.hex(),
        }

    return {
        "payload_flag_type": "unkown",
        "payload_raw": payload[bytes_parsed:].hex(),
    }


def _parse_group_text_data_message(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    channel_hash = payload[bytes_parsed]
    bytes_parsed += 1
    cipher_mac = payload[bytes_parsed : bytes_parsed + 2]
    bytes_parsed += 2
    ciphertext = payload[bytes_parsed:]

    # TODO: implement cipher text sublayers. Same format as for plaintext, but decryption is needed

    return {
        "payload_destination_hash": hex(channel_hash),
        "payload_cipher_mac": cipher_mac.hex(),
        "payload_ciphertext": ciphertext.hex(),
    }


def _parse_anonymous_request(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    destination_hash = payload[bytes_parsed]
    bytes_parsed += 1
    public_key = payload[bytes_parsed : bytes_parsed + 32]
    bytes_parsed += 32
    cipher_mac = payload[bytes_parsed : bytes_parsed + 2]
    bytes_parsed += 2
    ciphertext = payload[bytes_parsed:]

    # TODO: Implement Room server login and Repeater/Sensor login format
    # Skipped for now since the data is encrypted anyway
    # https://github.com/meshcore-dev/MeshCore/blob/main/docs/payloads.md#room-server-login

    return {
        "payload_destination_hash": hex(destination_hash),
        "payload_public_key": public_key.hex(),
        "payload_cipher_mac": cipher_mac.hex(),
        "payload_ciphertext": ciphertext.hex(),
    }


def _parse_plain_text_message(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    destination_hash = payload[bytes_parsed]
    bytes_parsed += 1
    source_hash = payload[bytes_parsed]
    bytes_parsed += 1
    cipher_mac = payload[bytes_parsed : bytes_parsed + 2]
    bytes_parsed += 2

    timestamp_b = payload[bytes_parsed : bytes_parsed + 4]
    timestamp = datetime.fromtimestamp(
        int.from_bytes(timestamp_b, byteorder="little")
    ).strftime("%Y-%m-%d %H:%M:%S")
    bytes_parsed += 4

    txt_types = {
        0x00: "plain_text_message",
        0x01: "cli_command",
        0x02: "signed_plain_text_message",
    }
    txt_type_attempt = payload[bytes_parsed]
    txt_type_b = txt_type_attempt >> 3
    attempt = txt_type_attempt & 0x07
    try:
        txt_type = txt_types[txt_type_b]
    except:
        txt_type = f"unknown : {hex(txt_type_b)}"
    bytes_parsed += 1

    signiture = b""
    if txt_type == "signed_plain_text_message":
        signiture = payload[bytes_parsed : bytes_parsed + 4]
        bytes_parsed += 4

    message = payload[bytes_parsed:]

    ret = {
        "payload_destination_hash": hex(destination_hash),
        "payload_source_hash": hex(source_hash),
        "payload_cipher_mac": cipher_mac.hex(),
        "payload_timestamp": timestamp,
        "payload_txt_type": txt_type,
        "payload_attempt": str(attempt),
        "payload_message": str(message),
    }
    if txt_type == "signed_plain_text_message":
        ret["payload_signiture"] = signiture.hex()

    return ret


def _parse_response(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    destination_hash = payload[bytes_parsed]
    bytes_parsed += 1
    source_hash = payload[bytes_parsed]
    bytes_parsed += 1
    cipher_mac = payload[bytes_parsed : bytes_parsed + 2]
    bytes_parsed += 2

    tag = payload[bytes_parsed : bytes_parsed + 4]
    bytes_parsed += 4
    content = payload[bytes_parsed:]

    return {
        "payload_destination_hash": hex(destination_hash),
        "payload_source_hash": hex(source_hash),
        "payload_cipher_mac": cipher_mac.hex(),
        "payload_tag": tag.hex(),
        "payload_content": content.hex(),
    }


def _parse_request(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    destination_hash = payload[bytes_parsed]
    bytes_parsed += 1
    source_hash = payload[bytes_parsed]
    bytes_parsed += 1
    cipher_mac = payload[bytes_parsed : bytes_parsed + 2]
    bytes_parsed += 2

    timestamp_b = payload[bytes_parsed : bytes_parsed + 4]
    timestamp = datetime.fromtimestamp(
        int.from_bytes(timestamp_b, byteorder="little")
    ).strftime("%Y-%m-%d %H:%M:%S")
    bytes_parsed += 4

    request_types = {
        0x01: "get_stats",
        0x02: "keepalive",
        0x03: "get_telemetry_data",
        0x04: "get_mma_data",
        0x05: "get_access_list",
    }
    request_type_b = payload[bytes_parsed]
    try:
        request_type = request_types[request_type_b]
    except:
        request_type = f"unknown : {hex(request_type_b)}"
    bytes_parsed += 1
    request_data = payload[bytes_parsed:]

    return {
        "payload_destination_hash": hex(destination_hash),
        "payload_source_hash": hex(source_hash),
        "payload_cipher_mac": cipher_mac.hex(),
        "payload_timestamp": timestamp,
        "payload_request_type": request_type,
        "payload_request_data": request_data.hex(),
    }


def _parse_return_path(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    destination_hash = payload[bytes_parsed]
    bytes_parsed += 1
    source_hash = payload[bytes_parsed]
    bytes_parsed += 1
    cipher_mac = payload[bytes_parsed : bytes_parsed + 2]
    bytes_parsed += 2

    path_len = int(payload[bytes_parsed])
    bytes_parsed += 1
    path = payload[bytes_parsed : bytes_parsed + path_len]
    bytes_parsed += path_len
    extra_type = PayloadType(payload[bytes_parsed])
    bytes_parsed += 1
    extra_data = payload[bytes_parsed:]

    return {
        "payload_destination_hash": hex(destination_hash),
        "payload_source_hash": hex(source_hash),
        "payload_cipher_mac": cipher_mac.hex(),
        "payload_path_len": str(path_len),
        "payload_path": str([hex(item) for item in path]),
        "payload_extra_type": extra_type.name,
        "payload_extra_data": extra_data.hex(),
    }


def _parse_ack(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    checksum = payload[bytes_parsed : bytes_parsed + 4]
    bytes_parsed += 4
    raw = payload[bytes_parsed:]
    ret = {"payload_checksum": checksum.hex()}
    if len(raw) > 0:
        ret["payload_raw"] = raw.hex()
    return ret


def _parse_advertisement(payload: bytes) -> dict[str, str]:
    bytes_parsed = 0
    public_key = payload[bytes_parsed : bytes_parsed + 32]
    bytes_parsed += 32
    timestamp = payload[bytes_parsed : bytes_parsed + 4]
    bytes_parsed += 4
    signature = payload[bytes_parsed : bytes_parsed + 64]
    bytes_parsed += 64
    appdata = payload[bytes_parsed:]

    appdata_f = _parse_appdata(appdata)
    payload_f = {
        "payload_public_key": public_key.hex(),
        "payload_timestamp": datetime.fromtimestamp(
            int.from_bytes(timestamp, byteorder="little")
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "payload_signature": signature.hex(),
        "payload_appdata": appdata.hex(),
    }

    return payload_f | appdata_f


def _parse_appdata(appdata: bytes) -> dict[str, str]:
    bytes_parsed = 0

    # Parse flags
    flags = appdata[0]
    bytes_parsed += 1
    is_chat_node = bool((flags & 0xF) == 0x01)
    is_repeater = bool((flags & 0xF) == 0x02)
    is_room_server = bool((flags & 0xF) == 0x03)
    is_sensor = bool((flags & 0xF) == 0x04)
    has_location = bool(flags & 0x10)
    has_feature_1 = bool(flags & 0x20)
    has_feature_2 = bool(flags & 0x40)
    has_name = bool(flags & 0x80)

    # Parse long lat and reserved features
    latitude = ""
    longitude = ""
    feature_1 = ""
    feature_2 = ""
    if has_location:
        lat = int.from_bytes(appdata[bytes_parsed : bytes_parsed + 4])
        latitude = str(lat / 1000000)
        bytes_parsed += 4
        lon = int.from_bytes(appdata[bytes_parsed : bytes_parsed + 4])
        longitude = str(lon / 1000000)
        bytes_parsed += 4
    if has_feature_1:
        feature_1 = appdata[bytes_parsed : bytes_parsed + 2].hex()
        bytes_parsed += 2
    if has_feature_2:
        feature_2 = appdata[bytes_parsed : bytes_parsed + 2].hex()
        bytes_parsed += 2
    # Parse name
    name = str(appdata[bytes_parsed:])

    return {
        "payload_appdata_flag_is_chat_node": str(is_chat_node),
        "payload_appdata_flag_is_repeater": str(is_repeater),
        "payload_appdata_flag_is_room_server": str(is_room_server),
        "payload_appdata_flag_is_sensor": str(is_sensor),
        "payload_appdata_flag_has_location": str(has_location),
        "payload_appdata_flag_has_feature_1": str(has_feature_1),
        "payload_appdata_flag_has_name": str(has_name),
        "payload_appdata_latitude": latitude,
        "payload_appdata_longitude": longitude,
        "payload_appdata_feature_1": feature_1,
        "payload_appdata_feature_2": feature_2,
        "payload_appdata_name": name,
    }
