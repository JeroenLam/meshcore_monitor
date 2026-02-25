// Enum definitions
const RouteType = {
    ROUTE_TYPE_TRANSPORT_FLOOD: 0x00,
    ROUTE_TYPE_FLOOD: 0x01,
    ROUTE_TYPE_DIRECT: 0x02,
    ROUTE_TYPE_TRANSPORT_DIRECT: 0x03,
};

const RouteTypeName = {
    0x00: "ROUTE_TYPE_TRANSPORT_FLOOD",
    0x01: "ROUTE_TYPE_FLOOD",
    0x02: "ROUTE_TYPE_DIRECT",
    0x03: "ROUTE_TYPE_TRANSPORT_DIRECT",
};

const PayloadType = {
    PAYLOAD_TYPE_REQ: 0x00,
    PAYLOAD_TYPE_RESPONSE: 0x01,
    PAYLOAD_TYPE_TXT_MSG: 0x02,
    PAYLOAD_TYPE_ACK: 0x03,
    PAYLOAD_TYPE_ADVERT: 0x04,
    PAYLOAD_TYPE_GRP_TXT: 0x05,
    PAYLOAD_TYPE_GRP_DATA: 0x06,
    PAYLOAD_TYPE_ANON_REQ: 0x07,
    PAYLOAD_TYPE_PATH: 0x08,
    PAYLOAD_TYPE_TRACE: 0x09,
    PAYLOAD_TYPE_MULTIPART: 0x0a,
    PAYLOAD_TYPE_CONTROL: 0x0b,
    PAYLOAD_TYPE_RESERVED1: 0x0c,
    PAYLOAD_TYPE_RESERVED2: 0x0d,
    PAYLOAD_TYPE_RESERVED3: 0x0e,
    PAYLOAD_TYPE_RAW_CUSTOM: 0x0f,
};

const PayloadTypeName = {
    0x00: "PAYLOAD_TYPE_REQ",
    0x01: "PAYLOAD_TYPE_RESPONSE",
    0x02: "PAYLOAD_TYPE_TXT_MSG",
    0x03: "PAYLOAD_TYPE_ACK",
    0x04: "PAYLOAD_TYPE_ADVERT",
    0x05: "PAYLOAD_TYPE_GRP_TXT",
    0x06: "PAYLOAD_TYPE_GRP_DATA",
    0x07: "PAYLOAD_TYPE_ANON_REQ",
    0x08: "PAYLOAD_TYPE_PATH",
    0x09: "PAYLOAD_TYPE_TRACE",
    0x0a: "PAYLOAD_TYPE_MULTIPART",
    0x0b: "PAYLOAD_TYPE_CONTROL",
    0x0c: "PAYLOAD_TYPE_RESERVED1",
    0x0d: "PAYLOAD_TYPE_RESERVED2",
    0x0e: "PAYLOAD_TYPE_RESERVED3",
    0x0f: "PAYLOAD_TYPE_RAW_CUSTOM",
};

const PayloadVersion = {
    PAYLOAD_VERSION_1: 0x00,
    PAYLOAD_VERSION_2: 0x01,
    PAYLOAD_VERSION_3: 0x02,
    PAYLOAD_VERSION_4: 0x03,
};

const PayloadVersionName = {
    0x00: "PAYLOAD_VERSION_1",
    0x01: "PAYLOAD_VERSION_2",
    0x02: "PAYLOAD_VERSION_3",
    0x03: "PAYLOAD_VERSION_4",
};

// Helper function to convert hex string to bytes
function hexStringToBytes(hexString) {
    // Remove spaces and convert to lowercase
    const cleanHex = hexString.replace(/\s/g, "").toLowerCase();

    // Check if valid hex
    if (!/^[0-9a-f]*$/.test(cleanHex)) {
        throw new Error("Invalid hex string");
    }

    // Check if even length
    if (cleanHex.length % 2 !== 0) {
        throw new Error("Hex string must have even length");
    }

    const bytes = [];
    for (let i = 0; i < cleanHex.length; i += 2) {
        bytes.push(parseInt(cleanHex.substr(i, 2), 16));
    }
    return bytes;
}

// Extract header information from first byte
function extractHeader(byte) {
    const payloadVersion = (byte >> 6) & 0b11;
    const payloadType = (byte >> 2) & 0b1111;
    const routeType = byte & 0b11;
    return [routeType, payloadType, payloadVersion];
}

// Parse MC header
function parseMcHeader(bytes) {
    let bytesParsed = 0;

    // Parse Header
    const header = extractHeader(bytes[bytesParsed]);
    bytesParsed += 1;

    // Parse Transport Codes (Optional)
    let transportCodes = [];
    if (
        header[0] === RouteType.ROUTE_TYPE_TRANSPORT_FLOOD ||
        header[0] === RouteType.ROUTE_TYPE_TRANSPORT_DIRECT
    ) {
        transportCodes = [
            bytes[bytesParsed],
            bytes[bytesParsed + 1],
            bytes[bytesParsed + 2],
            bytes[bytesParsed + 3],
        ];
        bytesParsed += 4;
    }

    // Parse Path Len
    const pathLen = bytes[bytesParsed];
    bytesParsed += 1;

    // Parse Path
    const path = [];
    for (let i = 0; i < pathLen; i++) {
        path.push(bytes[bytesParsed + i]);
    }
    bytesParsed += pathLen;

    // Parse Payload
    const payload = bytes.slice(bytesParsed);

    // Create return struct
    const headerDict = {
        header_route_type: RouteTypeName[header[0]],
        header_payload_type: PayloadTypeName[header[1]],
        header_payload_version: PayloadVersionName[header[2]],
        header_transport_codes: transportCodes.map((b) => "0x" + b.toString(16).padStart(2, "0")),
        header_path_len: pathLen,
        header_path: path.map((b) => "0x" + b.toString(16).padStart(2, "0")),
        header_len: bytesParsed,
    };

    return [headerDict, header[1], payload];
}

// Parse plain text message
function parsePlainTextMessage(payload) {
    let bytesParsed = 0;
    const destinationHash = payload[bytesParsed];
    bytesParsed += 1;
    const sourceHash = payload[bytesParsed];
    bytesParsed += 1;
    const cipherMac = payload.slice(bytesParsed, bytesParsed + 2);
    bytesParsed += 2;

    const timestampB = payload.slice(bytesParsed, bytesParsed + 4);
    const timestamp = new Date(
        bytesToInt32LE(timestampB) * 1000
    ).toISOString();
    bytesParsed += 4;

    const txtTypes = {
        0x00: "plain_text_message",
        0x01: "cli_command",
        0x02: "signed_plain_text_message",
    };
    const txtTypeAttempt = payload[bytesParsed];
    const txtTypeB = txtTypeAttempt >> 3;
    const attempt = txtTypeAttempt & 0x07;
    const txtType = txtTypes[txtTypeB] || `unknown: 0x${txtTypeB.toString(16)}`;
    bytesParsed += 1;

    let signature = "";
    if (txtType === "signed_plain_text_message") {
        signature = bytesToHex(payload.slice(bytesParsed, bytesParsed + 4));
        bytesParsed += 4;
    }

    const message = bytesToString(payload.slice(bytesParsed));

    const ret = {
        destination_hash: "0x" + destinationHash.toString(16).padStart(2, "0"),
        source_hash: "0x" + sourceHash.toString(16).padStart(2, "0"),
        cipher_mac: bytesToHex(cipherMac),
        timestamp: timestamp,
        txt_type: txtType,
        attempt: attempt,
        message: message,
    };

    if (txtType === "signed_plain_text_message") {
        ret.signature = signature;
    }

    return ret;
}

// Parse request
function parseRequest(payload) {
    let bytesParsed = 0;
    const destinationHash = payload[bytesParsed];
    bytesParsed += 1;
    const sourceHash = payload[bytesParsed];
    bytesParsed += 1;
    const cipherMac = payload.slice(bytesParsed, bytesParsed + 2);
    bytesParsed += 2;

    const timestampB = payload.slice(bytesParsed, bytesParsed + 4);
    const timestamp = new Date(
        bytesToInt32LE(timestampB) * 1000
    ).toISOString();
    bytesParsed += 4;

    const requestTypes = {
        0x01: "get_stats",
        0x02: "keepalive",
        0x03: "get_telemetry_data",
        0x04: "get_mma_data",
        0x05: "get_access_list",
    };
    const requestTypeB = payload[bytesParsed];
    const requestType =
        requestTypes[requestTypeB] || `unknown: 0x${requestTypeB.toString(16)}`;
    bytesParsed += 1;
    const requestData = bytesToHex(payload.slice(bytesParsed));

    return {
        destination_hash: "0x" + destinationHash.toString(16).padStart(2, "0"),
        source_hash: "0x" + sourceHash.toString(16).padStart(2, "0"),
        cipher_mac: bytesToHex(cipherMac),
        timestamp: timestamp,
        request_type: requestType,
        request_data: requestData,
    };
}

// Parse response
function parseResponse(payload) {
    let bytesParsed = 0;
    const destinationHash = payload[bytesParsed];
    bytesParsed += 1;
    const sourceHash = payload[bytesParsed];
    bytesParsed += 1;
    const cipherMac = payload.slice(bytesParsed, bytesParsed + 2);
    bytesParsed += 2;

    const tag = payload.slice(bytesParsed, bytesParsed + 4);
    bytesParsed += 4;
    const content = bytesToHex(payload.slice(bytesParsed));

    return {
        destination_hash: "0x" + destinationHash.toString(16).padStart(2, "0"),
        source_hash: "0x" + sourceHash.toString(16).padStart(2, "0"),
        cipher_mac: bytesToHex(cipherMac),
        tag: bytesToHex(tag),
        content: content,
    };
}

// Parse ACK
function parseAck(payload) {
    let bytesParsed = 0;
    const checksum = bytesToHex(payload.slice(bytesParsed, bytesParsed + 4));
    bytesParsed += 4;
    const raw = bytesToHex(payload.slice(bytesParsed));

    const ret = {
        checksum: checksum,
    };
    if (raw.length > 0) {
        ret.raw = raw;
    }
    return ret;
}

// Parse advertisement
function parseAdvertisement(payload) {
    let bytesParsed = 0;
    const publicKey = bytesToHex(payload.slice(bytesParsed, bytesParsed + 32));
    bytesParsed += 32;
    const timestamp = new Date(
        bytesToInt32LE(payload.slice(bytesParsed, bytesParsed + 4)) * 1000
    ).toISOString();
    bytesParsed += 4;
    const signature = bytesToHex(payload.slice(bytesParsed, bytesParsed + 64));
    bytesParsed += 64;
    const appdata = payload.slice(bytesParsed);

    const appdataF = parseAppdata(appdata);
    const payloadF = {
        public_key: publicKey,
        timestamp: timestamp,
        signature: signature,
        appdata: bytesToHex(appdata),
    };

    return { ...payloadF, ...appdataF };
}

// Parse appdata
function parseAppdata(appdata) {
    let bytesParsed = 0;

    // Parse flags
    const flags = appdata[0];
    bytesParsed += 1;
    const isChatNode = (flags & 0xf) === 0x01;
    const isRepeater = (flags & 0xf) === 0x02;
    const isRoomServer = (flags & 0xf) === 0x03;
    const isSensor = (flags & 0xf) === 0x04;
    const hasLocation = !!(flags & 0x10);
    const hasFeature1 = !!(flags & 0x20);
    const hasFeature2 = !!(flags & 0x40);
    const hasName = !!(flags & 0x80);

    // Parse lat/lon and features
    let latitude = "";
    let longitude = "";
    let feature1 = "";
    let feature2 = "";

    if (hasLocation) {
        const lat = bytesToInt32LE(appdata.slice(bytesParsed, bytesParsed + 4));
        latitude = (lat / 1000000).toString();
        bytesParsed += 4;
        const lon = bytesToInt32LE(appdata.slice(bytesParsed, bytesParsed + 4));
        longitude = (lon / 1000000).toString();
        bytesParsed += 4;
    }
    if (hasFeature1) {
        feature1 = bytesToHex(appdata.slice(bytesParsed, bytesParsed + 2));
        bytesParsed += 2;
    }
    if (hasFeature2) {
        feature2 = bytesToHex(appdata.slice(bytesParsed, bytesParsed + 2));
        bytesParsed += 2;
    }

    const name = bytesToString(appdata.slice(bytesParsed));

    return {
        appdata_flag_is_chat_node: isChatNode,
        appdata_flag_is_repeater: isRepeater,
        appdata_flag_is_room_server: isRoomServer,
        appdata_flag_is_sensor: isSensor,
        appdata_flag_has_location: hasLocation,
        appdata_flag_has_feature_1: hasFeature1,
        appdata_flag_has_feature_2: hasFeature2,
        appdata_latitude: latitude,
        appdata_longitude: longitude,
        appdata_feature_1: feature1,
        appdata_feature_2: feature2,
        appdata_name: name,
    };
}

// Parse anonymous request
function parseAnonymousRequest(payload) {
    let bytesParsed = 0;
    const destinationHash = payload[bytesParsed];
    bytesParsed += 1;
    const publicKey = bytesToHex(payload.slice(bytesParsed, bytesParsed + 32));
    bytesParsed += 32;
    const cipherMac = bytesToHex(payload.slice(bytesParsed, bytesParsed + 2));
    bytesParsed += 2;
    const ciphertext = bytesToHex(payload.slice(bytesParsed));

    return {
        destination_hash: "0x" + destinationHash.toString(16).padStart(2, "0"),
        public_key: publicKey,
        cipher_mac: cipherMac,
        ciphertext: ciphertext,
    };
}

// Parse group text/data message
function parseGroupTextDataMessage(payload) {
    let bytesParsed = 0;
    const channelHash = payload[bytesParsed];
    bytesParsed += 1;
    const cipherMac = bytesToHex(payload.slice(bytesParsed, bytesParsed + 2));
    bytesParsed += 2;
    const ciphertext = bytesToHex(payload.slice(bytesParsed));

    return {
        destination_hash: "0x" + channelHash.toString(16).padStart(2, "0"),
        cipher_mac: cipherMac,
        ciphertext: ciphertext,
    };
}

// Parse return path
function parseReturnPath(payload) {
    let bytesParsed = 0;
    const destinationHash = payload[bytesParsed];
    bytesParsed += 1;
    const sourceHash = payload[bytesParsed];
    bytesParsed += 1;
    const cipherMac = bytesToHex(payload.slice(bytesParsed, bytesParsed + 2));
    bytesParsed += 2;

    const pathLen = payload[bytesParsed];
    bytesParsed += 1;
    const path = [];
    for (let i = 0; i < pathLen; i++) {
        path.push("0x" + payload[bytesParsed + i].toString(16).padStart(2, "0"));
    }
    bytesParsed += pathLen;
    const extraType = payload[bytesParsed];
    bytesParsed += 1;
    const extraData = bytesToHex(payload.slice(bytesParsed));

    return {
        destination_hash: "0x" + destinationHash.toString(16).padStart(2, "0"),
        source_hash: "0x" + sourceHash.toString(16).padStart(2, "0"),
        cipher_mac: cipherMac,
        path_len: pathLen,
        path: path,
        extra_type: PayloadTypeName[extraType] || `unknown: 0x${extraType.toString(16)}`,
        extra_data: extraData,
    };
}

// Parse control data
function parseControlData(payload) {
    let bytesParsed = 0;
    const flags = payload[bytesParsed];
    const flagTypeB = flags >> 4;
    bytesParsed += 1;

    if (flagTypeB === 0x08) {
        const flagType = "DISCOVER_REQ";
        const prefixOnly = flags & 0x0f;

        const typeFilter = payload[bytesParsed];
        bytesParsed += 1;
        const tag = bytesToHex(payload.slice(bytesParsed, bytesParsed + 4));
        bytesParsed += 4;
        const since = bytesToHex(payload.slice(bytesParsed));

        return {
            flag_type: flagType,
            prefix_only: "0x" + prefixOnly.toString(16).padStart(2, "0"),
            type_filter: "0x" + typeFilter.toString(16).padStart(2, "0"),
            tag: tag,
            since: since,
        };
    } else if (flagTypeB === 0x09) {
        const flagType = "DISCOVER_RESP";
        const nodeType = flags & 0x0f;

        const snr = payload[bytesParsed];
        bytesParsed += 1;
        const tag = bytesToHex(payload.slice(bytesParsed, bytesParsed + 4));
        bytesParsed += 4;
        const pubKey = bytesToHex(payload.slice(bytesParsed));

        return {
            flag_type: flagType,
            node_type: "0x" + nodeType.toString(16).padStart(2, "0"),
            snr: (snr / 4).toString(),
            tag: tag,
            pub_key: pubKey,
        };
    }

    return {
        flag_type: "unknown",
        raw: bytesToHex(payload.slice(bytesParsed)),
    };
}

// Parse payload based on type
function parsePayload(payloadType, payload) {
    try {
        switch (payloadType) {
            case PayloadType.PAYLOAD_TYPE_REQ:
                return parseRequest(payload);
            case PayloadType.PAYLOAD_TYPE_RESPONSE:
                return parseResponse(payload);
            case PayloadType.PAYLOAD_TYPE_TXT_MSG:
                return parsePlainTextMessage(payload);
            case PayloadType.PAYLOAD_TYPE_ACK:
                return parseAck(payload);
            case PayloadType.PAYLOAD_TYPE_ADVERT:
                return parseAdvertisement(payload);
            case PayloadType.PAYLOAD_TYPE_GRP_TXT:
            case PayloadType.PAYLOAD_TYPE_GRP_DATA:
                return parseGroupTextDataMessage(payload);
            case PayloadType.PAYLOAD_TYPE_ANON_REQ:
                return parseAnonymousRequest(payload);
            case PayloadType.PAYLOAD_TYPE_PATH:
                return parseReturnPath(payload);
            case PayloadType.PAYLOAD_TYPE_CONTROL:
                return parseControlData(payload);
            case PayloadType.PAYLOAD_TYPE_TRACE:
            case PayloadType.PAYLOAD_TYPE_MULTIPART:
            case PayloadType.PAYLOAD_TYPE_RESERVED1:
            case PayloadType.PAYLOAD_TYPE_RESERVED2:
            case PayloadType.PAYLOAD_TYPE_RESERVED3:
            case PayloadType.PAYLOAD_TYPE_RAW_CUSTOM:
                return { payload_error: "unimplemented" };
            default:
                return { payload_error: "unimplemented" };
        }
    } catch (e) {
        return { payload_error: `Error parsing payload (${e.message})` };
    }
}

// Main parsing function
function parseMcPacket(pkt) {
    const [headerF, payloadType, payload] = parseMcHeader(pkt);
    const payloadF = parsePayload(payloadType, payload);
    return { ...headerF, ...payloadF };
}

// Helper functions
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

function bytesToString(bytes) {
    return String.fromCharCode.apply(null, bytes);
}

function bytesToInt32LE(bytes) {
    return (
        bytes[0] |
        (bytes[1] << 8) |
        (bytes[2] << 16) |
        (bytes[3] << 24)
    );
}

// Decryption functions
function decryptGroupText(ciphertext, channelName) {
    try {
        // Derive key from channel name using SHA256
        const hash = CryptoJS.SHA256(channelName);
        // Take first 16 bytes (32 hex chars) for AES-128
        const keyHex = hash.toString().substring(0, 32);
        const key = CryptoJS.enc.Hex.parse(keyHex);

        // Convert ciphertext hex string to CryptoJS format
        const ciphertextWords = CryptoJS.enc.Hex.parse(ciphertext);

        // Decrypt using AES-ECB
        const decrypted = CryptoJS.AES.decrypt(
            { ciphertext: ciphertextWords },
            key,
            {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.NoPadding
            }
        );

        // Convert decrypted data to bytes
        const decryptedHex = decrypted.toString(CryptoJS.enc.Hex);
        const decryptedBytes = [];
        for (let i = 0; i < decryptedHex.length; i += 2) {
            decryptedBytes.push(parseInt(decryptedHex.substr(i, 2), 16));
        }

        // Extract timestamp (4 bytes, little-endian)
        const timestamp = bytesToInt32LE(decryptedBytes.slice(0, 4));
        const timestampStr = new Date(timestamp * 1000).toISOString();

        // Extract flags (1 byte)
        const flags = decryptedBytes[4];

        // Extract message (remaining bytes, null-terminated)
        const messageBytes = decryptedBytes.slice(5);
        let messageStr = '';
        for (let i = 0; i < messageBytes.length; i++) {
            if (messageBytes[i] === 0) break;
            messageStr += String.fromCharCode(messageBytes[i]);
        }

        // Parse message format: <name>: <text>
        const colonSpaceIndex = messageStr.indexOf(': ');

        if (colonSpaceIndex === -1) {
            // If format doesn't match, return error
            return {
                success: false,
                error: 'Message does not follow the expected format <name>: <text>'
            };
        }

        const senderName = messageStr.substring(0, colonSpaceIndex);
        const messageText = messageStr.substring(colonSpaceIndex + 2);

        return {
            success: true,
            timestamp: timestampStr,
            flags: '0x' + flags.toString(16).padStart(2, '0'),
            message: messageStr,
            sender: senderName,
            text: messageText,
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// Decryption function with user-provided key
function decryptGroupTextWithKey(ciphertext, keyHex) {
    try {
        // Validate key format
        if (!/^[0-9a-fA-F]*$/.test(keyHex)) {
            return {
                success: false,
                error: 'Decryption key must be in hexadecimal format'
            };
        }

        // Validate key length (should be 32 hex chars for AES-128)
        if (keyHex.length !== 32) {
            return {
                success: false,
                error: 'Decryption key must be 32 hexadecimal characters (16 bytes for AES-128)'
            };
        }

        const key = CryptoJS.enc.Hex.parse(keyHex);

        // Convert ciphertext hex string to CryptoJS format
        const ciphertextWords = CryptoJS.enc.Hex.parse(ciphertext);

        // Decrypt using AES-ECB
        const decrypted = CryptoJS.AES.decrypt(
            { ciphertext: ciphertextWords },
            key,
            {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.NoPadding
            }
        );

        // Convert decrypted data to bytes
        const decryptedHex = decrypted.toString(CryptoJS.enc.Hex);
        const decryptedBytes = [];
        for (let i = 0; i < decryptedHex.length; i += 2) {
            decryptedBytes.push(parseInt(decryptedHex.substr(i, 2), 16));
        }

        // Extract timestamp (4 bytes, little-endian)
        const timestamp = bytesToInt32LE(decryptedBytes.slice(0, 4));
        const timestampStr = new Date(timestamp * 1000).toISOString();

        // Extract flags (1 byte)
        const flags = decryptedBytes[4];

        // Extract message (remaining bytes, null-terminated)
        const messageBytes = decryptedBytes.slice(5);
        let messageStr = '';
        for (let i = 0; i < messageBytes.length; i++) {
            if (messageBytes[i] === 0) break;
            messageStr += String.fromCharCode(messageBytes[i]);
        }

        // Parse message format: <name>: <text>
        const colonSpaceIndex = messageStr.indexOf(': ');

        if (colonSpaceIndex === -1) {
            // If format doesn't match, return error
            return {
                success: false,
                error: 'Message does not follow the expected format <name>: <text>'
            };
        }

        const senderName = messageStr.substring(0, colonSpaceIndex);
        const messageText = messageStr.substring(colonSpaceIndex + 2);

        return {
            success: true,
            timestamp: timestampStr,
            flags: '0x' + flags.toString(16).padStart(2, '0'),
            message: messageStr,
            sender: senderName,
            text: messageText,
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// Decryption function with word list
function decryptWithWordList(ciphertext, wordList) {
    try {
        const results = [];

        for (const word of wordList) {
            const trimmedWord = word.trim();
            if (!trimmedWord) continue;

            // Try with #word format
            const channelName = "#" + trimmedWord;
            const result = decryptGroupText(ciphertext, channelName);

            if (result.success) {
                results.push({
                    word: trimmedWord,
                    timestamp: result.timestamp,
                    flags: result.flags,
                    message: result.message,
                    sender: result.sender,
                    text: result.text,
                });
            }
        }

        if (results.length === 0) {
            return {
                success: false,
                error: 'No valid decryptions found with the provided word list'
            };
        }

        return {
            success: false,
            wordListResults: results
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// Export for use in HTML
window.PacketParser = {
    parseMcPacket,
    hexStringToBytes,
    decryptGroupText,
    decryptGroupTextWithKey,
    decryptWithWordList,
};
