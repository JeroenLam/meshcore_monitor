# MeshCore Packet Visualizer

A static web-based tool for parsing and visualizing MeshCore network packets. This visualizer allows you to paste hexadecimal packet data and see a detailed breakdown of the packet structure.

## Features

- 🔍 **Real-time Packet Parsing**: Parse hex strings into structured packet data
- 📊 **Visual Breakdown**: See header and payload information in an organized grid layout
- 🎨 **Color-coded Hex Display**: Visualize the raw hex data with color-coded sections
- 📱 **Responsive Design**: Works on desktop and mobile devices
- 🚀 **No Backend Required**: Runs entirely in the browser

## Usage

1. Open `index.html` in a web browser
2. Paste your packet hex string in the input field (spaces are optional)
3. Click "Parse Packet" or press Enter
4. View the parsed packet structure and hex visualization

### Example Input

```
01 0a 02 03 04 05 48 65 6c 6c 6f
```

Or without spaces:

```
010a020304050548656c6c6f
```

## Packet Structure

The visualizer parses packets according to the MeshCore protocol specification:

### Header Fields

- **Route Type**: Determines how the packet is routed (FLOOD, DIRECT, TRANSPORT_FLOOD, TRANSPORT_DIRECT)
- **Payload Type**: Specifies the type of payload (REQ, RESPONSE, TXT_MSG, ACK, ADVERT, etc.)
- **Payload Version**: Version of the payload format
- **Transport Codes**: Optional codes for transport routing
- **Path Length**: Number of hops in the path
- **Path**: List of node addresses in the path

### Payload Types

The visualizer supports parsing the following payload types:

- **REQ (0x00)**: Request messages with destination/source hashes and request type
- **RESPONSE (0x01)**: Response messages with tag and content
- **TXT_MSG (0x02)**: Plain text messages with timestamp and message content
- **ACK (0x03)**: Acknowledgment messages with checksum
- **ADVERT (0x04)**: Advertisement messages with public key and node information
- **GRP_TXT (0x05)**: Group text messages
- **GRP_DATA (0x06)**: Group data messages
- **ANON_REQ (0x07)**: Anonymous request messages
- **PATH (0x08)**: Return path messages
- **CONTROL (0x0B)**: Control messages (DISCOVER_REQ, DISCOVER_RESP)

## File Structure

```
visualiser/
├── index.html      # Main HTML page
├── styles.css      # Styling and layout
├── parser.js       # Packet parsing logic
└── README.md       # This file
```

## Hosting on GitHub Pages

To host this visualizer on GitHub Pages:

1. Create a GitHub repository
2. Push the `visualiser` folder contents to the repository
3. Enable GitHub Pages in repository settings
4. Select the branch and folder to publish
5. Access your visualizer at `https://yourusername.github.io/repository-name/`

## Technical Details

### Parser Implementation

The parser is a JavaScript port of the Python parsing logic from `mc_scraper/parsing.py`. It implements:

- Byte-level packet parsing
- Enum-based type identification
- Timestamp conversion (Unix to ISO 8601)
- Hex string validation and conversion
- Error handling with user-friendly messages

### Supported Hex Formats

- Uppercase or lowercase hex digits
- Spaces between bytes (optional)
- No prefix required (0x prefix is not needed)

### Error Handling

The visualizer provides clear error messages for:

- Invalid hex strings
- Odd-length hex input
- Parsing errors with detailed descriptions
- Empty input validation

## Browser Compatibility

- Chrome/Chromium 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Limitations

- Some payload types are marked as "unimplemented" in the original parser
- Encrypted payloads cannot be decrypted (ciphertext is displayed as hex)
- Maximum packet size is limited by browser memory

## Development

To modify the parser:

1. Edit `parser.js` to update parsing logic
2. Update `styles.css` for visual changes
3. Modify `index.html` for layout changes
4. Test in your browser by opening `index.html`

## License

This visualizer is part of the MeshCore project.

## References

- MeshCore Protocol Documentation: https://github.com/meshcore-dev/MeshCore/blob/main/docs/payloads.md
- Original Python Parser: `mc_scraper/parsing.py`
