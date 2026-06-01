// XML Parser using pure JavaScript
// Parses XML strings into JavaScript objects without external dependencies

var xml = new function () {
    /**
     * Parse XML string into a JavaScript object
     * @param {string} xmlString - The XML string to parse
     * @returns {object} Parsed XML as JavaScript object
     */
    this.parse = function (xmlString) {
        if (!xmlString || typeof xmlString !== 'string') {
            logger.error('Invalid input: xmlString must be a non-empty string');
        }

        // Remove XML declaration and trim whitespace
        xmlString = xmlString.replace(/<\?xml[^?]*\?>/g, '').trim();

        if (!xmlString) {
            logger.error('Invalid XML: Empty string after removing declaration');
        }

        // Parse the root element
        return parseElement(xmlString, 0).element;
    };

    /**
     * Parse attributes from an attribute string
     * @param {string} attrString - String containing attributes (e.g., ' id="123" name="test"')
     * @returns {object} Object with attribute key-value pairs
     */
    function parseAttributes(attrString) {
        const attrs = {};
        if (!attrString || !attrString.trim()) {
            return attrs;
        }

        // Match attributes in format: name="value" or name='value'
        const regex = /([a-zA-Z0-9:_-]+)\s*=\s*["']([^"']*)["']/g;
        let match;

        while ((match = regex.exec(attrString)) !== null) {
            attrs[match[1]] = match[2];
        }

        return attrs;
    }

    /**
     * Decode XML entities
     * @param {string} text - Text containing XML entities
     * @returns {string} Decoded text
     */
    function decodeEntities(text) {
        return text
            .replace(/</g, '<')
            .replace(/>/g, '>')
            .replace(/&/g, '&')
            .replace(/"/g, '"')
            .replace(/'/g, "'");
    }

    /**
     * Parse a single XML element recursively
     * @param {string} xml - XML string to parse
     * @param {number} startPos - Starting position in the string
     * @returns {object} Object containing the parsed element and the position after parsing
     */
    function parseElement(xml, startPos) {
        let pos = startPos;

        // Skip whitespace
        while (pos < xml.length && /\s/.test(xml[pos])) {
            pos++;
        }

        if (pos >= xml.length || xml[pos] !== '<') {
            logger.error('Invalid XML: Expected opening tag at position ' + pos);
        }

        // Check for self-closing tag: <tagName attr="value" />
        const selfClosingMatch = xml.substring(pos).match(/^<([a-zA-Z0-9:_-]+)([^>]*?)\/>/);
        if (selfClosingMatch) {
            const tagName = selfClosingMatch[1];
            const attributes = parseAttributes(selfClosingMatch[2]);

            return {
                element: {
                    tagName: tagName,
                    attributes: attributes,
                    children: [],
                    textContent: ''
                },
                endPos: pos + selfClosingMatch[0].length
            };
        }

        // Match opening tag: <tagName attr="value">
        const openTagMatch = xml.substring(pos).match(/^<([a-zA-Z0-9:_-]+)([^>]*)>/);
        if (!openTagMatch) {
            logger.error('Invalid XML: Malformed opening tag at position ' + pos);
        }

        const tagName = openTagMatch[1];
        const attributes = parseAttributes(openTagMatch[2]);
        pos += openTagMatch[0].length;

        // Parse content (text and child elements)
        const children = [];
        let textContent = '';
        let contentStart = pos;

        while (pos < xml.length) {
            // Check for closing tag
            const closeTagMatch = xml.substring(pos).match(/^<\/([a-zA-Z0-9:_-]+)>/);
            if (closeTagMatch) {
                if (closeTagMatch[1] !== tagName) {
                    logger.error('Invalid XML: Mismatched closing tag. Expected </' + tagName + '> but found </' + closeTagMatch[1] + '>');
                }

                // Capture any remaining text content before closing tag
                if (children.length === 0 && pos > contentStart) {
                    textContent = decodeEntities(xml.substring(contentStart, pos).trim());
                }

                pos += closeTagMatch[0].length;
                break;
            }

            // Check for child element (but not entity references like <)
            if (xml[pos] === '<' && xml[pos + 1] !== '/' && xml[pos + 1] !== '!') {
                // If we have text before this child element and no children yet, capture it
                if (children.length === 0 && pos > contentStart) {
                    const textBefore = xml.substring(contentStart, pos).trim();
                    if (textBefore) {
                        textContent = decodeEntities(textBefore);
                    }
                }

                // Parse child element
                const childResult = parseElement(xml, pos);
                children.push(childResult.element);
                pos = childResult.endPos;
                contentStart = pos;
            } else {
                pos++;
            }
        }

        // If we reached end of string without finding closing tag
        if (pos >= xml.length && !xml.substring(startPos, pos).includes('</' + tagName + '>')) {
            logger.error('Invalid XML: Missing closing tag for <' + tagName + '>');
        }

        return {
            element: {
                tagName: tagName,
                attributes: attributes,
                children: children,
                textContent: children.length === 0 ? textContent : ''
            },
            endPos: pos
        };
    }
};
