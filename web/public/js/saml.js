(function () {
    var table = document.querySelector('table');
    if (!table) return;

    var samlValue = null;
    Array.prototype.forEach.call(table.querySelectorAll('tr'), function (tr) {
        var b = tr.querySelector('td b');
        if (b && b.textContent === 'SAMLResponse') {
            var code = tr.querySelector('td code');
            if (code) samlValue = code.textContent;
        }
    });
    if (!samlValue) return;

    var base64ToBytes = function (b64) {
        var bin = atob(b64.trim());
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    };

    var bytesToText = function (bytes) {
        try {
            return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        } catch (e) {
            return String.fromCharCode.apply(null, bytes);
        }
    };

    var looksLikeXml = function (text) {
        return /^\s*</.test(text);
    };

    var insertPanel = function (title, body) {
        var wrapper = document.createElement('table');
        wrapper.style.borderCollapse = 'collapse';
        wrapper.style.width = '100%';
        wrapper.style.marginTop = '1em';

        var hRow = document.createElement('tr');
        var hCell = document.createElement('td');
        hCell.innerHTML = '<b>' + title + '</b>';
        hRow.appendChild(hCell);
        wrapper.appendChild(hRow);

        var bRow = document.createElement('tr');
        var bCell = document.createElement('td');
        bCell.appendChild(body);
        bRow.appendChild(bCell);
        wrapper.appendChild(bRow);

        table.parentNode.insertBefore(wrapper, table.nextSibling);
        return wrapper;
    };

    var renderXml = function (xmlText) {
        var blob = new Blob([xmlText], { type: 'application/xml' });
        var url = URL.createObjectURL(blob);

        var iframe = document.createElement('iframe');
        iframe.src = url;
        iframe.sandbox = 'allow-same-origin';
        iframe.style.width = '100%';
        iframe.style.height = '500px';
        iframe.style.resize = 'vertical';
        iframe.style.border = '1px solid #ccc';
        iframe.addEventListener('load', function () { URL.revokeObjectURL(url); });

        insertPanel('Decoded SAMLResponse', iframe);
        try { console.log('Decoded SAMLResponse:', xmlText); } catch (e) {}
    };

    var renderError = function (message) {
        var i = document.createElement('i');
        i.textContent = message;
        insertPanel('Decoded SAMLResponse', i);
    };

    var handleBytes = function (bytes) {
        var text = bytesToText(bytes);
        if (looksLikeXml(text)) {
            renderXml(text);
            return;
        }

        if (typeof DecompressionStream === 'undefined') {
            renderError('SAMLResponse is not plain XML and this browser lacks DecompressionStream support needed to inflate it (it may be deflate-compressed, as used by the SAML HTTP-Redirect binding).');
            return;
        }

        var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
        new Response(stream).arrayBuffer().then(function (buf) {
            var inflatedText = bytesToText(new Uint8Array(buf));
            if (looksLikeXml(inflatedText)) {
                renderXml(inflatedText);
            } else {
                renderError('Unable to interpret SAMLResponse as XML, even after raw-deflate inflation.');
            }
        }).catch(function () {
            renderError('Unable to interpret SAMLResponse as XML (base64-decoded payload is neither plain XML nor raw-deflate compressed).');
        });
    };

    try {
        handleBytes(base64ToBytes(samlValue));
    } catch (e) {
        renderError('Failed to base64-decode SAMLResponse: ' + e.message);
    }
})();
