var JwtUtil = (function () {
    var b64urlDecode = function (s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        var bin = atob(s);
        try {
            return decodeURIComponent(bin.split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
        } catch (e) {
            return bin;
        }
    };

    var decodeJwt = function (jwt) {
        var parts = jwt.split('.');
        if (parts.length < 2) return null;
        try {
            return {
                header: JSON.parse(b64urlDecode(parts[0])),
                payload: JSON.parse(b64urlDecode(parts[1]))
            };
        } catch (e) {
            return null;
        }
    };

    var renderDecodedJwt = function (afterNode, label, jwt) {
        if (!jwt) return afterNode;
        var decoded = decodeJwt(jwt);
        if (!decoded) return afterNode;

        var jwtTable = document.createElement('table');
        jwtTable.style.borderCollapse = 'collapse';
        jwtTable.style.width = '100%';
        jwtTable.style.marginTop = '1em';

        var hRow = document.createElement('tr');
        var hCell = document.createElement('td');
        hCell.colSpan = 2;
        hCell.innerHTML = '<b>Decoded ' + label + '</b>';
        hRow.appendChild(hCell);
        jwtTable.appendChild(hRow);

        var hdrRow = document.createElement('tr');
        var hdrKey = document.createElement('td');
        var hdrCell = document.createElement('td');
        hdrKey.style.verticalAlign = 'top';
        hdrCell.style.verticalAlign = 'top';
        var hdrLabel = document.createElement('b');
        hdrLabel.textContent = 'header';
        hdrKey.appendChild(hdrLabel);
        var hdrPre = document.createElement('pre');
        hdrPre.textContent = JSON.stringify(decoded.header, null, 2);
        hdrCell.appendChild(hdrPre);
        hdrRow.appendChild(hdrKey);
        hdrRow.appendChild(hdrCell);
        jwtTable.appendChild(hdrRow);

        var pldRow = document.createElement('tr');
        var pldKey = document.createElement('td');
        var pldCell = document.createElement('td');
        pldKey.style.verticalAlign = 'top';
        pldCell.style.verticalAlign = 'top';
        var pldLabel = document.createElement('b');
        pldLabel.textContent = 'payload';
        pldKey.appendChild(pldLabel);
        var pldPre = document.createElement('pre');
        pldPre.textContent = JSON.stringify(decoded.payload, null, 2);
        pldCell.appendChild(pldPre);
        pldRow.appendChild(pldKey);
        pldRow.appendChild(pldCell);
        jwtTable.appendChild(pldRow);

        afterNode.parentNode.insertBefore(jwtTable, afterNode.nextSibling);

        try { console.log(label + ' header:', decoded.header); console.log(label + ' payload:', decoded.payload); } catch (e) {}

        return jwtTable;
    };

    return {
        decodeJwt: decodeJwt,
        renderDecodedJwt: renderDecodedJwt
    };
})();
