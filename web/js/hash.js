(function () {
    var hash = window.location.hash.replace(/^#/, '');
    if (!hash) return;

    var table = document.querySelector('table');
    if (!table) return;

    var decode = function (s) {
        try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch (e) { return s; }
    };

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

    var header = document.createElement('tr');
    var th = document.createElement('td');
    th.colSpan = 2;
    th.innerHTML = '<b>Fragment parameters</b>';
    header.appendChild(th);
    table.appendChild(header);

    var idToken = null;

    hash.split('&').forEach(function (pair) {
        var eq = pair.indexOf('=');
        var k = eq >= 0 ? pair.slice(0, eq) : pair;
        var v = eq >= 0 ? pair.slice(eq + 1) : '';
        k = decode(k);
        v = decode(v);

        if (k === 'id_token') idToken = v;

        var tr = document.createElement('tr');
        var tdK = document.createElement('td');
        var tdV = document.createElement('td');
        var b = document.createElement('b');
        b.textContent = k;
        var code = document.createElement('code');
        code.textContent = v;
        tdK.appendChild(b);
        tdV.appendChild(code);
        tr.appendChild(tdK);
        tr.appendChild(tdV);
        table.appendChild(tr);

        try { console.log(k + ' = ' + v); } catch (e) {}
    });

    if (idToken) {
        var decoded = decodeJwt(idToken);
        if (decoded) {
            var jwtTable = document.createElement('table');
            jwtTable.style.borderCollapse = 'collapse';
            jwtTable.style.width = '100%';
            jwtTable.style.marginTop = '1em';

            var hRow = document.createElement('tr');
            var hCell = document.createElement('td');
            hCell.colSpan = 2;
            hCell.innerHTML = '<b>Decoded id_token</b>';
            hRow.appendChild(hCell);
            jwtTable.appendChild(hRow);

            var bRow = document.createElement('tr');
            var hdrCell = document.createElement('td');
            var pldCell = document.createElement('td');
            hdrCell.style.verticalAlign = 'top';
            pldCell.style.verticalAlign = 'top';

            var hdrPre = document.createElement('pre');
            hdrPre.textContent = JSON.stringify(decoded.header, null, 2);
            var pldPre = document.createElement('pre');
            pldPre.textContent = JSON.stringify(decoded.payload, null, 2);

            hdrCell.appendChild(hdrPre);
            pldCell.appendChild(pldPre);
            bRow.appendChild(hdrCell);
            bRow.appendChild(pldCell);
            jwtTable.appendChild(bRow);

            table.parentNode.insertBefore(jwtTable, table.nextSibling);

            try { console.log('id_token header:', decoded.header); console.log('id_token payload:', decoded.payload); } catch (e) {}
        }
    }
})();
