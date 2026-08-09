(function () {
    var hash = window.location.hash.replace(/^#/, '');
    if (!hash) return;

    var table = document.querySelector('table');
    if (!table) return;

    var decode = function (s) {
        try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch (e) { return s; }
    };

    var header = document.createElement('tr');
    var th = document.createElement('td');
    th.colSpan = 2;
    th.innerHTML = '<b>Fragment parameters</b>';
    header.appendChild(th);
    table.appendChild(header);

    var idToken = null;
    var accessToken = null;

    hash.split('&').forEach(function (pair) {
        var eq = pair.indexOf('=');
        var k = eq >= 0 ? pair.slice(0, eq) : pair;
        var v = eq >= 0 ? pair.slice(eq + 1) : '';
        k = decode(k);
        v = decode(v);

        if (k === 'id_token') idToken = v;
        if (k === 'access_token') accessToken = v;

        var tr = document.createElement('tr');
        var tdK = document.createElement('td');
        var tdV = document.createElement('td');
        var b = document.createElement('b');
        b.textContent = k;
        var code = document.createElement('code');
        code.textContent = v;
        tdK.appendChild(b);
        tdV.appendChild(code);
        tdV.appendChild(document.createTextNode(' '));
        var copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'copy-btn';
        copyBtn.title = 'Copy to clipboard';
        copyBtn.setAttribute('aria-label', 'Copy to clipboard');
        copyBtn.textContent = '📋';
        tdV.appendChild(copyBtn);
        tr.appendChild(tdK);
        tr.appendChild(tdV);
        table.appendChild(tr);

        try { console.log(k + ' = ' + v); } catch (e) {}
    });

    var lastInserted = table;
    lastInserted = JwtUtil.renderDecodedJwt(lastInserted, 'id_token', idToken);
    lastInserted = JwtUtil.renderDecodedJwt(lastInserted, 'access_token', accessToken);
})();
