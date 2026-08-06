(function () {
    var search = window.location.search.replace(/^\?/, '');

    var table = document.querySelector('table');
    if (!table) return;

    var decode = function (s) {
        try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch (e) { return s; }
    };

    if (!search) {
        var tr = document.createElement('tr');
        var td = document.createElement('td');
        td.colSpan = 2;
        var i = document.createElement('i');
        i.textContent = '(no query parameters)';
        td.appendChild(i);
        tr.appendChild(td);
        table.appendChild(tr);
        return;
    }

    search.split('&').forEach(function (pair) {
        var eq = pair.indexOf('=');
        var k = eq >= 0 ? pair.slice(0, eq) : pair;
        var v = eq >= 0 ? pair.slice(eq + 1) : '';
        k = decode(k);
        v = decode(v);

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
})();
