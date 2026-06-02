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

    hash.split('&').forEach(function (pair) {
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
        tr.appendChild(tdK);
        tr.appendChild(tdV);
        table.appendChild(tr);

        try { console.log(k + ' = ' + v); } catch (e) {}
    });
})();
