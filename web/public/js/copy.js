(function () {
    var copyText = function (text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
        }
        return new Promise(function (resolve, reject) {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            try {
                document.execCommand('copy') ? resolve() : reject(new Error('copy failed'));
            } catch (e) {
                reject(e);
            } finally {
                document.body.removeChild(ta);
            }
        });
    };

    var findPrecedingCode = function (btn) {
        var code = btn.previousElementSibling;
        while (code && code.tagName !== 'CODE') code = code.previousElementSibling;
        return code;
    };

    var flash = function (btn) {
        var original = btn.textContent;
        btn.textContent = '✅';
        setTimeout(function () { btn.textContent = original; }, 1000);
    };

    document.addEventListener('click', function (e) {
        var exportBtn = e.target.closest && e.target.closest('.copy-export-btn');
        if (exportBtn) {
            var exportCode = findPrecedingCode(exportBtn);
            var tr = exportBtn.closest('tr');
            var keyEl = tr && tr.querySelector('td b');
            if (!exportCode || !keyEl) return;

            var value = exportCode.textContent.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
            var exportCmd = 'export ' + keyEl.textContent + '="' + value + '"';

            copyText(exportCmd).then(function () { flash(exportBtn); }).catch(function () {});
            return;
        }

        var btn = e.target.closest && e.target.closest('.copy-btn');
        if (!btn) return;

        var code = findPrecedingCode(btn);
        if (!code) return;

        copyText(code.textContent).then(function () { flash(btn); }).catch(function () {});
    });
})();
