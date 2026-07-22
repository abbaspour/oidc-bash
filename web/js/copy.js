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

    document.addEventListener('click', function (e) {
        var btn = e.target.closest && e.target.closest('.copy-btn');
        if (!btn) return;

        var code = btn.previousElementSibling;
        while (code && code.tagName !== 'CODE') code = code.previousElementSibling;
        if (!code) return;

        copyText(code.textContent).then(function () {
            var original = btn.textContent;
            btn.textContent = '✅';
            setTimeout(function () { btn.textContent = original; }, 1000);
        }).catch(function () {});
    });
})();
