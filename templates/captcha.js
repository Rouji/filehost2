function renderBar(fraction, width = 20) {
    const filled = Math.max(0, Math.min(width, Math.round(fraction * width)));
    return '[' + '|'.repeat(filled) + ' '.repeat(width - filled) + ']';
}

function leadingZeroBits(bytes) {
    let n = 0;
    for (const b of bytes) {
        if (b === 0) { n += 8; continue; }
        n += Math.clz32(b) - 24;
        break;
    }
    return n;
}

async function sha256(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return new Uint8Array(digest);
}

// Where to go after verifying: `?next=<slug>`, resolved against this page so a
// base_url path prefix is respected. null if missing or off-origin.
function nextUrl() {
    const next = new URLSearchParams(window.location.search).get('next');
    if (!next) return null;
    try {
        const url = new URL(next, new URL('.', window.location.href));
        return url.origin === window.location.origin ? url : null;
    } catch {
        return null;
    }
}

async function solve() {
    const status = document.getElementById('status');
    const bar = document.getElementById('bar');
    const { token, difficulty } = await (await fetch('/captcha/challenge')).json();
    status.textContent = `Solving challenge (difficulty ${difficulty})...`;
    bar.textContent = renderBar(0);

    let nonce = 0;
    let bits = 0;
    let bestBits = 0;
    do {
        nonce++;
        const hash = await sha256(`${token}.${nonce}`);
        bits = leadingZeroBits(hash);
        bestBits = Math.max(bestBits, bits);
        if (nonce % 64 === 0) {
            bar.textContent = `${renderBar(bestBits / difficulty)} ${bestBits}/${difficulty}`;
        }
    } while (bits < difficulty);
    bar.textContent = `${renderBar(1)} ${difficulty}/${difficulty}`;

    status.textContent = 'Verifying...';
    const res = await fetch('/captcha/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, nonce: String(nonce) }),
    });

    if (!res.ok) {
        status.textContent = 'Verification failed, please reload this page.';
        return;
    }

    // straight back to the requested file; replace() keeps the captcha out of history
    const next = nextUrl();
    if (next) {
        status.textContent = 'Verified. Redirecting...';
        window.location.replace(next);
        return;
    }

    status.textContent = 'Verified. You can retry your upload now.';
    setTimeout(function() { window.location = new URL('.', window.location.href); }, 2000);
}

solve().catch((e) => {
    document.getElementById('status').textContent = `Something went wrong: ${e}`;
});
