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

    status.textContent = res.ok
        ? 'Verified. You can retry your upload now.'
        : 'Verification failed, please reload this page.';

    if (res.ok) {
        setTimeout(function() { window.location = '/'; }, 2000);
    }
}

solve().catch((e) => {
    document.getElementById('status').textContent = `Something went wrong: ${e}`;
});
