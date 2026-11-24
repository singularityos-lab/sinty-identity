(function () {
  'use strict';
  const main = document.querySelector('main');
  const flow = main.dataset.flow;
  const $ = (id) => document.getElementById(id);
  const say = (text) => { $('message').textContent = text; };
  if (main.dataset.password !== 'true') $('password-fields').hidden = true;
  if (main.dataset.password !== 'true') $('use-password').hidden = true;

  async function post(path, body) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Sinty-Request': '1' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
    });
    return { status: r.status, body: await r.json().catch(() => ({})) };
  }

  const messages = {
    wrong: 'The user name or password is not right.',
    locked: 'Too many attempts. Wait a little and try again.',
    stronger: 'This application needs a stronger sign-in: confirm on your device.',
    expired: 'This request has expired. Go back to the application and try again.',
  };

  $('use-password').addEventListener('click', async () => {
    say('');
    const r = await post('/login/password', { flow, user: $('user').value, password: $('password').value, otp: $('otp').value });
    if (r.status === 200) location.assign(r.body.next);
    else say(messages[r.body.error] || 'Sign-in failed.');
  });

  $('use-device').addEventListener('click', async () => {
    say('');
    const r = await post('/login/device', { flow, user: $('user').value });
    if (r.status !== 200) { say(messages[r.body.error] || 'Sign-in failed.'); return; }
    $('who').hidden = true;
    $('waiting').hidden = false;
    $('number').textContent = r.body.number;
    const tick = async () => {
      const s = await post('/login/status', { approval: r.body.approval });
      if (s.body.status === 'approved') { location.assign(s.body.next); return; }
      if (s.body.status === 'pending') { setTimeout(tick, 1500); return; }
      $('who').hidden = false;
      $('waiting').hidden = true;
      say(s.body.status === 'denied' ? 'The request was refused on the device.' : messages.expired);
    };
    setTimeout(tick, 1500);
  });
})();
