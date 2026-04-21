document.addEventListener('click', async (event) => {
  const pwToggle = event.target.closest('.password-toggle');
  if (pwToggle) {
    const tray = pwToggle.closest('.password-input-tray');
    const input = tray?.querySelector('input.password-input-tray__input');
    if (!input || pwToggle.disabled || input.disabled) return;
    const reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    pwToggle.setAttribute('aria-pressed', reveal ? 'true' : 'false');
    const labelReveal = reveal ? 'Hide password' : 'Show password';
    pwToggle.setAttribute('aria-label', labelReveal);
    pwToggle.setAttribute('title', labelReveal);
    const iconShow = pwToggle.querySelector('.password-toggle__icon--show');
    const iconHide = pwToggle.querySelector('.password-toggle__icon--hide');
    if (iconShow && iconHide) {
      iconShow.hidden = reveal;
      iconHide.hidden = !reveal;
    }
    return;
  }

  const toggleButton = event.target.closest('.secret-toggle');
  if (toggleButton) {
    const targetId = toggleButton.dataset.secretTarget;
    const target = document.getElementById(targetId);
    if (!target) return;
    const secret = target.dataset.secret || '';
    const currentlyHidden = target.textContent.includes('•');
    target.textContent = currentlyHidden ? secret : '••••••••';
    toggleButton.textContent = currentlyHidden ? 'Hide' : 'Show';
  }

  const copyButton = event.target.closest('.copy-btn');
  if (copyButton) {
    const value = copyButton.dataset.copy || '';
    try {
      await navigator.clipboard.writeText(value);
      const old = copyButton.textContent;
      copyButton.textContent = 'Copied';
      copyButton.classList.add('copied-state');
      setTimeout(() => {
        copyButton.textContent = old;
        copyButton.classList.remove('copied-state');
      }, 1200);
    } catch (error) {
      alert('Copy failed on this browser.');
    }
  }
});
