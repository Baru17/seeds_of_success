/* ============================================================
    Seeds of Success — Validation Utilities
    ============================================================ */

const Validators = {
  NAME_REGEX: /^[A-Za-z]+([ '.-][A-Za-z]+)*$/,
  EMAIL_REGEX: /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/,
  PHONE_REGEX: /^\+?[0-9\s().-]{7,20}$/,

  validateName(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) return { valid: false, message: '' };
    if (trimmed.length < 2) return { valid: false, message: 'Name must be at least 2 characters.' };
    if (trimmed.length > 50) return { valid: false, message: 'Name must be 50 characters or fewer.' };
    if (!this.NAME_REGEX.test(trimmed)) return { valid: false, message: 'Name is invalid' };
    return { valid: true, message: '' };
  },

  validateEmail(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) return { valid: false, message: '' };
    if (!this.EMAIL_REGEX.test(trimmed)) return { valid: false, message: 'Enter a valid email address' };
    return { valid: true, message: '' };
  },

  validatePhone(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) return { valid: false, message: '' };
    if (!this.PHONE_REGEX.test(trimmed)) return { valid: false, message: 'Enter a valid phone number' };
    return { valid: true, message: '' };
  },

  validatePassword(value) {
    if (!value) return { valid: false, message: '', strength: 'none' };
    const hasLower = /[a-z]/.test(value);
    const hasUpper = /[A-Z]/.test(value);
    const hasNumber = /[0-9]/.test(value);
    const hasSpecial = /[^A-Za-z0-9]/.test(value);
    const length = value.length;
    const criteria = [hasLower, hasUpper, hasNumber, hasSpecial];
    const metCount = criteria.filter(Boolean).length;

    let strength = 'weak';
    if (length >= 8 && metCount >= 4) strength = 'strong';
    else if (length >= 8 && metCount >= 3) strength = 'medium';

    const allMet = metCount === 4 && length >= 8;
    return {
      valid: allMet,
      message: '',
      strength,
      hasLower, hasUpper, hasNumber, hasSpecial,
      length,
      metCount
    };
  },

  validateSubject(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) return { valid: false, message: '' };
    if (trimmed.length < 2) return { valid: false, message: 'Subject must be at least 2 characters.' };
    return { valid: true, message: '' };
  },

  validateMessage(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) return { valid: false, message: '' };
    if (trimmed.length < 10) return { valid: false, message: 'Message must be at least 10 characters.' };
    if (trimmed.length > 1000) return { valid: false, message: 'Message must be 1000 characters or fewer.' };
    return { valid: true, message: '' };
  },

  validateAmount(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) return { valid: false, message: '' };
    if (!/^\d+(\.\d{1,2})?$/.test(trimmed)) return { valid: false, message: 'Enter a valid amount' };
    const num = Number(trimmed);
    if (num <= 0) return { valid: false, message: 'Amount must be greater than zero' };
    return { valid: true, message: '' };
  },

  validateDonationName(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) return { valid: false, message: '' };
    if (trimmed.length < 2 || trimmed.length > 50) return { valid: false, message: 'Name must be 2-50 characters.' };
    if (!/^[\p{L}\p{M}' -]+$/u.test(trimmed)) return { valid: false, message: 'Name is invalid' };
    return { valid: true, message: '' };
  },

  passwordsMatch(password, confirmPassword) {
    if (!password || !confirmPassword) return true;
    return password === confirmPassword;
  }
};

function getMsgEl(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return null;
  const wrapper = field.closest('.form-group, .vol-group, .donate-group');
  if (!wrapper) return null;
  let msgEl = wrapper.querySelector('.validation-message');
  if (!msgEl) {
    msgEl = document.createElement('div');
    msgEl.className = 'validation-message hidden';
    wrapper.appendChild(msgEl);
  }
  return msgEl;
}

function showValidationMessage(fieldId, message, type) {
  const msgEl = getMsgEl(fieldId);
  if (!msgEl) return;
  if (!message) {
    msgEl.className = 'validation-message hidden';
    msgEl.textContent = '';
    return;
  }
  msgEl.textContent = message;
  msgEl.className = 'validation-message ' + type;
}

function showPasswordStrength(fieldId, result) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  const wrapper = field.closest('.form-group, .vol-group');
  if (!wrapper) return;

  let strengthEl = wrapper.querySelector('.password-strength');
  if (!strengthEl) {
    strengthEl = document.createElement('div');
    strengthEl.className = 'password-strength';
    wrapper.appendChild(strengthEl);
  }

  if (!result || result.strength === 'none' || !result.length) {
    strengthEl.innerHTML = '';
    return;
  }

  const strength = result.strength;
  const labelMap = { weak: 'Weak', medium: 'Medium', strong: 'Strong' };
  strengthEl.innerHTML =
    '<div class="password-strength-bar"><div class="password-strength-fill ' + strength + '"></div></div>' +
    '<span class="password-strength-label ' + strength + '">' + labelMap[strength] + '</span>';
}

function showPasswordRequirements(fieldId, result) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  const wrapper = field.closest('.form-group, .vol-group');
  if (!wrapper) return;

  let reqEl = wrapper.querySelector('.password-requirements');
  if (!reqEl) {
    reqEl = document.createElement('ul');
    reqEl.className = 'password-requirements';
    wrapper.appendChild(reqEl);
  }

  if (!result || !result.length) {
    reqEl.innerHTML = '';
    return;
  }

  const reqs = [
    { label: 'Min 8 chars', met: result.length >= 8 },
    { label: 'Uppercase', met: result.hasUpper },
    { label: 'Lowercase', met: result.hasLower },
    { label: 'Number', met: result.hasNumber },
    { label: 'Special char', met: result.hasSpecial },
    { label: 'Max 50 chars', met: result.length <= 50 }
  ];

  reqEl.innerHTML = reqs.map(function(r) {
    return '<li class="' + (r.met ? 'met' : '') + '"><span class="req-icon">' + (r.met ? '\u2713' : '\u25CB') + '</span> ' + r.label + '</li>';
  }).join('');
}

function markFieldValid(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  const wrapper = field.closest('.form-group, .vol-group, .donate-group');
  if (!wrapper) return;
  field.classList.remove('invalid');
  field.classList.add('valid');
}

function markFieldInvalid(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  const wrapper = field.closest('.form-group, .vol-group, .donate-group');
  if (!wrapper) return;
  field.classList.remove('valid');
  field.classList.add('invalid');
}

function clearFieldState(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  field.classList.remove('valid', 'invalid');
}

let emailCheckTimeouts = {};
let lastEmailChecked = '';
let emailCheckRequestSeq = {};

function debounceEmailCheck(fieldId, email, callback) {
  const trimmed = email.trim().toLowerCase();
  if (emailCheckTimeouts[fieldId]) {
    clearTimeout(emailCheckTimeouts[fieldId]);
  }
  const seq = (emailCheckRequestSeq[fieldId] || 0) + 1;
  emailCheckRequestSeq[fieldId] = seq;
  emailCheckTimeouts[fieldId] = setTimeout(function() {
    if (trimmed !== lastEmailChecked && trimmed.length > 0) {
      lastEmailChecked = trimmed;
      const currentSeq = seq;
      callback(trimmed, function() { return currentSeq === emailCheckRequestSeq[fieldId]; });
    }
  }, 500);
}

function showCheckingState(fieldId) {
  showValidationMessage(fieldId, 'Checking...', 'checking');
}

window.Validators = Validators;
window.showValidationMessage = showValidationMessage;
window.showPasswordStrength = showPasswordStrength;
window.showPasswordRequirements = showPasswordRequirements;
window.markFieldValid = markFieldValid;
window.markFieldInvalid = markFieldInvalid;
window.clearFieldState = clearFieldState;
window.debounceEmailCheck = debounceEmailCheck;
window.showCheckingState = showCheckingState;
